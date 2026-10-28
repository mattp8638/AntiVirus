package fleet

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// AT-13: altered binary or manifest, replayed/older release, wrong platform, expired manifest, unsigned release and an
// untrusted key are all refused; a correctly signed newer release installs.

func newReleaseKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func pin(t *testing.T, keys ...ed25519.PrivateKey) {
	t.Helper()
	old, oldSeq := ReleasePublicKeys, ReleaseSeq
	var parts []string
	for _, k := range keys {
		parts = append(parts, base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)))
	}
	ReleasePublicKeys, ReleaseSeq = strings.Join(parts, ","), "100"
	t.Cleanup(func() { ReleasePublicKeys, ReleaseSeq = old, oldSeq })
}

func manifestFor(binary []byte, release int64) ReleaseManifest {
	sum := sha256.Sum256(binary)
	now := time.Now().UTC()
	return ReleaseManifest{Platform: platformName(), Arch: runtime.GOARCH, Channel: "stable", Release: release, Version: "9.9.9",
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(binary)), Issued: now, Expires: now.Add(24 * time.Hour)}
}

// signedServer serves the given manifest/signature and binary on the update endpoints.
func signedServer(t *testing.T, manifest []byte, sig string, binary []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/update/" + platformName():
			_ = json.NewEncoder(w).Encode(AgentUpdate{Available: true, Version: "9.9.9", SHA256: "ignored-when-signed",
				URL: "/downloads/agent", Manifest: string(manifest), Signature: sig})
		case "/downloads/agent":
			_, _ = w.Write(binary)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSignedReleaseInstalls(t *testing.T) {
	key := newReleaseKey(t)
	pin(t, key)
	binary := []byte("signed new agent")
	manifest, sig, err := SignRelease(key, manifestFor(binary, 101))
	if err != nil {
		t.Fatal(err)
	}
	a, exe, exited := testUpdateAgent(t, signedServer(t, manifest, sig, binary).URL)
	result, err := a.selfUpdate(false)
	if err != nil || result["updated"] != true {
		t.Fatalf("expected update, got %v %v", result, err)
	}
	if got, _ := os.ReadFile(exe); string(got) != string(binary) {
		t.Fatal("binary not replaced")
	}
	<-exited
}

func TestReleaseRejections(t *testing.T) {
	key, other := newReleaseKey(t), newReleaseKey(t)
	pin(t, key)
	binary := []byte("signed new agent")
	good, goodSig, _ := SignRelease(key, manifestFor(binary, 101))

	expired := manifestFor(binary, 101)
	expired.Expires = time.Now().Add(-time.Hour)
	expiredRaw, expiredSig, _ := SignRelease(key, expired)
	wrongArch := manifestFor(binary, 101)
	wrongArch.Arch = "s390x"
	wrongRaw, wrongSig, _ := SignRelease(key, wrongArch)
	olderRaw, olderSig, _ := SignRelease(key, manifestFor(binary, 99))
	sameRaw, sameSig, _ := SignRelease(key, manifestFor(binary, 100))
	foreignRaw, foreignSig, _ := SignRelease(other, manifestFor(binary, 101))
	tampered := []byte(strings.Replace(string(good), `"release":101`, `"release":999`, 1))

	cases := []struct {
		name     string
		manifest []byte
		sig      string
		binary   []byte
		want     string
	}{
		{"unsigned", nil, "", binary, "unsigned release"},
		{"altered manifest", tampered, goodSig, binary, "does not match a trusted release key"},
		{"altered binary", good, goodSig, []byte("signed new agenT"), "checksum mismatch"},
		{"untrusted key", foreignRaw, foreignSig, binary, "does not match a trusted release key"},
		{"wrong platform", wrongRaw, wrongSig, binary, "release is for"},
		{"expired", expiredRaw, expiredSig, binary, "expired"},
		{"downgrade", olderRaw, olderSig, binary, "older than the running release"},
		{"garbage signature", good, "not-base64!", binary, "malformed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, exe, _ := testUpdateAgent(t, signedServer(t, c.manifest, c.sig, c.binary).URL)
			_, err := a.selfUpdate(false)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
			if got, _ := os.ReadFile(exe); string(got) != "old binary" {
				t.Fatal("binary changed despite refusal")
			}
		})
	}
	// A replay of the release already running is "up to date", and forcing it does not allow anything older.
	a, _, _ := testUpdateAgent(t, signedServer(t, sameRaw, sameSig, binary).URL)
	if result, err := a.selfUpdate(false); err != nil || result["updated"] != false {
		t.Fatalf("replayed current release: %v %v", result, err)
	}
	b, _, _ := testUpdateAgent(t, signedServer(t, olderRaw, olderSig, binary).URL)
	if _, err := b.selfUpdate(true); err == nil {
		t.Fatal("force must not install an older release")
	}
}

func TestKeyRotationAcceptsEitherPinnedKey(t *testing.T) {
	current, next := newReleaseKey(t), newReleaseKey(t)
	pin(t, current, next)
	binary := []byte("rotated")
	manifest, sig, _ := SignRelease(next, manifestFor(binary, 150))
	if _, err := VerifyRelease(manifest, sig, PinnedReleaseKeys(), platformName(), runtime.GOARCH, 100, time.Now(), false); err != nil {
		t.Fatalf("release signed by the next key should verify: %v", err)
	}
}

func TestLoadReleaseSigningKeyFromPKCS8PEM(t *testing.T) {
	key := newReleaseKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "release.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReleaseSigningKey(path)
	if err != nil || !loaded.Equal(key) {
		t.Fatalf("load failed: %v", err)
	}
}
