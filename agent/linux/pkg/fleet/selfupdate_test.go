package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func updateServer(t *testing.T, version string, binary []byte, advertisedSHA string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Device-Api-Key") != "key" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/v1/agent/update/" + platformName():
			if r.URL.Query().Get("arch") != runtime.GOARCH {
				w.WriteHeader(400)
				return
			}
			_ = json.NewEncoder(w).Encode(AgentUpdate{Available: true, Version: version, SHA256: advertisedSHA,
				URL: "/downloads/fenrir-agent-linux-" + runtime.GOARCH})
		case "/downloads/fenrir-agent-linux-" + runtime.GOARCH:
			_, _ = w.Write(binary)
		default:
			w.WriteHeader(404)
		}
	}))
}

func testUpdateAgent(t *testing.T, server string) (*Agent, string, chan int) {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "fenrir-agent")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := New(Config{Server: server, StateDir: dir})
	a.client.APIKey = "key"
	a.exePath = exe
	exited := make(chan int, 1)
	a.exit = func(code int) { exited <- code }
	a.restartDelay = 10 * time.Millisecond
	return a, exe, exited
}

func TestSelfUpdateReplacesBinaryAndRestarts(t *testing.T) {
	binary := []byte("new agent binary")
	sum := sha256.Sum256(binary)
	srv := updateServer(t, "99.0.0", binary, hex.EncodeToString(sum[:]))
	defer srv.Close()
	a, exe, exited := testUpdateAgent(t, srv.URL)
	result, err := a.selfUpdate(false)
	if err != nil {
		t.Fatal(err)
	}
	if result["updated"] != true || result["to"] != "99.0.0" {
		t.Fatalf("unexpected result %v", result)
	}
	if got, _ := os.ReadFile(exe); string(got) != string(binary) {
		t.Fatalf("binary not replaced: %q", got)
	}
	if info, _ := os.Stat(exe); info.Mode().Perm()&0o100 == 0 {
		t.Fatal("new binary is not executable")
	}
	select {
	case code := <-exited:
		if code != 0 {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not restart after updating")
	}
}

func TestSelfUpdateRejectsChecksumMismatchAndSkipsCurrentVersion(t *testing.T) {
	srv := updateServer(t, "99.0.0", []byte("tampered"), "0000000000000000000000000000000000000000000000000000000000000000")
	defer srv.Close()
	a, exe, _ := testUpdateAgent(t, srv.URL)
	if _, err := a.selfUpdate(false); err == nil {
		t.Fatal("expected a checksum error")
	}
	if got, _ := os.ReadFile(exe); string(got) != "old binary" {
		t.Fatal("binary changed despite checksum mismatch")
	}
	if _, err := os.Stat(exe + ".new"); err == nil {
		t.Fatal("temporary file left behind")
	}

	same := updateServer(t, Version, []byte("x"), "abc")
	defer same.Close()
	b, _, _ := testUpdateAgent(t, same.URL)
	result, err := b.selfUpdate(false)
	if err != nil || result["updated"] != false {
		t.Fatalf("expected no update for the current version, got %v %v", result, err)
	}
}

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{{"1.2.0", "1.1.9", true}, {"1.1.0", "1.1.0", false}, {"1.10.0", "1.9.9", true}, {"1.1", "1.1.1", false}, {"", "1.0.0", false}}
	for _, c := range cases {
		if got := NewerVersion(c.a, c.b); got != c.want {
			t.Errorf("NewerVersion(%q,%q)=%v", c.a, c.b, got)
		}
	}
}

func TestNeedsUpdatePrefersBuildIDs(t *testing.T) {
	cases := []struct {
		sv, sb, v, b string
		want         bool
	}{
		{"1.0.0", "aaaa", "1.0.0", "bbbb", true},   // same version, different source: update
		{"1.0.0", "aaaa", "1.0.0", "aaaa", false},  // identical build
		{"0.9.0", "aaaa", "1.0.0", "bbbb", true},   // the server's build wins even with a lower number
		{"1.1.0", "", "1.0.0", "bbbb", true},       // older server: compare versions
		{"1.0.0", "aaaa", "1.0.0", "", false},      // dev binary without an id: compare versions
	}
	for _, c := range cases {
		if got := NeedsUpdate(c.sv, c.sb, c.v, c.b); got != c.want {
			t.Errorf("NeedsUpdate(%q,%q,%q,%q) = %v", c.sv, c.sb, c.v, c.b, got)
		}
	}
}
