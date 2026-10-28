package fleet

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Set at build time with -ldflags -X (see deploy/Dockerfile):
//
//	ReleasePublicKeys: comma-separated base64 Ed25519 public keys this agent trusts for its own updates
//	                   (the current release key and, during a rotation, the next one).
//	ReleaseSeq:        this binary's release number. Releases only move forwards; a rollback is published as
//	                   the older binary under a new, higher release number.
//
// With no keys pinned (lab builds) the agent falls back to the server-supplied SHA-256 only.
var (
	ReleasePublicKeys = ""
	ReleaseSeq        = "0"
)

// ReleaseManifest is what the release key signs. The signature covers the exact manifest bytes.
type ReleaseManifest struct {
	Schema   int       `json:"schema"`
	Platform string    `json:"platform"` // linux | macos
	Arch     string    `json:"arch"`     // amd64 | arm64
	Channel  string    `json:"channel"`
	Release  int64     `json:"release"`
	Version  string    `json:"version"`
	BuildID  string    `json:"buildId"`
	SHA256   string    `json:"sha256"`
	Size     int64     `json:"size"`
	Issued   time.Time `json:"issued"`
	Expires  time.Time `json:"expires"`
}

// PinnedReleaseKeys parses ReleasePublicKeys; malformed entries are ignored (and reported by the caller as none).
func PinnedReleaseKeys() []ed25519.PublicKey {
	var keys []ed25519.PublicKey
	for _, part := range strings.Split(ReleasePublicKeys, ",") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(part))
		if err == nil && len(raw) == ed25519.PublicKeySize {
			keys = append(keys, ed25519.PublicKey(raw))
		}
	}
	return keys
}

func currentRelease() int64 {
	n, _ := strconv.ParseInt(ReleaseSeq, 10, 64)
	return n
}

// VerifyRelease checks a signed manifest against the pinned keys and this device, and that it moves forwards.
// allowSame permits reinstalling the release already running (a forced repair), never an older one.
func VerifyRelease(manifest []byte, signature string, keys []ed25519.PublicKey, platform, arch string, current int64,
	now time.Time, allowSame bool) (*ReleaseManifest, error) {
	if len(manifest) == 0 || signature == "" {
		return nil, errors.New("the server offered an unsigned release; this agent only installs signed releases")
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("release signature is malformed")
	}
	trusted := false
	for _, key := range keys {
		if ed25519.Verify(key, manifest, sig) {
			trusted = true
			break
		}
	}
	if !trusted {
		return nil, errors.New("release signature does not match a trusted release key")
	}
	var m ReleaseManifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, fmt.Errorf("release manifest is not valid JSON: %w", err)
	}
	switch {
	case m.Schema != 1:
		return nil, fmt.Errorf("unsupported release manifest schema %d", m.Schema)
	case m.Platform != platform || m.Arch != arch:
		return nil, fmt.Errorf("release is for %s/%s, not %s/%s", m.Platform, m.Arch, platform, arch)
	case m.Expires.IsZero() || now.After(m.Expires):
		return nil, fmt.Errorf("release manifest expired on %s", m.Expires.Format(time.RFC3339))
	case len(m.SHA256) != 64 || m.Size <= 0:
		return nil, errors.New("release manifest has no valid hash or size")
	case m.Release < current || (m.Release == current && !allowSame):
		return nil, &downgradeError{offered: m.Release, current: current}
	}
	return &m, nil
}

type downgradeError struct{ offered, current int64 }

func (e *downgradeError) Error() string {
	if e.offered == e.current {
		return "already running this release"
	}
	return fmt.Sprintf("refusing release %d: older than the running release %d", e.offered, e.current)
}

// LoadReleaseSigningKey reads an Ed25519 private key in PKCS#8 PEM (as written by
// `openssl genpkey -algorithm ed25519`).
func LoadReleaseSigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("release key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("release key is not an Ed25519 key")
	}
	return key, nil
}

// SignRelease returns the manifest bytes and their base64 signature.
func SignRelease(key ed25519.PrivateKey, m ReleaseManifest) ([]byte, string, error) {
	m.Schema = 1
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, "", err
	}
	return raw, base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw)), nil
}
