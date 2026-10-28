package fleet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScannerQuarantineAndRestore(t *testing.T) {
	dir := t.TempDir()
	sample := filepath.Join(dir, "bad.bin")
	if err := os.WriteFile(sample, []byte("fenrir test sample"), 0o755); err != nil {
		t.Fatal(err)
	}
	sha, _ := HashFile(sample, 0)
	s := NewScanner(filepath.Join(dir, "q"))
	var b Bundle
	if err := json.Unmarshal([]byte(`{"signatureVersion":"v1","hashes":[{"type":"sha256","value":"`+sha+`","malwareFamily":"Test"}]}`), &b); err != nil {
		t.Fatal(err)
	}
	s.Load(&b)
	scanned, findings := s.ScanPaths([]string{dir}, nil, true, 0)
	if scanned != 1 || len(findings) != 1 || findings[0].Action != "quarantined" {
		t.Fatalf("scan: scanned=%d findings=%+v", scanned, findings)
	}
	if _, err := os.Stat(sample); !os.IsNotExist(err) {
		t.Fatal("sample should have been moved to quarantine")
	}
	if path, err := s.Restore(findings[0].Record); err != nil || path != sample {
		t.Fatalf("restore: %v %s", err, path)
	}
	if _, err := s.Restore("../../etc/passwd"); err == nil {
		t.Fatal("path traversal in record id must be rejected")
	}
}

func TestIsolationRulesetKeepsControlPlane(t *testing.T) {
	rules := IsolationRuleset([]string{"203.0.113.10", "2001:db8::1"})
	for _, want := range []string{"policy drop", "ip daddr 203.0.113.10 accept", "ip6 daddr 2001:db8::1 accept", `oifname "lo" accept`} {
		if !strings.Contains(rules, want) {
			t.Fatalf("ruleset missing %q:\n%s", want, rules)
		}
	}
}

func TestParseHexAddr(t *testing.T) {
	ip, port := parseHexAddr("0100007F:0050")
	if ip != "127.0.0.1" || port != 80 {
		t.Fatalf("got %s:%d", ip, port)
	}
}

func TestEnrollAndCommandProtocol(t *testing.T) {
	var completed map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/enroll":
			if r.Header.Get("X-Fenrir-Token") != "fet_test" {
				w.WriteHeader(403)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"deviceId": "dev_1", "deviceApiKey": "fdk_1", "approved": true,
				"policy": map[string]interface{}{"id": "p", "revision": "r1", "realtimeProtection": true}})
		case r.Header.Get("X-Device-Api-Key") != "fdk_1":
			w.WriteHeader(401)
		case strings.HasSuffix(r.URL.Path, "/commands/pending"):
			json.NewEncoder(w).Encode(map[string]interface{}{"items": []map[string]string{{"id": "c1", "type": "policy.refresh"}}})
		case strings.HasSuffix(r.URL.Path, "/state"):
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "dispatched", "cancelRequested": false})
		case strings.HasSuffix(r.URL.Path, "/complete"):
			json.NewDecoder(r.Body).Decode(&completed)
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{"changed": false, "policy": map[string]interface{}{"revision": "r1"}})
		}
	}))
	defer srv.Close()
	state := t.TempDir()
	a := New(Config{Server: srv.URL + "/api/v1", EnrollmentToken: "fet_test", StateDir: state, PersistenceGlobs: []string{}, Homes: []string{}})
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	if a.client.APIKey != "fdk_1" {
		t.Fatal("api key not stored")
	}
	a.RunCommands()
	if completed["status"] != "completed" {
		t.Fatalf("command result: %+v", completed)
	}
	// Identity survives a restart without re-enrolling.
	b := New(Config{Server: srv.URL, StateDir: state, PersistenceGlobs: []string{}, Homes: []string{}})
	if err := b.Start(); err != nil || b.client.DeviceID != "dev_1" {
		t.Fatalf("reload: %v %s", err, b.client.DeviceID)
	}
}
