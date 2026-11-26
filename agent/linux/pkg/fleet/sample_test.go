package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSampleCollectUploadsOnlyMatchingQuarantinedFiles(t *testing.T) {
	dir := t.TempDir()
	q := &Scanner{QuarantineDir: filepath.Join(dir, "q")}
	src := filepath.Join(dir, "evil.bin")
	body := []byte("not really malware")
	_ = os.WriteFile(src, body, 0o755)
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	id, err := q.Quarantine(src, sha)
	if err != nil {
		t.Fatal(err)
	}
	var uploaded []byte
	upload := func(name string, data []byte) (string, error) {
		if name != sha+".sample" {
			t.Fatalf("unexpected name %s", name)
		}
		uploaded = data
		return "art-1", nil
	}
	out, err := SampleCollect(`{"recordId":"`+id+`","sha256":"`+sha+`"}`, q, upload)
	if err != nil || out["artifactId"] != "art-1" || string(uploaded) != string(body) {
		t.Fatalf("collect failed: %v %v", out, err)
	}
	// The quarantined file stays unreadable afterwards (mode 0), even when the agent had to grant itself access.
	if info, err := os.Stat(filepath.Join(q.QuarantineDir, id+".bin")); err != nil || info.Mode().Perm() != 0 {
		t.Fatalf("quarantined file must keep mode 0 after a sample is collected: %v %v", info.Mode(), err)
	}
	if _, err := SampleCollect(`{"recordId":"`+id+`","sha256":"`+strings.Repeat("0", 64)+`"}`, q, upload); err == nil {
		t.Fatal("a different SHA-256 must be refused")
	}
	if _, err := SampleCollect(`{"recordId":"../../etc/passwd","sha256":"`+sha+`"}`, q, upload); err == nil {
		t.Fatal("path traversal must be refused")
	}
	// A quarantined file altered on disk is refused.
	_ = os.Chmod(filepath.Join(q.QuarantineDir, id+".bin"), 0o600)
	_ = os.WriteFile(filepath.Join(q.QuarantineDir, id+".bin"), []byte("changed"), 0o600)
	if _, err := SampleCollect(`{"recordId":"`+id+`","sha256":"`+sha+`"}`, q, upload); err == nil {
		t.Fatal("an altered quarantined file must be refused")
	}
}
