package fleet

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var evilBytes = []byte("fenrir archive test payload")

func evilSHA() string { h := sha256.Sum256(evilBytes); return hex.EncodeToString(h[:]) }

func zipOf(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("readme.txt")
	f.Write([]byte("hello"))
	f, _ = w.Create(name)
	f.Write(data)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tarGzOf(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
	tw.Write(data)
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func loadedScanner(t *testing.T, dir, category string) *Scanner {
	t.Helper()
	s := NewScanner(filepath.Join(dir, "q"))
	var b Bundle
	_ = json.Unmarshal([]byte(`{"signatureVersion":"v1","hashes":[{"type":"sha256","value":"`+evilSHA()+`","malwareFamily":"Test.Family","category":"`+category+`"}]}`), &b)
	s.Load(&b)
	return s
}

func TestArchiveScanningFindsNestedMembersWithinDepth(t *testing.T) {
	dir := t.TempDir()
	scanRoot := filepath.Join(dir, "scan")
	os.MkdirAll(scanRoot, 0o755)
	inner := zipOf(t, "payload.exe", evilBytes)
	nested := zipOf(t, "inner.zip", inner) // payload two levels down
	os.WriteFile(filepath.Join(scanRoot, "nested.zip"), nested, 0o644)
	os.WriteFile(filepath.Join(scanRoot, "bundle.tar.gz"), tarGzOf(t, "bin/payload", evilBytes), 0o644)
	s := loadedScanner(t, dir, "malware")

	if _, findings := s.ScanPathsWith([]string{scanRoot}, nil, false, 0, ScanOptions{Archives: false, PUA: "block"}); len(findings) != 0 {
		t.Fatalf("archives off must not look inside: %+v", findings)
	}
	_, findings := s.ScanPathsWith([]string{scanRoot}, nil, false, 0, ScanOptions{Archives: true, MaxDepth: 1, PUA: "block"})
	if len(findings) != 1 || findings[0].Member != "bin/payload" {
		t.Fatalf("depth 1 should find only the tar.gz member: %+v", findings)
	}
	_, findings = s.ScanPathsWith([]string{scanRoot}, nil, true, 0, ScanOptions{Archives: true, MaxDepth: 2, PUA: "block"})
	if len(findings) != 2 {
		t.Fatalf("depth 2 should find both: %+v", findings)
	}
	for _, f := range findings {
		if f.Action != "quarantined" || (f.Member != "bin/payload" && f.Member != "inner.zip!payload.exe") {
			t.Errorf("finding %+v", f)
		}
	}
	if _, err := os.Stat(filepath.Join(scanRoot, "nested.zip")); !os.IsNotExist(err) {
		t.Error("the archive holding the payload should be quarantined")
	}
}

func TestPUAModes(t *testing.T) {
	for _, tc := range []struct {
		mode, action string
		count        int
	}{{"off", "", 0}, {"audit", "detected", 1}, {"block", "quarantined", 1}} {
		dir := t.TempDir()
		root := filepath.Join(dir, "scan")
		os.MkdirAll(root, 0o755)
		os.WriteFile(filepath.Join(root, "toolbar.exe"), evilBytes, 0o644)
		s := loadedScanner(t, dir, "pua")
		_, findings := s.ScanPathsWith([]string{root}, nil, true, 0, ScanOptions{PUA: tc.mode})
		if len(findings) != tc.count || (tc.count == 1 && (findings[0].Action != tc.action || findings[0].Category != "pua")) {
			t.Errorf("mode %s: %+v", tc.mode, findings)
		}
	}
	// Malware is unaffected by the PUA setting.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "m.exe"), evilBytes, 0o644)
	if _, findings := loadedScanner(t, t.TempDir(), "malware").ScanPathsWith([]string{dir}, nil, false, 0, ScanOptions{PUA: "off"}); len(findings) != 1 {
		t.Errorf("malware must still be found with PUA off: %+v", findings)
	}
}

func TestNetworkMountParsing(t *testing.T) {
	info := "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
		"40 22 0:50 / /mnt/team\\040share rw - cifs //fs/share rw,vers=3.0\n" +
		"41 22 0:51 / /home/alice rw - nfs4 fs:/home/alice rw\n" +
		"42 22 0:52 / /run/user/1000/doc rw - fuse.portal portal rw\n"
	got := ParseMountInfo(info)
	if len(got) != 2 || got[0] != "/mnt/team share" || got[1] != "/home/alice" {
		t.Fatalf("mountinfo: %q", got)
	}
	mac := "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)\n" +
		"//alice@nas/Media on /Volumes/Media (smbfs, nodev, nosuid, mounted by alice)\n" +
		"nas:/export on /Volumes/export (nfs)\n"
	if got := ParseMacMounts(mac); len(got) != 2 || got[0] != "/Volumes/Media" || got[1] != "/Volumes/export" {
		t.Fatalf("mac mounts: %q", got)
	}
	p := firewallPolicy(t, `{}`)
	p.Modules["antimalware"] = map[string]interface{}{"scanNetworkDrives": true, "scanCpuLimitPercent": 2.0, "puaProtection": "weird", "archiveMaxDepth": 50.0}
	opts := ScanOptionsFromPolicy(p)
	if opts.SkipNetwork || opts.CPULimitPercent != 5 || opts.PUA != "block" || opts.MaxDepth != 20 || !opts.Archives {
		t.Fatalf("options %+v", opts)
	}
}

func TestCPUThrottle(t *testing.T) {
	var slept time.Duration
	th := &cpuThrottle{percent: 25, sleep: func(d time.Duration) { slept += d }}
	for i := 0; i < 10; i++ {
		th.after(10 * time.Millisecond) // 100 ms of work at 25% needs 300 ms of rest
	}
	if slept < 280*time.Millisecond || slept > 300*time.Millisecond {
		t.Fatalf("slept %v", slept)
	}
	var none time.Duration
	(&cpuThrottle{percent: 100, sleep: func(d time.Duration) { none += d }}).after(time.Second)
	if none != 0 {
		t.Fatal("100% means no throttling")
	}
}
