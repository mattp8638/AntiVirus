package fleet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeProc(t *testing.T, values map[string]string) string {
	root := t.TempDir()
	for key, value := range values {
		path := filepath.Join(root, "sys", key)
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestNetworkHardeningSetsAndRestoresKernelSettings(t *testing.T) {
	original := map[string]string{}
	for key := range NetworkHardeningSysctls {
		if !strings.HasPrefix(key, "net/ipv6") { // this host has IPv6 off: those keys are skipped
			original[key] = "7"
		}
	}
	original["net/ipv4/tcp_syncookies"] = "1" // already hardened: left as it is
	proc := fakeProc(t, original)
	etc := t.TempDir()
	n := NetHardening{ProcRoot: proc, EtcRoot: etc, StateDir: t.TempDir()}
	changed, err := n.Enable()
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != len(original)-1 {
		t.Fatalf("changed %d keys, want %d", len(changed), len(original)-1)
	}
	read := func(key string) string {
		data, _ := os.ReadFile(filepath.Join(proc, "sys", key))
		return strings.TrimSpace(string(data))
	}
	if read("net/ipv4/conf/all/accept_redirects") != "0" || read("net/ipv4/conf/all/rp_filter") != "2" {
		t.Fatal("hardened values not written")
	}
	conf, err := os.ReadFile(filepath.Join(etc, "etc/sysctl.d/90-fenrir-network.conf"))
	if err != nil || !strings.Contains(string(conf), "net.ipv4.conf.all.accept_source_route = 0") {
		t.Fatalf("boot-time file missing: %v %s", err, conf)
	}
	// Enabling again keeps the first saved originals, not the hardened values.
	if _, err := n.Enable(); err != nil {
		t.Fatal(err)
	}
	restored, err := n.Disable()
	if err != nil || len(restored) != len(original) {
		t.Fatalf("restored %d (%v), want %d", len(restored), err, len(original))
	}
	if read("net/ipv4/conf/all/accept_redirects") != "7" || read("net/ipv4/tcp_syncookies") != "1" {
		t.Fatal("original values not restored")
	}
	if _, err := os.Stat(filepath.Join(etc, "etc/sysctl.d/90-fenrir-network.conf")); !os.IsNotExist(err) {
		t.Fatal("boot-time file must be removed")
	}
	// Disabling when Fenrir never enabled it touches nothing.
	if keys, err := n.Disable(); err != nil || keys != nil {
		t.Fatalf("second disable: %v %v", keys, err)
	}
}
