package fleet

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseSSHFailure(t *testing.T) {
	cases := []struct {
		line, addr, user string
		ok               bool
	}{
		{"Oct 26 10:00:01 web sshd[123]: Failed password for root from 203.0.113.9 port 51234 ssh2", "203.0.113.9", "root", true},
		{"sshd-session[9]: Invalid user admin from 2001:db8::7 port 4444", "2001:db8::7", "admin", true},
		{"sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 1 ssh2", "", "", false}, // already counted
		{"sshd[1]: Failed publickey for deploy from 198.51.100.4 port 22 ssh2", "198.51.100.4", "deploy", true},
		{"sshd[1]: Accepted publickey for deploy from 198.51.100.4 port 22 ssh2", "", "", false},
		{"sshd[1]: Invalid user  from 192.0.2.1 port 22", "192.0.2.1", "", true},
	}
	for _, c := range cases {
		addr, user, ok := parseSSHFailure(c.line)
		if ok != c.ok || addr != c.addr || user != c.user {
			t.Errorf("%q: got %q %q %v", c.line, addr, user, ok)
		}
	}
}

func TestBruteTracker(t *testing.T) {
	if normaliseRemoteAddress("::ffff:198.51.100.7") != "198.51.100.7" || normaliseRemoteAddress("127.0.0.1") != "" ||
		normaliseRemoteAddress("::1") != "" || normaliseRemoteAddress("1.2.3.4 dir") != "" || normaliseRemoteAddress("[2001:DB8::1]") != "2001:db8::1" {
		t.Fatal("address normalisation")
	}
	tr := newBruteTracker()
	t0 := int64(1_000_000)
	for i := 0; i < bruteThreshold-1; i++ {
		if tr.onFailure("203.0.113.9", "root", t0+int64(i)) != nil {
			t.Fatal("blocked too early")
		}
	}
	b := tr.onFailure("203.0.113.9", "admin", t0+20)
	if b == nil || b.Until != t0+20+bruteBaseBlockSecs || b.Strikes != 1 || len(b.Accounts) != 2 {
		t.Fatalf("block: %+v", b)
	}
	for i := 0; i < 30; i++ {
		if tr.onFailure("198.51.100.1", "bob", t0+int64(i)*120) != nil {
			t.Fatal("spread-out failures must not add up")
		}
	}
	if got := tr.expire(t0 + 20 + bruteBaseBlockSecs); len(got) != 1 {
		t.Fatalf("expire: %v", got)
	}
	t1 := t0 + 2*bruteBaseBlockSecs
	var again *bruteBlock
	for i := 0; i < bruteThreshold; i++ {
		again = tr.onFailure("203.0.113.9", "root", t1+int64(i))
	}
	if again == nil || again.Strikes != 2 || again.Until != t1+bruteThreshold-1+4*bruteBaseBlockSecs {
		t.Fatalf("repeat: %+v", again)
	}
	if len(tr.clear()) != 1 || len(tr.blocks) != 0 {
		t.Fatal("clear")
	}
}

type fakeBruteFirewall struct {
	blocked, unblocked []string
	resets             int
}

func (f *fakeBruteFirewall) block(addr string, _ int64) error {
	f.blocked = append(f.blocked, addr)
	return nil
}
func (f *fakeBruteFirewall) unblock(addr string) error {
	f.unblocked = append(f.unblocked, addr)
	return nil
}
func (f *fakeBruteFirewall) reset() error { f.resets++; return nil }

func TestCheckBruteForceReadsAuthLog(t *testing.T) {
	if IsMacOS {
		t.Skip("reads the unified log on macOS")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(logPath, []byte("old: Failed password for root from 203.0.113.50 port 1 ssh2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New(Config{StateDir: dir})
	fw := &fakeBruteFirewall{}
	a.brute = &bruteGuard{tracker: newBruteTracker(), reader: &sshLogReader{path: logPath}, firewall: fw}
	now := time.Unix(2_000_000, 0)
	a.checkBruteForce(now) // starts at the end of the log: history is ignored
	f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	for i := 0; i < 12; i++ {
		_, _ = f.WriteString("sshd[1]: Failed password for root from 203.0.113.9 port 2 ssh2\n")
	}
	_, _ = f.WriteString("sshd[1]: Failed password for root from 203.0.113.50 po") // partial line waits
	f.Close()
	a.checkBruteForce(now.Add(20 * time.Second))
	if len(fw.blocked) != 1 || fw.blocked[0] != "203.0.113.9" {
		t.Fatalf("blocked: %v", fw.blocked)
	}
	if a.QueueLength() == 0 {
		t.Fatal("no telemetry")
	}
	a.checkBruteForce(now.Add(2 * time.Hour))
	if len(fw.unblocked) != 1 {
		t.Fatalf("unblocked: %v", fw.unblocked)
	}
	a.state.Policy.Modules = map[string]map[string]interface{}{"firewall": {"bruteForceProtection": false}}
	a.checkBruteForce(now.Add(3 * time.Hour))
	if fw.resets != 1 {
		t.Fatalf("resets: %d", fw.resets)
	}
}
