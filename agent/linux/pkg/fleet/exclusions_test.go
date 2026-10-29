package fleet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const agentSha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func policyWithExclusions(t *testing.T, rules string) Policy {
	t.Helper()
	var p Policy
	doc := `{"revision":"r1","modules":{"attackSurface":{"blockLolbinAbuse":"block"},"edrExclusions":{"rules":` + rules + `}}}`
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		t.Fatalf("policy with exclusions must decode: %v", err)
	}
	return p
}

func TestExclusionPathMatchingIsStrict(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/opt/acme/acme-agent", "/opt/acme/acme-agent", true},
		{"/opt/acme/acme-agent-*", "/opt/acme/acme-agent-2.4", true},
		{`C:\Program Files\Acme\agent.exe`, `c:/program files/acme/AGENT.EXE`, true},
		{"/opt/acme/acme-agent", "/tmp/acme-agent", false},
		{"/opt/acme/acme-agent", "/opt/acme/sub/acme-agent", false},
		{"/opt/acme/[x]agent", "/opt/acme/[x]agent", true},
	}
	for _, c := range cases {
		if got := ExclusionPathMatches(c.pattern, c.path); got != c.want {
			t.Errorf("ExclusionPathMatches(%q, %q) = %v", c.pattern, c.path, got)
		}
	}
}

func TestProcessChainNeedsParentHash(t *testing.T) {
	p := policyWithExclusions(t, `[{"id":"exc_1","kind":"process-chain","parentImage":"/opt/acme/acme-agent",
		"parentSha256":["`+agentSha+`"],"childImage":"/bin/bash","scopes":["behavior","sigma"]}]`)
	rules := p.EdrExclusions()
	if len(rules) != 1 || !rules[0].HasScope("behavior") {
		t.Fatalf("rules: %+v", rules)
	}
	if MatchExclusion(rules, "behavior", "/bin/bash", "", "/opt/acme/acme-agent", agentSha, "") == nil {
		t.Fatal("hashed parent should be trusted")
	}
	for _, parentSha := range []string{"", strings.Repeat("b", 64)} {
		if MatchExclusion(rules, "behavior", "/bin/bash", "", "/opt/acme/acme-agent", parentSha, "") != nil {
			t.Fatalf("parent hash %q must not be trusted", parentSha)
		}
	}
	if MatchExclusion(rules, "antimalware", "/bin/bash", "", "/opt/acme/acme-agent", agentSha, "") != nil {
		t.Fatal("a rule only relaxes the scopes it lists")
	}
	if MatchExclusion(rules, "behavior", "/usr/bin/python3", "", "/opt/acme/acme-agent", agentSha, "") != nil {
		t.Fatal("other children are not covered")
	}
	if !NeedsParentHash(rules, "/opt/acme/acme-agent") || NeedsParentHash(rules, "/usr/sbin/cron") {
		t.Fatal("only parents named by a rule are hashed")
	}
}

func TestSenseOnceHonoursExclusionAndReportsIt(t *testing.T) {
	root := t.TempDir()
	parentExe := filepath.Join(root, "acme-agent")
	if err := os.WriteFile(parentExe, []byte("acme rmm agent build 7"), 0o755); err != nil {
		t.Fatal(err)
	}
	sha, _ := HashFile(parentExe, 0)
	writeProc := func(pid, ppid int, exe, cmd string) {
		dir := filepath.Join(root, "proc", itoa(pid))
		_ = os.MkdirAll(dir, 0o755)
		stat := itoa(pid) + " (x) S " + itoa(ppid) + " 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0"
		_ = os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "cmdline"), []byte(strings.ReplaceAll(cmd, " ", "\x00")), 0o644)
		_ = os.Symlink(exe, filepath.Join(dir, "exe"))
		_ = os.WriteFile(filepath.Join(dir, "status"), []byte("Uid:\t0\t0\t0\t0\n"), 0o644)
	}
	a := New(Config{StateDir: t.TempDir(), ProcRoot: filepath.Join(root, "proc")})
	_ = os.MkdirAll(a.cfg.ProcRoot, 0o755)
	a.procs = NewProcessSensor(a.cfg.ProcRoot)
	a.netw = NewNetworkSensor(a.cfg.ProcRoot)
	a.files = NewFileMonitor(nil)
	a.state.Policy = policyWithExclusions(t, `[{"id":"exc_rmm","kind":"process-chain","parentImage":"`+parentExe+`",
		"parentSha256":["`+sha+`"],"childImage":"/bin/bash","scopes":["behavior"]}]`)

	writeProc(500, 1, parentExe, parentExe)
	writeProc(501, 500, "/bin/bash", "bash -c curl http://example.test/i.sh | sh")
	a.SenseOnce()

	var applied, blocked bool
	for _, e := range a.queue {
		switch {
		case e.EventType == "edr.exclusion.applied" && strings.Contains(e.PayloadJSON, `"exc_rmm"`):
			applied = true
		case strings.HasPrefix(e.EventType, "asr.rule."):
			blocked = true
		case e.EventType == "process.start" && strings.Contains(e.PayloadJSON, `"pid":501`) &&
			!strings.Contains(e.PayloadJSON, sha):
			t.Errorf("the child's process event should carry the verified parent hash: %s", e.PayloadJSON)
		}
	}
	if !applied || blocked {
		t.Fatalf("applied=%v blocked=%v events=%+v", applied, blocked, a.queue)
	}
}
