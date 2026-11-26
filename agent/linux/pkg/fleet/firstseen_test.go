package fleet

import (
	"testing"
	"time"
)

func TestFirstSeenIsKeptAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	s := OpenFirstSeen(dir)
	if got := s.Observe("ABC", now); !got.Equal(now) {
		t.Fatalf("first observation: %v", got)
	}
	if got := s.Observe("abc", now.Add(time.Hour)); !got.Equal(now) {
		t.Fatal("a later observation must keep the first time (and ignore case)")
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	again := OpenFirstSeen(dir)
	if got := again.Observe("abc", now.Add(48*time.Hour)); !got.Equal(now) {
		t.Fatal("the first-seen time must survive a restart")
	}
	if !NewlySeen(now, now.Add(23*time.Hour)) || NewlySeen(now, now.Add(25*time.Hour)) || NewlySeen(time.Time{}, now) {
		t.Fatal("newly seen means within 24 hours of the first sighting")
	}
}

func TestBlockNewlySeenExecutables(t *testing.T) {
	p := Policy{Modules: map[string]map[string]interface{}{"applicationControl": {"mode": "enforce-denylist", "blockNewlySeenExecutables": true}}}
	fresh := ProcInfo{Exe: "/home/alex/Downloads/tool", FirstSeen: time.Now().Add(-time.Hour)}
	if !has(EvaluateProcess(p, fresh, ProcInfo{}, "abc"), "applicationControl.blockNewlySeenExecutables") {
		t.Fatal("a program first seen an hour ago in a user folder must be blocked")
	}
	old := fresh
	old.FirstSeen = time.Now().Add(-30 * time.Hour)
	if has(EvaluateProcess(p, old, ProcInfo{}, "abc"), "applicationControl.blockNewlySeenExecutables") {
		t.Fatal("after 24 hours the program is no longer new")
	}
	mac := ProcInfo{Exe: "/Users/alex/Downloads/tool", FirstSeen: time.Now()}
	if !has(EvaluateProcess(p, mac, ProcInfo{}, "abc"), "applicationControl.blockNewlySeenExecutables") {
		t.Fatal("macOS home folders are user-writable too")
	}
	system := ProcInfo{Exe: "/usr/bin/newtool", FirstSeen: time.Now()}
	if has(EvaluateProcess(p, system, ProcInfo{}, "abc"), "applicationControl.blockNewlySeenExecutables") {
		t.Fatal("system folders are left alone so package updates keep working")
	}
	audit := Policy{Modules: map[string]map[string]interface{}{"applicationControl": {"mode": "audit", "blockNewlySeenExecutables": true}}}
	if strongest(EvaluateProcess(audit, fresh, ProcInfo{}, "abc")) != "audit" {
		t.Fatal("audit mode only audits")
	}
	off := Policy{Modules: map[string]map[string]interface{}{"applicationControl": {"mode": "off", "blockNewlySeenExecutables": true}}}
	if len(EvaluateProcess(off, fresh, ProcInfo{}, "abc")) != 0 || blocksNewlySeen(off) {
		t.Fatal("with application control off nothing is blocked")
	}
	if !blocksNewlySeen(p) || !hasHashRules(p) {
		t.Fatal("the setting needs the program's hash")
	}
}
