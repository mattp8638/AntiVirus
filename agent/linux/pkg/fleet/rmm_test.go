package fleet

import (
	"strings"
	"testing"
)

func TestRunScriptCapturesOutputAndExitCode(t *testing.T) {
	dir := t.TempDir()
	ok, err := RunScript(dir, `{"language":"bash","body":"Name='x'\"'\"'y'\necho \"hi $Name $FENRIR_NAME\"; echo oops >&2","environment":{"FENRIR_NAME":"env","bad name":"skip"},"timeoutSeconds":30}`)
	if err != nil || ok["stdout"] != "hi x'y env\n" || ok["stderr"] != "oops\n" || ok["exitCode"] != 0 {
		t.Fatalf("result %v err %v", ok, err)
	}
	failed, err := RunScript(dir, `{"language":"sh","body":"echo partial; exit 3","timeoutSeconds":30}`)
	if err == nil || failed["exitCode"] != 3 || failed["stdout"] != "partial\n" {
		t.Fatalf("result %v err %v", failed, err)
	}
	slow, err := RunScript(dir, `{"language":"sh","body":"sleep 5","timeoutSeconds":1}`)
	if err == nil || !strings.Contains(err.Error(), "timed out") || slow["exitCode"] != -1 {
		t.Fatalf("timeout result %v err %v", slow, err)
	}
	if _, err := RunScript(dir, `{"language":"powershell","body":"Get-Date"}`); err == nil {
		t.Fatal("PowerShell must be refused on Linux")
	}
}

func TestParseAptAndDnf(t *testing.T) {
	apt := ParseAptUpgradable(`Listing... Done
openssl/jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.15]
curl/jammy-updates 7.81.0-1ubuntu1.20 amd64 [upgradable from: 7.81.0-1ubuntu1.16]`)
	if len(apt) != 2 || apt[0]["id"] != "apt:openssl" || apt[0]["classification"] != "security" || apt[1]["classification"] != "updates" {
		t.Fatalf("apt %v", apt)
	}
	dnf := ParseDnfCheckUpdate(`
kernel.x86_64                 5.14.0-427.el9          baseos
nginx.x86_64                  1:1.20.1-16.el9         appstream
Obsoleting Packages
`, map[string]bool{"kernel": true}, "dnf")
	if len(dnf) != 2 || dnf[0]["id"] != "dnf:kernel" || dnf[0]["classification"] != "security" || dnf[1]["availableVersion"] != "1:1.20.1-16.el9" {
		t.Fatalf("dnf %v", dnf)
	}
}

func TestPackageNamesAreValidated(t *testing.T) {
	if _, err := SoftwareInstall(`{"installer":"apt","identifier":"--force-yes"}`, false); err == nil {
		t.Fatal("option-looking package names must be refused")
	}
	if _, err := ServiceControl("ssh; reboot", `{"action":"restart"}`); err == nil {
		t.Fatal("invalid service names must be refused")
	}
}

func TestRealtimeURL(t *testing.T) {
	if got := RealtimeURL("https://cloud.example/api/v1/", "dev_1"); got != "wss://cloud.example/api/v1/devices/dev_1/realtime" {
		t.Fatal(got)
	}
	if got := RealtimeURL("http://localhost:8080", "dev_2"); got != "ws://localhost:8080/api/v1/devices/dev_2/realtime" {
		t.Fatal(got)
	}
}

func TestMetricsCollect(t *testing.T) {
	m := &MetricsCollector{ProcRoot: "/proc"}
	m.Collect()
	out := m.Collect()
	if _, ok := out["memoryPercent"]; !ok {
		t.Fatalf("no memory metric: %v", out)
	}
	if _, ok := out["uptimeSeconds"]; !ok {
		t.Fatal("no uptime")
	}
}
