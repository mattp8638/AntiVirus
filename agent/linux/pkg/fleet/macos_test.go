package fleet

import (
	"strings"
	"testing"
)

func TestParsePSOutput(t *testing.T) {
	args := `    1     0     0 Sun Oct 25 08:00:01 2026     /sbin/launchd
  412     1   501 Sun Oct 25 09:12:44 2026     /Applications/Google Chrome.app/Contents/MacOS/Google Chrome --type=renderer
  900   412   501 Sun Oct 25 09:13:02 2026     (kernel_task)`
	comm := `    1 /sbin/launchd
  412 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
  900 kernel_task`
	procs := ParsePSOutput(args, comm)
	if len(procs) != 3 {
		t.Fatalf("want 3 processes, got %d", len(procs))
	}
	chrome := procs[412]
	if chrome.PPID != 1 || chrome.UID != 501 || chrome.Exe != "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ||
		!strings.HasSuffix(chrome.Cmdline, "--type=renderer") || chrome.StartTicks == 0 {
		t.Fatalf("unexpected %+v", chrome)
	}
	if procs[900].Exe != "" {
		t.Fatal("a bare name must not be treated as an executable path")
	}
}

func TestParseMacMetrics(t *testing.T) {
	top := "Processes: 500 total\nCPU usage: 10.0% user, 5.0% sys, 85.0% idle\n\nProcesses: 501 total\nCPU usage: 3.33% user, 6.67% sys, 90.00% idle\n"
	if cpu, ok := ParseTopCPU(top); !ok || cpu != 10 {
		t.Fatalf("cpu %v %v", cpu, ok)
	}
	vm := `Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                               20000.
Pages active:                            300000.
Pages inactive:                          290000.
Pages speculative:                        10000.
Pages wired down:                        100000.
Pages occupied by compressor:            124288.`
	used, ok := ParseVMStat(vm, 16*1024*1024*1024)
	if !ok || used != 50 { // (300000+100000+124288) pages * 16 KiB = 8 GiB of 16 GiB
		t.Fatalf("memory %v", used)
	}
	if boot, ok := ParseBootTime("{ sec = 1729880000, usec = 512345 } Fri Oct 25 18:13:20 2024"); !ok || boot.Unix() != 1729880000 {
		t.Fatal("boot time")
	}
	df := `Filesystem     1024-blocks      Used Available Capacity  Mounted on
/dev/disk3s1s1   482797652  10480000 300000000     4%    /
/dev/disk3s6     482797652   3145756 300000000     2%    /System/Volumes/VM
/dev/disk3s5     482797652 168000000 300000000    36%    /System/Volumes/Data
/dev/disk5s1     976762584 500000000 476762584    52%    /Volumes/Backup Drive
map auto_home            0         0         0   100%    /System/Volumes/Data/home`
	disks := ParseDF(df)
	if len(disks) != 2 || disks[0]["mount"] != "/" || disks[1]["mount"] != "/Volumes/Backup Drive" {
		t.Fatalf("disks %v", disks)
	}
}

func TestParseSoftwareUpdateList(t *testing.T) {
	out := `Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: macOS Sonoma 14.7.1-23H222
	Title: macOS Sonoma 14.7.1, Version: 14.7.1, Size: 1543210KiB, Recommended: YES, Action: restart,
* Label: macOS Sequoia 15.1-24B83
	Title: macOS Sequoia 15.1, Version: 15.1, Size: 6400000KiB, Recommended: YES, Action: restart,
* Label: Safari18.1SonomaAuto-18.1
	Title: Safari, Version: 18.1, Size: 160374KiB, Recommended: YES,
* Label: XProtectPlistConfigData_10_15-5279
	Title: XProtectPlistConfigData, Version: 5279, Size: 2048KiB, Recommended: YES,
* Label: Command Line Tools for Xcode-16.1
	Title: Command Line Tools for Xcode, Version: 16.1, Size: 750000KiB, Recommended: YES,
`
	patches := ParseSoftwareUpdateList(out, "14")
	byID := map[string]map[string]interface{}{}
	for _, p := range patches {
		byID[p["id"].(string)] = p
	}
	expect := map[string]string{
		"macos:macOS Sonoma 14.7.1-23H222":         "security",
		"macos:macOS Sequoia 15.1-24B83":           "feature",
		"macos:Safari18.1SonomaAuto-18.1":          "security",
		"macos:XProtectPlistConfigData_10_15-5279": "definition",
		"macos:Command Line Tools for Xcode-16.1":  "updates",
	}
	for id, class := range expect {
		if byID[id] == nil || byID[id]["classification"] != class {
			t.Errorf("%s: got %v want %s", id, byID[id], class)
		}
	}
	if byID["macos:macOS Sonoma 14.7.1-23H222"]["rebootRequired"] != true || byID["macos:Safari18.1SonomaAuto-18.1"]["rebootRequired"] != false {
		t.Error("reboot flags")
	}
	if len(ParseSoftwareUpdateList("Software Update Tool\n\nNo new software available.\n", "14")) != 0 {
		t.Error("no updates")
	}
}

func TestParseSystemProfilerAppsAndSerial(t *testing.T) {
	apps := ParseSystemProfilerApps([]byte(`{"SPApplicationsDataType":[
	 {"_name":"Google Chrome","version":"130.0.6723.92","obtained_from":"identified_developer","path":"/Applications/Google Chrome.app"},
	 {"_name":"Siri","version":"1.0","obtained_from":"apple","path":"/System/Library/CoreServices/Siri.app"},
	 {"_name":"Microsoft Word","version":"16.90","obtained_from":"mac_app_store","path":"/Applications/Microsoft Word.app"}]}`))
	if len(apps) != 2 || apps[0]["name"] != "Google Chrome" || apps[1]["vendor"] != "mac_app_store" {
		t.Fatalf("apps %v", apps)
	}
	serial := ParseIORegSerial(`+-o J314sAP  <class IOPlatformExpertDevice>
    {
      "IOPlatformSerialNumber" = "C02XG0FDJGH5"
      "IOPlatformUUID" = "0E3A..."`)
	if serial != "C02XG0FDJGH5" {
		t.Fatalf("serial %q", serial)
	}
}

func TestPFIsolationRules(t *testing.T) {
	rules := PFIsolationRules([]string{"203.0.113.10", "2001:db8::1"})
	for _, want := range []string{"block drop all", "pass quick on lo0 all", "port 53",
		"pass out quick inet proto { tcp udp } to 203.0.113.10 keep state", "pass out quick inet6 proto { tcp udp } to 2001:db8::1 keep state"} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %q in\n%s", want, rules)
		}
	}
}

func TestPlatformName(t *testing.T) {
	saved := IsMacOS
	defer func() { IsMacOS = saved }()
	IsMacOS = true
	if platformName() != "macos" || len(macPersistenceGlobs()) == 0 {
		t.Fatal("macOS platform name")
	}
	IsMacOS = false
	if platformName() != "linux" {
		t.Fatal("linux platform name")
	}
}

func TestParseBrewOutdated(t *testing.T) {
	out := ParseBrewOutdated([]byte(`{"formulae":[{"name":"openssl@3","installed_versions":["3.3.1"],"current_version":"3.3.2","pinned":false},
		{"name":"node","installed_versions":["20.1.0"],"current_version":"22.0.0","pinned":true}],
		"casks":[{"name":"google-chrome","installed_versions":["129.0"],"current_version":"130.0"},
		{"name":"zoom","installed_versions":"6.1","current_version":"6.2"}]}`))
	if len(out) != 3 {
		t.Fatalf("pinned formulae are skipped: %+v", out)
	}
	if out[0]["id"] != "brew:formula:openssl@3" || out[0]["installedVersion"] != "3.3.1" || out[0]["classification"] != "third-party" {
		t.Fatalf("formula: %+v", out[0])
	}
	if out[1]["id"] != "brew:cask:google-chrome" || out[2]["installedVersion"] != "6.1" {
		t.Fatalf("casks: %+v %+v", out[1], out[2])
	}
	if ParseBrewOutdated([]byte("not json")) != nil {
		t.Fatal("bad json")
	}
	if err := brewUpgrade("brew:formula:bad name"); err == nil {
		t.Fatal("names are validated")
	}
}

func TestParseLsofConnections(t *testing.T) {
	out := "p412\ncSafari\nn192.168.1.5:52344->17.253.144.10:443\nn[2001:db8::5]:50000->[2606:4700::1111]:443\np99\ncsshd\nn10.0.0.2:22\n"
	events := ParseLsofConnections(out)
	if len(events) != 2 {
		t.Fatalf("listening sockets have no remote end: %+v", events)
	}
	if events[0].PID != 412 || events[0].RemoteIP != "17.253.144.10" || events[0].RemotePort != 443 || events[0].LocalPort != 52344 || events[0].Exe != "Safari" {
		t.Fatalf("ipv4: %+v", events[0])
	}
	if events[1].RemoteIP != "2606:4700::1111" || events[1].LocalPort != 50000 {
		t.Fatalf("ipv6: %+v", events[1])
	}
}
