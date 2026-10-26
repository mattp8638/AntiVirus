package remote

import "testing"

func TestParseMacProcessesAndServices(t *testing.T) {
	procs := ParseMacProcesses("  412 jo  12.5 204800 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n    1 root 0.0 12000 /sbin/launchd\n")
	if len(procs) != 2 || procs[0]["name"] != "Google Chrome" || procs[0]["memMb"] != 200.0 || procs[0]["user"] != "jo" {
		t.Fatalf("procs %v", procs)
	}
	services := ParseLaunchctlList("PID\tStatus\tLabel\n-\t0\tcom.apple.backupd\n412\t0\tcom.apple.Finder\n-\t78\tcom.example.broken\n")
	if len(services) != 3 {
		t.Fatalf("services %v", services)
	}
	status := map[string]string{}
	for _, s := range services {
		status[s["name"].(string)] = s["status"].(string)
	}
	if status["com.apple.Finder"] != "running" || status["com.apple.backupd"] != "stopped" || status["com.example.broken"] != "failed" {
		t.Fatalf("status %v", status)
	}
	if appleScriptString(`say "hi" \ bye`) != `"say \"hi\" \\ bye"` {
		t.Fatal("applescript quoting")
	}
}
