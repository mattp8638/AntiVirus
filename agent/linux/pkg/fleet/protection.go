package fleet

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Behaviour rules (Linux equivalents of the Windows attack surface rules)
// ---------------------------------------------------------------------------

type RuleDecision struct {
	Rule   string
	Mode   string // audit | warn | block
	Reason string
	MITRE  string
}

var (
	webServers  = map[string]bool{"nginx": true, "apache2": true, "httpd": true, "php-fpm": true, "php-fpm8.1": true, "php-fpm8.2": true, "php-fpm8.3": true, "php": true, "java": true, "node": true, "tomcat": true, "lighttpd": true, "caddy": true}
	shellish    = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "python": true, "python3": true, "perl": true, "ruby": true, "nc": true, "ncat": true, "netcat": true, "socat": true, "curl": true, "wget": true, "whoami": true, "id": true, "uname": true}
	downloadRun = regexp.MustCompile(`(?i)\b(curl|wget|fetch)\b[^|;]*\|\s*(sudo\s+)?(ba|da|z)?sh\b`)
	base64Run   = regexp.MustCompile(`(?i)base64\s+(-d|--decode)[^|;]*\|\s*(ba|da|z)?sh\b|exec\(\s*(base64|__import__\(['"]base64)`)
	reverseSh   = regexp.MustCompile(`(?i)/dev/tcp/|\b(nc|ncat|netcat)\b.*\s-(e|c)\s|socat\s.*exec:|pty\.spawn\(`)
)

func ruleMode(p Policy, key string) string {
	if v, ok := p.Modules["attackSurface"][key].(string); ok {
		return v
	}
	return "off"
}

func base(path string) string { return strings.ToLower(filepath.Base(path)) }

func onRemovable(path string) bool {
	for _, prefix := range []string{"/media/", "/run/media/", "/mnt/usb"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func systemPath(path string) bool {
	for _, prefix := range []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func userWritable(path string) bool {
	for _, prefix := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/run/user/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func listContains(list []string, values ...string) bool {
	for _, item := range list {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		for _, v := range values {
			if v != "" && item == strings.ToLower(v) {
				return true
			}
		}
	}
	return false
}

// EvaluateProcess applies behaviour rules and application control to a new process.
func EvaluateProcess(p Policy, proc ProcInfo, parent ProcInfo, sha string) []RuleDecision {
	var out []RuleDecision
	for _, excluded := range p.ModuleStrings("antimalware", "exclusionProcesses") {
		if base(proc.Exe) == strings.ToLower(excluded) {
			return nil
		}
	}
	add := func(key string, hit bool, reason, mitre string) {
		if !hit {
			return
		}
		if mode := ruleMode(p, key); mode != "off" && mode != "" {
			out = append(out, RuleDecision{"attackSurface." + key, mode, reason, mitre})
		}
	}
	cmd := proc.Cmdline
	add("blockWebshellCreation", webServers[base(parent.Exe)] && shellish[base(proc.Exe)],
		fmt.Sprintf("%s (web server) spawned %s", base(parent.Exe), base(proc.Exe)), "T1505.003")
	add("blockLolbinAbuse", downloadRun.MatchString(cmd) || reverseSh.MatchString(cmd),
		"download-and-execute or reverse shell command line", "T1059.004")
	add("blockObfuscatedScripts", base64Run.MatchString(cmd), "decoded script piped into an interpreter", "T1027")
	add("blockUntrustedUsbProcesses", onRemovable(proc.Exe), "program running from removable media", "T1091")
	add("blockCredentialStealingLsass", strings.Contains(cmd, "/etc/shadow") && !map[string]bool{"passwd": true, "chpasswd": true, "unix_chkpwd": true, "useradd": true, "usermod": true}[base(proc.Exe)],
		"reading the password hash database", "T1003.008")

	mode := "off"
	if v, ok := p.Modules["applicationControl"]["mode"].(string); ok {
		mode = v
	}
	if mode != "off" {
		action := "block"
		if mode == "audit" {
			action = "audit"
		}
		blocked := p.ModuleStrings("applicationControl", "blockedApps")
		if listContains(blocked, base(proc.Exe), sha, proc.Exe) {
			out = append(out, RuleDecision{"applicationControl.blockedApps", action, base(proc.Exe) + " is on the blocked list", "T1204"})
		} else if mode == "enforce-allowlist" {
			allowedHash := listContains(p.ModuleStrings("applicationControl", "allowedHashes"), sha)
			if !allowedHash && !systemPath(proc.Exe) {
				out = append(out, RuleDecision{"applicationControl.allowlist", "block", base(proc.Exe) + " is not on the allow list", "T1204"})
			}
		}
		if p.ModuleBool("applicationControl", "blockUnknownReputation", false) && userWritable(proc.Exe) {
			out = append(out, RuleDecision{"applicationControl.blockUnknownReputation", action,
				"unknown program running from a user-writable folder", "T1204.002"})
		}
	}
	return out
}

func strongest(decisions []RuleDecision) string {
	rank := map[string]int{"audit": 1, "warn": 2, "block": 3}
	best := ""
	for _, d := range decisions {
		if rank[d.Mode] > rank[best] {
			best = d.Mode
		}
	}
	return best
}

// ---------------------------------------------------------------------------
// Device control (udev + rfkill)
// ---------------------------------------------------------------------------

const udevRulesPath = "/etc/udev/rules.d/90-fenrir-device-control.rules"

// DeviceControlRules renders udev rules for the policy. Empty string means no restrictions.
func DeviceControlRules(p Policy) (string, []string) {
	var notes []string
	if !p.ModuleBool("deviceControl", "enabled", false) {
		return "", nil
	}
	usb, _ := p.Modules["deviceControl"]["usbStorage"].(string)
	var b strings.Builder
	if usb == "block" || usb == "read-only" {
		b.WriteString("# Managed by Fenrir. Local edits are overwritten.\n")
		b.WriteString("ACTION!=\"add|change\", GOTO=\"fenrir_end\"\n")
		ids := p.ModuleStrings("deviceControl", "usbAllowedIds")
		sort.Strings(ids)
		for _, id := range ids {
			parts := strings.SplitN(strings.ToLower(strings.TrimSpace(id)), ":", 2)
			if len(parts) == 2 && regexp.MustCompile(`^[0-9a-f]{4}$`).MatchString(parts[0]) && regexp.MustCompile(`^[0-9a-f]{4}$`).MatchString(parts[1]) {
				fmt.Fprintf(&b, "ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", GOTO=\"fenrir_end\"\n", parts[0], parts[1])
			} else {
				notes = append(notes, "ignored malformed USB id "+id+" (use VVVV:PPPP)")
			}
		}
		if usb == "block" {
			// Mass-storage interfaces (class 08) are de-authorised so no driver binds to them.
			b.WriteString("SUBSYSTEM==\"usb\", ENV{DEVTYPE}==\"usb_interface\", ATTR{bInterfaceClass}==\"08\", ATTR{authorized}=\"0\"\n")
		} else {
			b.WriteString("SUBSYSTEM==\"block\", ENV{ID_BUS}==\"usb\", ENV{DEVTYPE}==\"disk|partition\", RUN+=\"/sbin/blockdev --setro /dev/%k\"\n")
		}
		b.WriteString("LABEL=\"fenrir_end\"\n")
	} else if usb == "audit" {
		notes = append(notes, "USB audit mode records devices only")
	}
	for _, key := range []string{"opticalMedia", "mtpDevices", "printing"} {
		if v, _ := p.Modules["deviceControl"][key].(string); v != "" && v != "allow" {
			notes = append(notes, key+" control is not enforced on Linux yet")
		}
	}
	if p.ModuleBool("deviceControl", "encryptedUsbOnly", false) {
		notes = append(notes, "encrypted-USB-only is not enforced on Linux yet")
	}
	return b.String(), notes
}

// ApplyDeviceControl writes the udev rules and Bluetooth state. root lets tests use a temp dir.
func ApplyDeviceControl(p Policy, root string, dryRun bool) (string, []string, error) {
	rules, notes := DeviceControlRules(p)
	path := filepath.Join(root, udevRulesPath)
	current, _ := os.ReadFile(path)
	changed := string(current) != rules
	if changed {
		if rules == "" {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return "", notes, err
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return "", notes, err
			}
			if err := os.WriteFile(path, []byte(rules), 0o644); err != nil {
				return "", notes, err
			}
		}
		if !dryRun {
			_ = exec.Command("udevadm", "control", "--reload-rules").Run()
			_ = exec.Command("udevadm", "trigger", "--subsystem-match=usb", "--subsystem-match=block").Run()
		}
	}
	bt, _ := p.Modules["deviceControl"]["bluetoothFileTransfer"].(string)
	if !dryRun && p.ModuleBool("deviceControl", "enabled", false) && bt == "block" {
		if err := exec.Command("rfkill", "block", "bluetooth").Run(); err != nil {
			notes = append(notes, "rfkill unavailable: bluetooth not blocked")
		}
	}
	summary := "usb=allow"
	if usb, _ := p.Modules["deviceControl"]["usbStorage"].(string); p.ModuleBool("deviceControl", "enabled", false) && usb != "" {
		summary = "usb=" + usb
	}
	if !changed {
		summary = ""
	}
	return summary, notes, nil
}
