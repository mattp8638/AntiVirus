package fleet

// macOS support for the managed agent. The same binary (built with GOOS=darwin) speaks the full
// Fenrir protocol; this file supplies the macOS equivalents of the Linux-specific pieces:
// process table (ps), metrics (top, vm_stat, sysctl, df), software inventory (system_profiler),
// patching (softwareupdate), software (Homebrew, signed .pkg), services (launchctl) and network
// isolation (a pf anchor). Parsers are plain functions so they are unit-tested on any OS.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// IsMacOS is a variable so tests can exercise macOS paths that do not need real macOS tools.
var IsMacOS = runtime.GOOS == "darwin"

func platformName() string {
	if IsMacOS {
		return "macos"
	}
	return "linux"
}

// ---------------------------------------------------------------------------
// Process table
// ---------------------------------------------------------------------------

// ParsePSOutput combines `ps -axww -o pid=,ppid=,uid=,lstart=,args=` and `ps -axww -o pid=,comm=`.
// lstart is five tokens ("Sun Oct 25 20:10:07 2026"); comm is the full executable path on macOS.
func ParsePSOutput(argsOut, commOut string) map[int]ProcInfo {
	exes := map[int]string{}
	for _, line := range strings.Split(commOut, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		exes[pid] = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), fields[0]))
	}
	out := map[int]ProcInfo{}
	for _, line := range strings.Split(argsOut, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		pid, err1 := strconv.Atoi(fields[0])
		ppid, err2 := strconv.Atoi(fields[1])
		uid, err3 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		started, err := time.Parse("Mon Jan 2 15:04:05 2006", strings.Join(fields[3:8], " "))
		var ticks uint64
		if err == nil {
			ticks = uint64(started.Unix())
		}
		info := ProcInfo{PID: pid, PPID: ppid, UID: uid, StartTicks: ticks, Exe: exes[pid], Cmdline: strings.Join(fields[8:], " ")}
		if info.Exe != "" && !strings.HasPrefix(info.Exe, "/") {
			info.Exe = "" // a bare name (kernel task or zombie) is not an executable path
		}
		out[pid] = info
	}
	return out
}

func macProcessTable() map[int]ProcInfo {
	argsOut, err := exec.Command("ps", "-axww", "-o", "pid=,ppid=,uid=,lstart=,args=").Output()
	if err != nil {
		return nil
	}
	commOut, _ := exec.Command("ps", "-axww", "-o", "pid=,comm=").Output()
	return ParsePSOutput(string(argsOut), string(commOut))
}

// processTable returns every process: /proc on Linux, ps on macOS.
func processTable(root string) map[int]ProcInfo {
	if IsMacOS {
		return macProcessTable()
	}
	out := map[int]ProcInfo{}
	for _, pid := range listPIDs(root) {
		if p, err := readProc(root, pid); err == nil {
			out[pid] = p
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

var topCPU = regexp.MustCompile(`CPU usage:\s*([\d.]+)% user,\s*([\d.]+)% sys,\s*([\d.]+)% idle`)

// ParseTopCPU returns busy CPU % from the last sample of `top -l 2 -n 0 -s 1`.
func ParseTopCPU(out string) (float64, bool) {
	matches := topCPU.FindAllStringSubmatch(out, -1)
	if len(matches) == 0 {
		return 0, false
	}
	idle, err := strconv.ParseFloat(matches[len(matches)-1][3], 64)
	if err != nil {
		return 0, false
	}
	return 100 - idle, true
}

// ParseVMStat returns used memory % from `vm_stat` and hw.memsize (bytes).
func ParseVMStat(out string, memsize uint64) (float64, bool) {
	if memsize == 0 {
		return 0, false
	}
	pageSize := uint64(4096)
	if m := regexp.MustCompile(`page size of (\d+) bytes`).FindStringSubmatch(out); m != nil {
		pageSize, _ = strconv.ParseUint(m[1], 10, 64)
	}
	pages := map[string]uint64{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(parts[1]), "."), 10, 64)
		if err == nil {
			pages[strings.TrimSpace(parts[0])] = value
		}
	}
	used := (pages["Pages active"] + pages["Pages wired down"] + pages["Pages occupied by compressor"]) * pageSize
	if used == 0 {
		return 0, false
	}
	percent := float64(used) / float64(memsize) * 100
	if percent > 100 {
		percent = 100
	}
	return percent, true
}

// ParseBootTime reads `sysctl -n kern.boottime` ("{ sec = 1729880000, usec = 0 } ...").
func ParseBootTime(out string) (time.Time, bool) {
	m := regexp.MustCompile(`sec = (\d+)`).FindStringSubmatch(out)
	if m == nil {
		return time.Time{}, false
	}
	sec, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(sec, 0), true
}

// ParseDF reads `df -kP` and keeps the startup volume plus attached volumes (not APFS system sub-volumes).
func ParseDF(out string) []map[string]interface{} {
	var disks []map[string]interface{}
	for i, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if i == 0 || len(fields) < 6 || !strings.HasPrefix(fields[0], "/dev/") {
			continue
		}
		mount := strings.Join(fields[5:], " ")
		if mount != "/" && !strings.HasPrefix(mount, "/Volumes/") {
			continue
		}
		total, err1 := strconv.ParseFloat(fields[1], 64)
		avail, err2 := strconv.ParseFloat(fields[3], 64)
		if err1 != nil || err2 != nil || total == 0 {
			continue
		}
		disks = append(disks, map[string]interface{}{"mount": mount, "totalGb": total / (1 << 20), "freeGb": avail / (1 << 20),
			"freePercent": avail / total * 100})
	}
	return disks
}

func command(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func consoleUser() string {
	user := command("stat", "-f", "%Su", "/dev/console")
	if user == "" || user == "root" { // nobody signed in (login window)
		return ""
	}
	return user
}

func macMetrics() map[string]interface{} {
	out := map[string]interface{}{"remoteCapabilities": []string{"terminal", "files", "processes", "services"}}
	if cpu, ok := ParseTopCPU(command("top", "-l", "2", "-n", "0", "-s", "1")); ok {
		out["cpuPercent"] = cpu
	}
	memsize, _ := strconv.ParseUint(command("sysctl", "-n", "hw.memsize"), 10, 64)
	if used, ok := ParseVMStat(command("vm_stat"), memsize); ok {
		out["memoryPercent"], out["memoryTotalGb"] = used, float64(memsize)/(1<<30)
	}
	out["disks"] = ParseDF(command("df", "-kP"))
	if boot, ok := ParseBootTime(command("sysctl", "-n", "kern.boottime")); ok {
		out["uptimeSeconds"] = time.Since(boot).Seconds()
		out["lastBootAt"] = boot.UTC().Format(time.RFC3339)
	}
	if user := consoleUser(); user != "" {
		out["users"], out["loggedOnUser"] = []string{user}, user
	} else {
		out["users"] = []string{}
	}
	out["rebootPending"] = false
	out["stoppedServices"] = []string{}
	seen := map[string]bool{}
	var names []string
	for _, p := range macProcessTable() {
		if name := filepath.Base(p.Exe); p.Exe != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) > 400 {
		names = names[:400]
	}
	out["processNames"] = names
	out["manufacturer"], out["model"] = "Apple", command("sysctl", "-n", "hw.model")
	if zone, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(zone, "zoneinfo/"); i >= 0 {
			out["timezone"] = zone[i+len("zoneinfo/"):]
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Identity and inventory
// ---------------------------------------------------------------------------

func macOSRelease() string {
	name, version := command("sw_vers", "-productName"), command("sw_vers", "-productVersion")
	if name == "" {
		return "macOS"
	}
	return strings.TrimSpace(name + " " + version)
}

// ParseIORegSerial pulls IOPlatformSerialNumber from `ioreg -rd1 -c IOPlatformExpertDevice`.
func ParseIORegSerial(out string) string {
	if m := regexp.MustCompile(`"IOPlatformSerialNumber"\s*=\s*"([^"]+)"`).FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

func macSerial() string {
	return ParseIORegSerial(command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice"))
}

// ParseSystemProfilerApps reads `system_profiler SPApplicationsDataType -json`.
func ParseSystemProfilerApps(data []byte) []map[string]string {
	var doc struct {
		Apps []struct {
			Name         string `json:"_name"`
			Version      string `json:"version"`
			ObtainedFrom string `json:"obtained_from"`
			Path         string `json:"path"`
		} `json:"SPApplicationsDataType"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []map[string]string
	for _, app := range doc.Apps {
		if app.Name == "" || strings.HasPrefix(app.Path, "/System/Library/") || strings.Contains(app.Path, "/Library/Caches/") {
			continue
		}
		out = append(out, map[string]string{"name": app.Name, "version": app.Version, "vendor": app.ObtainedFrom})
		if len(out) >= 5000 {
			break
		}
	}
	return out
}

func macInstalledApps() []map[string]string {
	cmd := exec.Command("system_profiler", "SPApplicationsDataType", "-json", "-detailLevel", "mini")
	data, err := cmd.Output()
	if err != nil {
		return nil
	}
	return ParseSystemProfilerApps(data)
}

// ---------------------------------------------------------------------------
// Patching (softwareupdate)
// ---------------------------------------------------------------------------

// ParseSoftwareUpdateList reads `softwareupdate -l`. currentMajor is the running macOS major version:
// same-major macOS updates are security fixes; a different major version is a feature upgrade.
func ParseSoftwareUpdateList(out, currentMajor string) []map[string]interface{} {
	var patches []map[string]interface{}
	lines := strings.Split(out, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "* Label:") {
			continue
		}
		label := strings.TrimSpace(strings.TrimPrefix(line, "* Label:"))
		detail := ""
		if i+1 < len(lines) {
			detail = strings.TrimSpace(lines[i+1])
		}
		fields := map[string]string{}
		for _, part := range strings.Split(detail, ",") {
			if kv := strings.SplitN(part, ":", 2); len(kv) == 2 {
				fields[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
		title := fields["Title"]
		if title == "" {
			title = label
		}
		version := fields["Version"]
		classification := "updates"
		lowered := strings.ToLower(title + " " + label)
		switch {
		case strings.Contains(lowered, "xprotect") || strings.Contains(lowered, "mrt") || strings.Contains(lowered, "gatekeeper") ||
			strings.Contains(lowered, "background security") || strings.Contains(lowered, "rapid security"):
			classification = "definition"
		case strings.HasPrefix(lowered, "macos"):
			if currentMajor != "" && strings.SplitN(version, ".", 2)[0] != currentMajor {
				classification = "feature"
			} else {
				classification = "security"
			}
		case strings.Contains(lowered, "safari") || strings.Contains(lowered, "security"):
			classification = "security"
		}
		patches = append(patches, map[string]interface{}{"id": "macos:" + label, "title": strings.TrimSpace(title + " " + version),
			"source": "softwareupdate", "product": title, "availableVersion": version, "classification": classification,
			"rebootRequired": strings.Contains(strings.ToLower(fields["Action"]), "restart")})
	}
	return patches
}

func macPatchScan() (map[string]interface{}, error) {
	out, err := run(15*time.Minute, "softwareupdate", "-l")
	if err != nil && !strings.Contains(out, "No new software available") {
		return nil, fmt.Errorf("softwareupdate -l failed: %s", lastLines(out, 3))
	}
	major := strings.SplitN(command("sw_vers", "-productVersion"), ".", 2)[0]
	patches := ParseSoftwareUpdateList(out, major)
	if patches == nil {
		patches = []map[string]interface{}{}
	}
	return map[string]interface{}{"patches": patches, "rebootPending": false, "packageManager": "softwareupdate"}, nil
}

var softwareUpdateLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,199}$`)

func macPatchInstall(p installPayload) (map[string]interface{}, error) {
	results := make([]map[string]interface{}, 0, len(p.PatchIDs))
	var failures []string
	restart := false
	for _, id := range p.PatchIDs {
		label := strings.TrimPrefix(id, "macos:")
		if !strings.HasPrefix(id, "macos:") || !softwareUpdateLabel.MatchString(label) {
			results = append(results, map[string]interface{}{"id": id, "success": false, "error": "not a macOS software update"})
			continue
		}
		out, err := run(90*time.Minute, "softwareupdate", "-i", label, "--agree-to-license")
		entry := map[string]interface{}{"id": id, "success": err == nil}
		if err != nil {
			entry["error"] = lastLines(out, 2)
			failures = append(failures, label)
		}
		if strings.Contains(strings.ToLower(out), "restart") {
			restart = true
		}
		results = append(results, entry)
	}
	result := map[string]interface{}{"results": results, "rebootRequired": restart}
	if p.Reboot.Mode == "always" || (restart && p.Reboot.Mode != "never") {
		delay := p.Reboot.DeferMinutes
		if delay <= 0 {
			delay = 5
		}
		if _, err := run(30*time.Second, "shutdown", "-r", fmt.Sprintf("+%d", delay)); err == nil {
			result["rebootScheduledInMinutes"] = delay
		}
	}
	if len(failures) > 0 {
		return result, fmt.Errorf("could not install: %s", strings.Join(failures, ", "))
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Software (Homebrew as its owner, or a verified .pkg)
// ---------------------------------------------------------------------------

func brewCommand() (path, owner string, err error) {
	for _, candidate := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
		info, statErr := os.Stat(candidate)
		if statErr != nil {
			continue
		}
		if sys, ok := info.Sys().(*syscall.Stat_t); ok {
			return candidate, userName(int(sys.Uid)), nil
		}
	}
	return "", "", errors.New("Homebrew is not installed on this Mac")
}

func macSoftware(p softwarePayload, sha string, uninstall bool) (map[string]interface{}, error) {
	switch p.Installer {
	case "brew":
		if !packageName.MatchString(p.Identifier) {
			return nil, errors.New("invalid package name")
		}
		brew, owner, err := brewCommand()
		if err != nil {
			return nil, err
		}
		verb := "install"
		if uninstall {
			verb = "uninstall"
		}
		// Homebrew refuses to run as root; run it as the account that owns the installation.
		out, err := run(30*time.Minute, "sudo", "-u", owner, "-H", brew, verb, p.Identifier)
		result := map[string]interface{}{"output": lastLines(out, 20)}
		if err != nil {
			return result, fmt.Errorf("brew %s failed: %s", verb, lastLines(out, 3))
		}
		return result, nil
	case "pkg":
		if uninstall {
			return nil, errors.New(".pkg installers cannot be removed generically; use a script or the vendor's uninstaller")
		}
		path, err := downloadVerified(p.Identifier, sha)
		if err != nil {
			return nil, err
		}
		defer os.Remove(path)
		out, err := run(60*time.Minute, "installer", "-pkg", path, "-target", "/")
		result := map[string]interface{}{"output": lastLines(out, 20)}
		if err != nil {
			return result, fmt.Errorf("installer failed: %s", lastLines(out, 3))
		}
		return result, nil
	}
	return nil, fmt.Errorf("%s packages cannot be installed on macOS (use brew or pkg)", p.Installer)
}

func downloadVerified(url, sha string) (string, error) {
	if !strings.HasPrefix(url, "https://") || len(sha) != 64 {
		return "", errors.New("pkg installers need an https URL and SHA-256")
	}
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("download returned %d", resp.StatusCode)
	}
	file, err := os.CreateTemp("", "fenrir-*.pkg")
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(resp.Body, 4<<30)); err != nil {
		file.Close()
		os.Remove(file.Name())
		return "", err
	}
	file.Close()
	if got := hex.EncodeToString(hash.Sum(nil)); !strings.EqualFold(got, sha) {
		os.Remove(file.Name())
		return "", fmt.Errorf("checksum mismatch (expected %s, got %s)", sha, got)
	}
	return file.Name(), nil
}

// ---------------------------------------------------------------------------
// Services (launchd) and isolation (pf)
// ---------------------------------------------------------------------------

var launchdLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)

func macServiceControl(label, action string) (map[string]interface{}, error) {
	if !launchdLabel.MatchString(label) {
		return nil, errors.New("invalid launchd label")
	}
	target := "system/" + label
	var args []string
	switch action {
	case "start":
		args = []string{"kickstart", target}
	case "restart":
		args = []string{"kickstart", "-k", target}
	case "stop":
		args = []string{"kill", "SIGTERM", target}
	default:
		return nil, errors.New("action must be start, stop or restart")
	}
	if out, err := run(2*time.Minute, "launchctl", args...); err != nil {
		return nil, fmt.Errorf("launchctl %s %s: %s", args[0], label, lastLines(out, 3))
	}
	state := "unknown"
	if out, err := run(30*time.Second, "launchctl", "print", target); err == nil {
		if m := regexp.MustCompile(`(?m)^\s*state = (\S+)`).FindStringSubmatch(out); m != nil {
			state = m[1]
		}
	}
	return map[string]interface{}{"service": label, "action": action, "status": state}, nil
}

// PFAnchor is evaluated because macOS's default /etc/pf.conf includes `anchor "com.apple/*"`.
const PFAnchor = "com.apple/fenrir"

// PFIsolationRules allows loopback, DNS and the given addresses; everything else is dropped.
func PFIsolationRules(allow []string) string {
	var b strings.Builder
	b.WriteString("block drop all\npass quick on lo0 all\npass out quick proto udp to any port 53 keep state\n")
	for _, addr := range allow {
		family := "inet"
		if strings.Contains(addr, ":") {
			family = "inet6"
		}
		fmt.Fprintf(&b, "pass out quick %s proto { tcp udp } to %s keep state\n", family, addr)
	}
	return b.String()
}

func macIsolate(on bool, allow []string) error {
	if !on {
		if out, err := exec.Command("pfctl", "-a", PFAnchor, "-F", "all").CombinedOutput(); err != nil {
			return fmt.Errorf("pfctl failed: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	_ = exec.Command("pfctl", "-E").Run() // enable pf (harmless if already on)
	cmd := exec.Command("pfctl", "-a", PFAnchor, "-f", "-")
	cmd.Stdin = strings.NewReader(PFIsolationRules(allow))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

func macPersistenceGlobs() []string {
	return []string{"/Library/LaunchDaemons", "/Library/LaunchAgents", "/Users/*/Library/LaunchAgents", "/etc/periodic/daily",
		"/etc/periodic/weekly", "/etc/sudoers.d", "/var/at/tabs", "/usr/lib/cron/tabs", "/Users/*/.ssh/authorized_keys",
		"/var/root/.ssh/authorized_keys", "/etc/profile", "/etc/zshrc"}
}

func macHomeDirs() []string {
	matches, _ := filepath.Glob("/Users/*")
	var homes []string
	for _, home := range matches {
		if base := filepath.Base(home); base != "Shared" && !strings.HasPrefix(base, ".") {
			homes = append(homes, home)
		}
	}
	return homes
}

func macQuickScanRoots() []string {
	roots := []string{"/private/tmp", "/private/var/tmp", "/Users/Shared"}
	for _, home := range macHomeDirs() {
		roots = append(roots, filepath.Join(home, "Downloads"), filepath.Join(home, "Desktop"),
			filepath.Join(home, "Library", "LaunchAgents"))
	}
	return roots
}
