package fleet

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const maxScriptOutput = 64 << 10

// limitedBuffer keeps the first maxScriptOutput bytes and counts the rest.
type limitedBuffer struct {
	buf       bytes.Buffer
	truncated int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	room := maxScriptOutput - l.buf.Len()
	if room > 0 {
		if len(p) <= room {
			l.buf.Write(p)
		} else {
			l.buf.Write(p[:room])
			l.truncated += len(p) - room
		}
	} else {
		l.truncated += len(p)
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string {
	if l.truncated > 0 {
		return l.buf.String() + fmt.Sprintf("\n… %d more bytes not shown", l.truncated)
	}
	return l.buf.String()
}

type scriptPayload struct {
	ScriptName     string            `json:"scriptName"`
	Language       string            `json:"language"`
	Body           string            `json:"body"`
	Environment    map[string]string `json:"environment"`
	TimeoutSeconds int               `json:"timeoutSeconds"`
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// RunScript executes a library script and captures exit code, stdout and stderr.
func RunScript(stateDir string, raw string) (map[string]interface{}, error) {
	return RunScriptContext(context.Background(), stateDir, raw)
}

func RunScriptContext(ctx context.Context, stateDir string, raw string) (map[string]interface{}, error) {
	var p scriptPayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil || p.Body == "" {
		return nil, errors.New("script payload is missing")
	}
	interpreters := map[string][]string{"bash": {"/bin/bash"}, "sh": {"/bin/sh"}, "zsh": {"/bin/zsh"}, "python": {"python3"}}
	interp, ok := interpreters[p.Language]
	if !ok {
		return nil, fmt.Errorf("%s scripts cannot run on Linux", p.Language)
	}
	dir := filepath.Join(stateDir, "scripts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(dir, "run-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	if _, err := file.WriteString(p.Body); err != nil {
		file.Close()
		return nil, err
	}
	file.Close()
	timeout := time.Duration(p.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > 24*time.Hour {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, interp[0], append(interp[1:], file.Name())...)
	// Kill the whole process group on timeout, so children (sleep, curl...) cannot keep the job alive.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "FENRIR_SCRIPT="+p.ScriptName)
	for k, v := range p.Environment {
		if envName.MatchString(k) {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	var stdout, stderr limitedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	started := time.Now()
	runErr := cmd.Run()
	result := map[string]interface{}{"stdout": stdout.String(), "stderr": stderr.String(),
		"durationMs": time.Since(started).Milliseconds(), "exitCode": 0}
	if ctx.Err() == context.DeadlineExceeded {
		result["exitCode"] = -1
		return result, fmt.Errorf("script timed out after %s", timeout)
	}
	if runErr != nil {
		var exit *exec.ExitError
		if errors.As(runErr, &exit) {
			result["exitCode"] = exit.ExitCode()
			return result, fmt.Errorf("script exited with code %d", exit.ExitCode())
		}
		return result, runErr
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Patching through the system package manager
// ---------------------------------------------------------------------------

var packageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:@-]*$`)

func packageManager() string {
	for _, pm := range []string{"apt-get", "dnf", "yum", "zypper"} {
		if _, err := exec.LookPath(pm); err == nil {
			return pm
		}
	}
	return ""
}

func run(timeout time.Duration, name string, args ...string) (string, error) {
	return runContext(context.Background(), timeout, name, args...)
}

func runContext(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ParseAptUpgradable reads `apt list --upgradable` output.
func ParseAptUpgradable(out string) []map[string]interface{} {
	var patches []map[string]interface{}
	re := regexp.MustCompile(`^([^/\s]+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]`)
	for _, line := range strings.Split(out, "\n") {
		m := re.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		classification := "updates"
		if strings.Contains(m[2], "security") {
			classification = "security"
		}
		patches = append(patches, map[string]interface{}{"id": "apt:" + m[1], "title": m[1] + " " + m[4] + " → " + m[3], "source": "apt",
			"product": m[1], "installedVersion": m[4], "availableVersion": m[3], "classification": classification})
	}
	return patches
}

// ParseDnfCheckUpdate reads `dnf check-update` output; security names come from `dnf updateinfo list --security`.
func ParseDnfCheckUpdate(out string, security map[string]bool, source string) []map[string]interface{} {
	var patches []map[string]interface{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || strings.HasPrefix(line, " ") || !strings.Contains(fields[0], ".") {
			continue
		}
		name := fields[0][:strings.LastIndex(fields[0], ".")]
		classification := "updates"
		if security[name] {
			classification = "security"
		}
		patches = append(patches, map[string]interface{}{"id": source + ":" + name, "title": name + " → " + fields[1], "source": source,
			"product": name, "availableVersion": fields[1], "classification": classification})
	}
	return patches
}

// PatchScan lists available package updates.
func PatchScan() (map[string]interface{}, error) { return PatchScanContext(context.Background()) }

func PatchScanContext(ctx context.Context) (map[string]interface{}, error) {
	if IsMacOS {
		return macPatchScanContext(ctx)
	}
	pm := packageManager()
	var patches []map[string]interface{}
	switch pm {
	case "apt-get":
		if out, err := runContext(ctx, 10*time.Minute, "apt-get", "update", "-qq"); err != nil {
			return nil, fmt.Errorf("apt-get update failed: %s", lastLines(out, 3))
		}
		out, err := runContext(ctx, 5*time.Minute, "apt", "list", "--upgradable")
		if err != nil {
			return nil, err
		}
		patches = ParseAptUpgradable(out)
	case "dnf", "yum":
		security := map[string]bool{}
		if out, err := runContext(ctx, 10*time.Minute, pm, "-q", "updateinfo", "list", "--security"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				if f := strings.Fields(line); len(f) >= 3 {
					pkg := f[2]
					if i := strings.LastIndex(pkg, "-"); i > 0 {
						if j := strings.LastIndex(pkg[:i], "-"); j > 0 {
							security[pkg[:j]] = true
						}
					}
				}
			}
		}
		out, err := runContext(ctx, 10*time.Minute, pm, "-q", "check-update")
		var exit *exec.ExitError
		if err != nil && !(errors.As(err, &exit) && exit.ExitCode() == 100) {
			return nil, fmt.Errorf("%s check-update failed: %s", pm, lastLines(out, 3))
		}
		patches = ParseDnfCheckUpdate(out, security, pm)
	case "zypper":
		out, err := runContext(ctx, 10*time.Minute, "zypper", "-q", "--non-interactive", "list-updates")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(out, "\n") {
			cols := strings.Split(line, "|")
			if len(cols) >= 6 && strings.TrimSpace(cols[0]) == "v" {
				name := strings.TrimSpace(cols[2])
				patches = append(patches, map[string]interface{}{"id": "zypper:" + name, "title": name + " → " + strings.TrimSpace(cols[4]),
					"source": "zypper", "product": name, "installedVersion": strings.TrimSpace(cols[3]),
					"availableVersion": strings.TrimSpace(cols[4]), "classification": "updates"})
			}
		}
	default:
		return nil, errors.New("no supported package manager (apt, dnf, yum, zypper)")
	}
	sort.Slice(patches, func(i, j int) bool { return patches[i]["id"].(string) < patches[j]["id"].(string) })
	return map[string]interface{}{"patches": patches, "rebootPending": rebootPending(), "packageManager": pm}, nil
}

type installPayload struct {
	PatchIDs []string `json:"patchIds"`
	Reboot   struct {
		Mode         string `json:"mode"`
		DeferMinutes int    `json:"deferMinutes"`
	} `json:"reboot"`
}

// PatchInstall upgrades the listed packages, then reboots according to the policy.
func PatchInstall(raw string) (map[string]interface{}, error) {
	return PatchInstallContext(context.Background(), raw)
}

func PatchInstallContext(ctx context.Context, raw string) (map[string]interface{}, error) {
	var p installPayload
	_ = json.Unmarshal([]byte(raw), &p)
	if IsMacOS {
		return macPatchInstallContext(ctx, p)
	}
	pm := packageManager()
	var names []string
	byName := map[string]string{}
	for _, id := range p.PatchIDs {
		name := id
		if i := strings.Index(id, ":"); i >= 0 {
			name = id[i+1:]
		}
		if packageName.MatchString(name) {
			names = append(names, name)
			byName[name] = id
		}
	}
	if len(names) == 0 {
		return map[string]interface{}{"results": []interface{}{}}, nil
	}
	var out string
	var err error
	switch pm {
	case "apt-get":
		out, err = runContext(ctx, 60*time.Minute, "apt-get", append([]string{"install", "--only-upgrade", "-y", "-o", "Dpkg::Options::=--force-confold", "--"}, names...)...)
	case "dnf", "yum":
		out, err = runContext(ctx, 60*time.Minute, pm, append([]string{"upgrade", "-y", "--"}, names...)...)
	case "zypper":
		out, err = runContext(ctx, 60*time.Minute, "zypper", append([]string{"--non-interactive", "update", "--"}, names...)...)
	default:
		return nil, errors.New("no supported package manager")
	}
	results := make([]map[string]interface{}, 0, len(names))
	for _, name := range names {
		entry := map[string]interface{}{"id": byName[name], "success": err == nil}
		if err != nil {
			entry["error"] = lastLines(out, 2)
		}
		results = append(results, entry)
	}
	pending := rebootPending()
	result := map[string]interface{}{"results": results, "rebootRequired": pending, "output": lastLines(out, 20)}
	if p.Reboot.Mode == "always" || (pending && p.Reboot.Mode != "never") {
		delay := p.Reboot.DeferMinutes
		if delay <= 0 {
			delay = 5
		}
		if _, rerr := runContext(ctx, 30*time.Second, "shutdown", "-r", fmt.Sprintf("+%d", delay), "Fenrir: restarting to finish updates"); rerr == nil {
			result["rebootScheduledInMinutes"] = delay
		}
	}
	if err != nil {
		return result, fmt.Errorf("package upgrade failed: %s", lastLines(out, 3))
	}
	return result, nil
}

type softwarePayload struct {
	Installer  string `json:"installer"`
	Identifier string `json:"identifier"`
	Action     string `json:"action"`
	SHA256     string `json:"sha256"`
}

// SoftwareInstall installs or removes a package from the software library.
func SoftwareInstall(raw string, uninstall bool) (map[string]interface{}, error) {
	return SoftwareInstallContext(context.Background(), raw, uninstall)
}

func SoftwareInstallContext(ctx context.Context, raw string, uninstall bool) (map[string]interface{}, error) {
	var p softwarePayload
	_ = json.Unmarshal([]byte(raw), &p)
	if IsMacOS {
		return macSoftwareContext(ctx, p, p.SHA256, uninstall)
	}
	if !packageName.MatchString(p.Identifier) {
		return nil, errors.New("invalid package name")
	}
	var args []string
	switch p.Installer {
	case "apt":
		verb := "install"
		if uninstall {
			verb = "remove"
		}
		args = []string{"apt-get", verb, "-y", "--", p.Identifier}
	case "dnf":
		verb := "install"
		if uninstall {
			verb = "remove"
		}
		args = []string{packageManager(), verb, "-y", "--", p.Identifier}
	case "snap":
		verb := "install"
		if uninstall {
			verb = "remove"
		}
		args = []string{"snap", verb, p.Identifier}
	default:
		return nil, fmt.Errorf("%s packages cannot be installed on Linux", p.Installer)
	}
	out, err := runContext(ctx, 30*time.Minute, args[0], args[1:]...)
	result := map[string]interface{}{"output": lastLines(out, 20)}
	if err != nil {
		return result, fmt.Errorf("%s failed: %s", strings.Join(args[:2], " "), lastLines(out, 3))
	}
	return result, nil
}

// ServiceControl starts, stops or restarts a systemd unit.
func ServiceControl(name, raw string) (map[string]interface{}, error) {
	return ServiceControlContext(context.Background(), name, raw)
}

func ServiceControlContext(ctx context.Context, name, raw string) (map[string]interface{}, error) {
	var p struct {
		Action string `json:"action"`
	}
	_ = json.Unmarshal([]byte(raw), &p)
	if p.Action == "" {
		p.Action = "restart"
	}
	if p.Action != "start" && p.Action != "stop" && p.Action != "restart" {
		return nil, errors.New("action must be start, stop or restart")
	}
	if IsMacOS {
		return macServiceControlContext(ctx, name, p.Action)
	}
	if !packageName.MatchString(name) {
		return nil, errors.New("invalid service name")
	}
	if out, err := runContext(ctx, 2*time.Minute, "systemctl", p.Action, "--", name); err != nil {
		return nil, fmt.Errorf("systemctl %s %s: %s", p.Action, name, lastLines(out, 3))
	}
	status, _ := runContext(ctx, 30*time.Second, "systemctl", "is-active", "--", name)
	return map[string]interface{}{"service": name, "action": p.Action, "status": strings.TrimSpace(status)}, nil
}

// PowerAction schedules a reboot or shutdown.
func PowerAction(reboot bool, raw string) (map[string]interface{}, error) {
	return PowerActionContext(context.Background(), reboot, raw)
}

func PowerActionContext(ctx context.Context, reboot bool, raw string) (map[string]interface{}, error) {
	var p struct {
		DelayMinutes int    `json:"delayMinutes"`
		Message      string `json:"message"`
	}
	_ = json.Unmarshal([]byte(raw), &p)
	if p.DelayMinutes < 0 || p.DelayMinutes > 1440 {
		p.DelayMinutes = 1
	}
	flag := "-h"
	if reboot {
		flag = "-r"
	}
	message := p.Message
	if message == "" {
		message = "Fenrir: your IT provider is restarting this computer"
	}
	if out, err := runContext(ctx, 30*time.Second, "shutdown", flag, fmt.Sprintf("+%d", p.DelayMinutes), message); err != nil {
		return nil, fmt.Errorf("shutdown failed: %s", lastLines(out, 2))
	}
	return map[string]interface{}{"scheduledInMinutes": p.DelayMinutes, "reboot": reboot}, nil
}

func lastLines(text string, n int) string {
	var lines []string
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		if strings.TrimSpace(s.Text()) != "" {
			lines = append(lines, s.Text())
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
