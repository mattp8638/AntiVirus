package remote

// macOS versions of the process, service, consent and console-user helpers. Screen capture is
// not offered on macOS (it needs a signed app with Screen Recording permission), so sessions
// there provide terminal, files, processes and services.

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

var isMacOS = runtime.GOOS == "darwin"

// ParseMacProcesses reads `ps -axo pid=,user=,%cpu=,rss=,comm=` (rss in KiB, comm is the full path).
func ParseMacProcesses(out string) []Message {
	var items []Message
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		cpu, _ := strconv.ParseFloat(fields[2], 64)
		rss, _ := strconv.ParseFloat(fields[3], 64)
		path := strings.Join(fields[4:], " ")
		name := path
		if i := strings.LastIndex(path, "/"); i >= 0 {
			name = path[i+1:]
		}
		items = append(items, Message{"pid": pid, "name": name, "user": fields[1], "cpu": cpu, "memMb": rss / 1024, "path": path})
	}
	return items
}

func macProcesses() []Message {
	out, err := exec.Command("ps", "-axo", "pid=,user=,%cpu=,rss=,comm=").Output()
	if err != nil {
		return nil
	}
	return ParseMacProcesses(string(out))
}

// ParseLaunchctlList reads `launchctl list` ("PID  Status  Label").
func ParseLaunchctlList(out string) []Message {
	var items []Message
	for i, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if i == 0 && len(fields) > 0 && fields[0] == "PID" || len(fields) < 3 {
			continue
		}
		status := "stopped"
		if fields[0] != "-" {
			status = "running"
		} else if fields[1] != "0" {
			status = "failed"
		}
		items = append(items, Message{"name": fields[2], "display": fields[2], "status": status, "startType": "launchd"})
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["name"].(string) < items[j]["name"].(string) })
	return items
}

func macListServices() ([]Message, error) {
	out, err := exec.Command("launchctl", "list").Output()
	if err != nil {
		return nil, errors.New("launchctl is not available")
	}
	return ParseLaunchctlList(string(out)), nil
}

var macLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)

func macControlService(name, action string) error {
	if !macLabel.MatchString(name) {
		return errors.New("invalid launchd label")
	}
	args := map[string][]string{"start": {"kickstart", "system/" + name}, "restart": {"kickstart", "-k", "system/" + name},
		"stop": {"kill", "SIGTERM", "system/" + name}}[action]
	if args == nil {
		return errors.New("action must be start, stop or restart")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "launchctl", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func macConsoleUser() string {
	out, err := exec.Command("stat", "-f", "%Su", "/dev/console").Output()
	user := strings.TrimSpace(string(out))
	if err != nil || user == "root" {
		return ""
	}
	return user
}

// appleScriptString quotes text for an AppleScript string literal.
func appleScriptString(text string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(text) + `"`
}

// macAskConsent shows a dialog in the signed-in user's session (osascript via launchctl asuser).
func macAskConsent(opts Options, text string, timeout int) bool {
	user := macConsoleUser()
	if user == "" {
		return opts.OnConsentTimeout == "allow"
	}
	uidOut, err := exec.Command("id", "-u", user).Output()
	if err != nil {
		return opts.OnConsentTimeout == "allow"
	}
	script := fmt.Sprintf(`display dialog %s with title "Remote support request" buttons {"Deny", "Allow"} default button "Deny" giving up after %d`,
		appleScriptString(text), timeout)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+10)*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "launchctl", "asuser", strings.TrimSpace(string(uidOut)), "osascript", "-e", script).Output()
	if err != nil {
		return false
	}
	result := string(out)
	if strings.Contains(result, "gave up:true") {
		return opts.OnConsentTimeout == "allow"
	}
	return strings.Contains(result, "button returned:Allow")
}
