package fleet

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// MetricsCollector produces the health snapshot sent with every heartbeat
// (CPU, memory, disks, uptime, signed-in user, reboot pending, failed services).
type MetricsCollector struct {
	ProcRoot  string
	mu        sync.Mutex
	lastIdle  uint64
	lastTotal uint64
}

func (m *MetricsCollector) cpuPercent() (float64, bool) {
	data, err := os.ReadFile(filepath.Join(m.ProcRoot, "stat"))
	if err != nil {
		return 0, false
	}
	line := strings.SplitN(string(data), "\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, false
	}
	var total, idle uint64
	for i, f := range fields[1:] {
		v, _ := strconv.ParseUint(f, 10, 64)
		total += v
		if i == 3 || i == 4 { // idle + iowait
			idle += v
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prevIdle, prevTotal := m.lastIdle, m.lastTotal
	m.lastIdle, m.lastTotal = idle, total
	if prevTotal == 0 || total <= prevTotal {
		return 0, false
	}
	busy := float64((total-prevTotal)-(idle-prevIdle)) / float64(total-prevTotal) * 100
	return busy, true
}

func memInfo(procRoot string) (usedPercent, totalGb float64, ok bool) {
	f, err := os.Open(filepath.Join(procRoot, "meminfo"))
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	values := map[string]float64{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) >= 2 {
			v, _ := strconv.ParseFloat(fields[1], 64)
			values[strings.TrimSuffix(fields[0], ":")] = v
		}
	}
	total, avail := values["MemTotal"], values["MemAvailable"]
	if total == 0 {
		return 0, 0, false
	}
	return (total - avail) / total * 100, total / (1 << 20), true
}

var realFilesystems = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
	"vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "f2fs": true, "reiserfs": true, "jfs": true}

func disks(procRoot string) []map[string]interface{} {
	data, err := os.ReadFile(filepath.Join(procRoot, "mounts"))
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []map[string]interface{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !realFilesystems[fields[2]] || seen[fields[0]] {
			continue
		}
		seen[fields[0]] = true
		var st syscall.Statfs_t
		if syscall.Statfs(fields[1], &st) != nil || st.Blocks == 0 {
			continue
		}
		total := float64(st.Blocks) * float64(st.Bsize)
		free := float64(st.Bavail) * float64(st.Bsize)
		out = append(out, map[string]interface{}{"mount": fields[1], "totalGb": total / (1 << 30), "freeGb": free / (1 << 30),
			"freePercent": free / total * 100})
	}
	return out
}

func uptimeSeconds(procRoot string) float64 {
	data, err := os.ReadFile(filepath.Join(procRoot, "uptime"))
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseFloat(strings.Fields(string(data))[0], 64)
	return v
}

func loggedOnUsers() []string {
	out, err := exec.Command("who").Output()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var users []string
	for _, line := range strings.Split(string(out), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && !seen[fields[0]] {
			seen[fields[0]] = true
			users = append(users, fields[0])
		}
	}
	return users
}

func failedServices() []string {
	out, err := exec.Command("systemctl", "--failed", "--no-legend", "--plain", "--no-pager").Output()
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			names = append(names, strings.TrimSuffix(fields[0], ".service"))
		}
	}
	return names
}

func processNames(procRoot string) []string {
	entries, _ := os.ReadDir(procRoot)
	seen := map[string]bool{}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm"))
		if err == nil {
			seen[strings.TrimSpace(string(comm))] = true
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > 400 {
		names = names[:400]
	}
	return names
}

func rebootPending() bool {
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		return true
	}
	// RHEL family: needs-restarting -r exits 1 when a reboot is needed.
	if path, err := exec.LookPath("needs-restarting"); err == nil {
		cmd := exec.Command(path, "-r")
		if err := cmd.Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
				return true
			}
		}
	}
	return false
}

func dmi(name string) string {
	data, err := os.ReadFile("/sys/class/dmi/id/" + name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// Collect returns the heartbeat "metrics" object understood by Fenrir Cloud's RMM monitors.
func (m *MetricsCollector) Collect() map[string]interface{} {
	if IsMacOS {
		return macMetrics()
	}
	out := map[string]interface{}{"remoteCapabilities": []string{"terminal", "files", "processes", "services", "desktop"}}
	if cpu, ok := m.cpuPercent(); ok {
		out["cpuPercent"] = cpu
	}
	if used, total, ok := memInfo(m.ProcRoot); ok {
		out["memoryPercent"], out["memoryTotalGb"] = used, total
	}
	out["disks"] = disks(m.ProcRoot)
	out["uptimeSeconds"] = uptimeSeconds(m.ProcRoot)
	out["lastBootAt"] = time.Now().Add(-time.Duration(uptimeSeconds(m.ProcRoot)) * time.Second).UTC().Format(time.RFC3339)
	users := loggedOnUsers()
	out["users"] = users
	if len(users) > 0 {
		out["loggedOnUser"] = users[0]
	}
	out["rebootPending"] = rebootPending()
	out["stoppedServices"] = failedServices()
	out["processNames"] = processNames(m.ProcRoot)
	out["manufacturer"], out["model"] = dmi("sys_vendor"), dmi("product_name")
	if zone, err := os.Readlink("/etc/localtime"); err == nil {
		out["timezone"] = strings.TrimPrefix(zone, "/usr/share/zoneinfo/")
	}
	return out
}
