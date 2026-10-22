package fleet

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const Version = "1.0.0"

type Config struct {
	Server          string
	EnrollmentToken string
	StateDir        string
	ProcRoot        string
	// PersistenceGlobs are watched for new/changed files (cron, systemd, ssh keys).
	PersistenceGlobs []string
	// Homes get ransomware canaries; nil means every /home/* plus /root.
	Homes           []string
	DryRunIsolation bool
}

func DefaultPersistenceGlobs() []string {
	return []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/crontab", "/var/spool/cron/crontabs",
		"/etc/systemd/system", "/etc/rc.local", "/etc/ld.so.preload", "/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys",
		"/etc/sudoers.d", "/etc/profile.d"}
}

type State struct {
	DeviceID string `json:"deviceId"`
	APIKey   string `json:"deviceApiKey"`
	DNSURL   string `json:"dnsOverHttpsUrl"`
	Policy   Policy `json:"policy"`
	Isolated bool   `json:"isolated"`
}

type Agent struct {
	cfg     Config
	client  *Client
	state   State
	scanner *Scanner
	procs   *ProcessSensor
	netw    *NetworkSensor
	files   *FileMonitor
	mu      sync.Mutex
	queue   []Event
	stop    chan struct{}
	lastInv time.Time
}

func New(cfg Config) *Agent {
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	return &Agent{cfg: cfg, client: NewClient(cfg.Server), scanner: NewScanner(filepath.Join(cfg.StateDir, "quarantine")),
		stop: make(chan struct{})}
}

func (a *Agent) statePath() string { return filepath.Join(a.cfg.StateDir, "state.json") }

func (a *Agent) saveState() error {
	data, _ := json.MarshalIndent(a.state, "", "  ")
	tmp := a.statePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.statePath())
}

func readOSRelease() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if strings.HasPrefix(s.Text(), "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(s.Text(), "PRETTY_NAME="), `"`)
		}
	}
	return "Linux"
}

func serialNumber() string {
	for _, path := range []string{"/sys/class/dmi/id/product_serial", "/etc/machine-id"} {
		if data, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(data)) != "" {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

// Start loads or creates the device identity.
func (a *Agent) Start() error {
	if err := os.MkdirAll(a.cfg.StateDir, 0o700); err != nil {
		return err
	}
	if data, err := os.ReadFile(a.statePath()); err == nil {
		if err := json.Unmarshal(data, &a.state); err != nil {
			return fmt.Errorf("corrupt state file: %w", err)
		}
	}
	if a.state.DeviceID == "" {
		host, _ := os.Hostname()
		resp, err := a.client.Enroll(EnrollRequest{Hostname: host, OSVersion: readOSRelease(), SerialNumber: serialNumber(),
			Platform: "linux", AgentVersion: Version, EnrollmentToken: a.cfg.EnrollmentToken})
		if err != nil {
			return fmt.Errorf("enrollment failed: %w", err)
		}
		a.state = State{DeviceID: resp.DeviceID, APIKey: resp.DeviceAPIKey, DNSURL: resp.DNSOverHTTPSURL, Policy: resp.Policy}
		if err := a.saveState(); err != nil {
			return err
		}
		log.Printf("enrolled as %s (approved=%v)", resp.DeviceID, resp.Approved)
	}
	a.client.DeviceID, a.client.APIKey = a.state.DeviceID, a.state.APIKey
	a.procs = NewProcessSensor(a.cfg.ProcRoot)
	a.netw = NewNetworkSensor(a.cfg.ProcRoot)
	globs := a.cfg.PersistenceGlobs
	if globs == nil {
		globs = DefaultPersistenceGlobs()
	}
	a.files = NewFileMonitor(globs)
	if a.state.Policy.ModuleBool("ransomware", "canaryFiles", true) {
		homes := a.cfg.Homes
		if homes == nil {
			homes = homeDirs()
		}
		for _, path := range PlantCanaries(homes) {
			a.files.AddCanary(path)
		}
	}
	a.emit("service.started", "agent", "Fenrir Linux agent started", map[string]interface{}{"version": Version, "os": readOSRelease()})
	return nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *Agent) emit(eventType, source, summary string, payload map[string]interface{}) {
	data, _ := json.Marshal(payload)
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.queue) > 50000 { // bounded offline spool: drop oldest
		a.queue = a.queue[len(a.queue)-40000:]
	}
	a.queue = append(a.queue, Event{EventID: newID(), EventType: eventType, Source: source, Summary: summary, OccurredAt: nowISO(), PayloadJSON: string(data)})
}

// Flush uploads queued telemetry; failed batches stay queued.
func (a *Agent) Flush() error {
	a.mu.Lock()
	batch := a.queue
	if len(batch) > 1000 {
		batch = batch[:1000]
	}
	a.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	if _, err := a.client.SendTelemetry(batch); err != nil {
		return err
	}
	a.mu.Lock()
	a.queue = a.queue[len(batch):]
	a.mu.Unlock()
	return nil
}

func (a *Agent) QueueLength() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.queue)
}

// SenseOnce runs every sensor once and applies real-time verdicts.
func (a *Agent) SenseOnce() {
	p := a.state.Policy
	for _, proc := range a.procs.Poll() {
		parent, _ := a.procs.Lookup(proc.PPID)
		payload := map[string]interface{}{"processImagePath": proc.Exe, "commandLine": proc.Cmdline, "pid": proc.PID, "ppid": proc.PPID,
			"parentProcessImagePath": parent.Exe, "parentCommandLine": parent.Cmdline, "user": userName(proc.UID)}
		if p.RealtimeProtection && proc.Exe != "" && !a.suppressed(proc.Exe) {
			if sha, err := HashFile(proc.Exe, a.scanner.MaxFileBytes); err == nil {
				payload["sha256"] = sha
				if bad, family := a.scanner.Verdict(sha); bad {
					a.blockProcess(proc, sha, family)
				}
			}
		}
		a.emit("process.start", "procfs", "", payload)
	}
	if p.ModuleBool("edr", "collectNetworkEvents", true) {
		for _, c := range a.netw.Poll() {
			a.emit("network.connect", "procfs", "", map[string]interface{}{"processImagePath": c.Exe, "pid": c.PID,
				"remoteAddress": c.RemoteIP, "remotePort": c.RemotePort, "localPort": c.LocalPort, "protocol": "tcp"})
		}
	}
	for _, change := range a.files.Poll() {
		if change.Canary {
			a.emit("ransomware.canary.touched", "canary", "A ransomware canary file was "+change.Kind,
				map[string]interface{}{"path": change.Path, "change": change.Kind})
			continue
		}
		a.emit("file."+map[string]string{"created": "create", "modified": "write", "deleted": "delete"}[change.Kind], "persistence-monitor", "",
			map[string]interface{}{"path": change.Path, "targetPath": change.Path, "change": change.Kind})
	}
}

func (a *Agent) suppressed(path string) bool {
	for _, root := range a.state.Policy.SuppressionPathRoots {
		if root != "" && strings.HasPrefix(path, root) {
			return true
		}
	}
	return false
}

func (a *Agent) blockProcess(proc ProcInfo, sha, family string) {
	p := a.state.Policy
	action := "observed"
	if p.EnforceProcessStartVerdicts {
		targets := []int{proc.PID}
		if p.TerminateProcessTreeOnBlock {
			targets = append(Descendants(a.cfg.ProcRoot, proc.PID), proc.PID)
		}
		for _, pid := range targets {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		action = "terminated"
		if p.QuarantineOnMalicious {
			if id, err := a.scanner.Quarantine(proc.Exe, sha); err == nil {
				action = "terminated+quarantined:" + id
			}
		}
	}
	a.emit("threat.process.blocked", "realtime", fmt.Sprintf("Malicious process %s (%s)", filepath.Base(proc.Exe), family),
		map[string]interface{}{"processImagePath": proc.Exe, "pid": proc.PID, "sha256": sha, "threatName": family, "verdict": action, "score": 95})
}

// ---------------------------------------------------------------------------
// Control loop
// ---------------------------------------------------------------------------

func (a *Agent) refreshPolicy() {
	policy, changed, err := a.client.PolicyCheckIn(a.state.Policy.Revision, Version)
	if err != nil {
		log.Printf("policy check-in failed: %v", err)
		return
	}
	if changed || a.state.Policy.Revision == "" {
		a.state.Policy = policy
		_ = a.saveState()
		a.emit("policy.checked-in", "agent", "Applied policy "+policy.Revision, map[string]interface{}{"revision": policy.Revision})
	}
}

func (a *Agent) refreshSignatures() {
	bundle, err := a.client.FetchBundle()
	if err != nil {
		log.Printf("signature update failed: %v", err)
		return
	}
	if bundle.SignatureVersion != a.scanner.Version {
		a.scanner.Load(bundle)
		a.emit("signatures.delta.applied", "updater", "Signatures updated", map[string]interface{}{"version": bundle.SignatureVersion, "hashes": a.scanner.Count()})
	}
}

func (a *Agent) heartbeat() {
	resp, err := a.client.Heartbeat(Version, "healthy", a.state.Isolated)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == 401 {
			log.Printf("device credentials rejected; delete %s to re-enroll", a.statePath())
		}
		log.Printf("heartbeat failed: %v", err)
		return
	}
	if resp.EffectivePolicyRevision != a.state.Policy.Revision {
		a.refreshPolicy()
	}
	if resp.CommandsPending > 0 {
		a.RunCommands()
	}
}

// Run blocks until Stop is called.
func (a *Agent) Run() {
	a.refreshPolicy()
	a.refreshSignatures()
	a.sendInventory()
	sense := time.NewTicker(2 * time.Second)
	beat := time.NewTicker(60 * time.Second)
	commands := time.NewTicker(15 * time.Second)
	sigs := time.NewTicker(time.Duration(maxInt(5, a.state.Policy.ModuleInt("updates", "signatureIntervalMinutes", 60))) * time.Minute)
	upload := time.NewTicker(time.Duration(maxInt(5, a.state.Policy.ModuleInt("edr", "telemetryUploadSeconds", 30))) * time.Second)
	defer func() { sense.Stop(); beat.Stop(); commands.Stop(); sigs.Stop(); upload.Stop() }()
	a.heartbeat()
	for {
		select {
		case <-a.stop:
			_ = a.Flush()
			return
		case <-sense.C:
			a.SenseOnce()
		case <-upload.C:
			if err := a.Flush(); err != nil {
				log.Printf("telemetry upload failed (%d queued): %v", a.QueueLength(), err)
			}
		case <-beat.C:
			a.heartbeat()
			if time.Since(a.lastInv) > 12*time.Hour {
				a.sendInventory()
			}
		case <-commands.C:
			a.RunCommands()
		case <-sigs.C:
			a.refreshSignatures()
		}
	}
}

func (a *Agent) Stop() { close(a.stop) }

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// RunCommands executes pending remote actions and reports results.
func (a *Agent) RunCommands() {
	cmds, err := a.client.PendingCommands(20)
	if err != nil {
		log.Printf("command poll failed: %v", err)
		return
	}
	for _, cmd := range cmds {
		result, err := a.Execute(cmd)
		status := "completed"
		if err != nil {
			status = "failed"
			result = map[string]interface{}{"error": err.Error()}
		}
		if err := a.client.CompleteCommand(cmd.ID, status, result); err != nil {
			log.Printf("could not report command %s: %v", cmd.ID, err)
		}
		a.emit("command."+status, "command-executor", cmd.Type, map[string]interface{}{"commandId": cmd.ID, "type": cmd.Type})
	}
	_ = a.Flush()
}

func (a *Agent) Execute(cmd Command) (map[string]interface{}, error) {
	switch cmd.Type {
	case "device.isolate":
		if !a.state.Policy.NetworkContainment {
			return nil, errors.New("network containment is disabled by policy")
		}
		if err := a.isolate(true); err != nil {
			return nil, err
		}
		a.emit("device.isolated", "command-executor", "Device isolated from the network", nil)
		return map[string]interface{}{"isolated": true}, nil
	case "device.release":
		if err := a.isolate(false); err != nil {
			return nil, err
		}
		a.emit("device.released", "command-executor", "Device released from isolation", nil)
		return map[string]interface{}{"isolated": false}, nil
	case "process.terminate", "process.tree.terminate":
		if cmd.TargetPath == "" {
			return nil, errors.New("targetPath is required")
		}
		killed := 0
		for _, pid := range FindByExe(a.cfg.ProcRoot, cmd.TargetPath) {
			targets := []int{pid}
			if cmd.Type == "process.tree.terminate" {
				targets = append(Descendants(a.cfg.ProcRoot, pid), pid)
			}
			for _, t := range targets {
				if syscall.Kill(t, syscall.SIGKILL) == nil {
					killed++
				}
			}
		}
		return map[string]interface{}{"terminatedCount": killed}, nil
	case "scan.targeted", "scan.quick", "scan.full":
		roots := []string{cmd.TargetPath}
		switch cmd.Type {
		case "scan.quick":
			roots = append([]string{"/tmp", "/var/tmp", "/dev/shm"}, homeDirs()...)
		case "scan.full":
			roots = []string{"/"}
		}
		if cmd.TargetPath == "" && cmd.Type == "scan.targeted" {
			return nil, errors.New("targetPath is required")
		}
		scanned, findings := a.scanner.ScanPaths(roots, a.state.Policy.SuppressionPathRoots, a.state.Policy.QuarantineOnMalicious, 0)
		for _, f := range findings {
			a.emit("scan.threat."+strings.SplitN(f.Action, ":", 2)[0], "scanner", "Malware found: "+f.Family,
				map[string]interface{}{"path": f.Path, "sha256": f.SHA256, "threatName": f.Family, "verdict": f.Action, "score": 95})
		}
		return map[string]interface{}{"scanned": scanned, "findings": findings}, nil
	case "remediate.path":
		sha, err := HashFile(cmd.TargetPath, 0)
		if err != nil {
			return nil, err
		}
		id, err := a.scanner.Quarantine(cmd.TargetPath, sha)
		if err != nil {
			return nil, err
		}
		a.emit("quarantine.added", "command-executor", "File quarantined by analyst", map[string]interface{}{"path": cmd.TargetPath, "recordId": id})
		return map[string]interface{}{"recordId": id, "sha256": sha}, nil
	case "quarantine.restore":
		path, err := a.scanner.Restore(cmd.RecordID)
		if err != nil {
			return nil, err
		}
		a.emit("quarantine.restored", "command-executor", "File restored from quarantine", map[string]interface{}{"path": path})
		return map[string]interface{}{"restoredTo": path}, nil
	case "quarantine.delete":
		return map[string]interface{}{"deleted": cmd.RecordID}, a.scanner.Delete(cmd.RecordID)
	case "inventory.refresh":
		a.sendInventory()
		return map[string]interface{}{"ok": true}, nil
	case "policy.refresh":
		a.refreshPolicy()
		a.refreshSignatures()
		return map[string]interface{}{"revision": a.state.Policy.Revision, "signatures": a.scanner.Version}, nil
	case "support.bundle", "forensics.collect":
		return a.triage(), nil
	case "agent.repair":
		return map[string]interface{}{"repaired": true, "version": Version}, a.saveState()
	}
	return nil, fmt.Errorf("%s is not supported by the Linux agent %s", cmd.Type, Version)
}

// ---------------------------------------------------------------------------
// Isolation via nftables (falls back to a dry run when nft is unavailable)
// ---------------------------------------------------------------------------

func (a *Agent) controlPlaneAddrs() []string {
	u, err := url.Parse(a.cfg.Server)
	if err != nil {
		return nil
	}
	addrs, _ := net.LookupHost(u.Hostname())
	return addrs
}

func IsolationRuleset(allow []string) string {
	var b strings.Builder
	b.WriteString("table inet fenrir_isolation {\n  chain out {\n    type filter hook output priority -100; policy drop;\n")
	b.WriteString("    oifname \"lo\" accept\n    ct state established,related accept\n    udp dport 53 accept\n")
	for _, addr := range allow {
		family := "ip"
		if strings.Contains(addr, ":") {
			family = "ip6"
		}
		fmt.Fprintf(&b, "    %s daddr %s accept\n", family, addr)
	}
	b.WriteString("  }\n  chain in {\n    type filter hook input priority -100; policy drop;\n    iifname \"lo\" accept\n    ct state established,related accept\n  }\n}\n")
	return b.String()
}

func (a *Agent) isolate(on bool) error {
	if on {
		allow := append(a.controlPlaneAddrs(), a.state.Policy.ModuleStrings("firewall", "isolationAllowlist")...)
		if len(allow) == 0 {
			return errors.New("refusing to isolate: cannot resolve the Fenrir Cloud address, so the device would be unreachable")
		}
		if !a.cfg.DryRunIsolation {
			cmd := exec.Command("nft", "-f", "-")
			cmd.Stdin = strings.NewReader(IsolationRuleset(allow))
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("nft failed: %v: %s", err, strings.TrimSpace(string(out)))
			}
		}
	} else if !a.cfg.DryRunIsolation {
		if out, err := exec.Command("nft", "delete", "table", "inet", "fenrir_isolation").CombinedOutput(); err != nil &&
			!strings.Contains(string(out), "No such file") {
			return fmt.Errorf("nft failed: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	a.state.Isolated = on
	return a.saveState()
}

// ---------------------------------------------------------------------------
// Inventory and triage
// ---------------------------------------------------------------------------

func installedPackages() []map[string]string {
	var out []map[string]string
	if b, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n").Output(); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if parts := strings.SplitN(line, "\t", 3); len(parts) >= 2 && parts[0] != "" {
				out = append(out, map[string]string{"name": parts[0], "version": parts[1], "vendor": strings.Join(parts[2:], "")})
			}
		}
		return out
	}
	if b, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n").Output(); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if parts := strings.SplitN(line, "\t", 3); len(parts) >= 2 && parts[0] != "" {
				out = append(out, map[string]string{"name": parts[0], "version": parts[1], "vendor": strings.Join(parts[2:], "")})
			}
		}
	}
	return out
}

func (a *Agent) sendInventory() {
	host, _ := os.Hostname()
	var addrs []string
	if ifaces, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range ifaces {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				addrs = append(addrs, ipnet.IP.String())
			}
		}
	}
	a.emit("device.inventory.snapshot", "inventory", "Inventory snapshot", map[string]interface{}{
		"osName": readOSRelease(), "hostname": host, "arch": runtime.GOARCH, "ipAddresses": addrs, "software": installedPackages(),
	})
	a.lastInv = time.Now()
	_ = a.Flush()
}

func (a *Agent) triage() map[string]interface{} {
	var procs []map[string]interface{}
	for _, pid := range listPIDs(a.cfg.ProcRoot) {
		if p, err := readProc(a.cfg.ProcRoot, pid); err == nil && p.Exe != "" {
			procs = append(procs, map[string]interface{}{"pid": p.PID, "ppid": p.PPID, "exe": p.Exe, "cmdline": p.Cmdline, "uid": p.UID})
		}
	}
	conns := append(readConns(filepath.Join(a.cfg.ProcRoot, "net/tcp")), readConns(filepath.Join(a.cfg.ProcRoot, "net/tcp6"))...)
	persistence := map[string]string{}
	for path, fp := range a.files.snapshot() {
		persistence[path] = fp
	}
	return map[string]interface{}{"collectedAt": nowISO(), "processes": procs, "connections": conns, "persistence": persistence,
		"agentVersion": Version, "signatures": a.scanner.Version, "queuedEvents": a.QueueLength()}
}
