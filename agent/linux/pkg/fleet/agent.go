package fleet

import (
	"bufio"
	"context"
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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AntiVirus/agent/linux/pkg/ml"
	"github.com/AntiVirus/agent/linux/pkg/remote"
)

const Version = "1.2.0"

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
	if IsMacOS {
		return macPersistenceGlobs()
	}
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
	wake    chan struct{}
	lastInv time.Time
	// System profile (profile.go): last upload and whether one is being collected.
	lastProfile time.Time
	profileBusy atomic.Bool
	metrics     *MetricsCollector
	remote      *remote.Manager
	cmdMu       sync.Mutex
	// Self-update (selfupdate.go); exePath/exit/restartDelay are overridable in tests.
	schedule        *scanSchedule
	lastUpdateCheck time.Time
	exePath         string
	exit            func(int)
	restartDelay    time.Duration
	// Policy firewall (firewall.go): the rules last loaded, so they are only reloaded on change.
	firewallApplied string
	firewallSet     bool
	// SSH brute-force protection (bruteforce.go).
	brute *bruteGuard
	// New USB drives and memory cards (removable.go).
	media *removableWatch
	// File hashes for strict EDR exclusions (exclusions.go).
	hashes hashCache
	// Local loopback DNS proxy (dnsproxy.go).
	dns *dnsProxyState
}

// Agent binaries can be large; exclusions never hash anything bigger.
const maxExclusionHashBytes = 512 << 20

// exclusionApplied reports what a strict exclusion let through, so every use is visible in the console.
func (a *Agent) exclusionApplied(rule *ExclusionRule, proc, parent ProcInfo, parentSha string, suppressed []string) {
	a.emit("edr.exclusion.applied", "process-guard", "Exclusion "+rule.ID+" allowed "+filepath.Base(proc.Exe),
		map[string]interface{}{"exclusionId": rule.ID, "suppressed": suppressed, "pid": proc.PID, "processImagePath": proc.Exe,
			"commandLine": proc.Cmdline, "parentProcessImagePath": parent.Exe, "parentSha256": parentSha})
}

func New(cfg Config) *Agent {
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	a := &Agent{cfg: cfg, client: NewClient(cfg.Server), scanner: NewScanner(filepath.Join(cfg.StateDir, "quarantine")),
		schedule: loadScanSchedule(cfg.StateDir),
		stop:     make(chan struct{}), wake: make(chan struct{}, 1), metrics: &MetricsCollector{ProcRoot: cfg.ProcRoot},
		remote: remote.NewManager(), exit: os.Exit, restartDelay: 5 * time.Second}
	a.remote.OnEvent = func(eventType, summary string, payload map[string]interface{}) {
		a.emit(eventType, "remote-access", summary, payload)
	}
	return a
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
	if IsMacOS {
		return macOSRelease()
	}
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
	if IsMacOS {
		if serial := macSerial(); serial != "" {
			return serial
		}
	}
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
			Platform: platformName(), AgentVersion: Version, EnrollmentToken: a.cfg.EnrollmentToken})
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
	a.emit("service.started", "agent", "Fenrir "+platformName()+" agent started", map[string]interface{}{"version": Version, "os": readOSRelease()})
	return nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// routineTelemetry maps routine (non-detection) event types to the EDR setting that collects them.
var routineTelemetry = []struct{ prefix, setting string }{
	{"process.start", "collectProcessEvents"}, {"file.", "collectFileEvents"},
	{"network.connect", "collectNetworkEvents"}, {"dns.", "collectDnsEvents"},
}

// TelemetryAllowed applies the policy's EDR collection settings. Detections, scans, quarantine and agent
// health events are always sent; only routine activity telemetry can be turned off.
func TelemetryAllowed(p Policy, eventType string) bool {
	for _, r := range routineTelemetry {
		if strings.HasPrefix(eventType, r.prefix) {
			if p.ModuleString("edr", "telemetryLevel", "standard") == "minimal" {
				return false
			}
			return p.ModuleBool("edr", r.setting, true)
		}
	}
	return true
}

func (a *Agent) emit(eventType, source, summary string, payload map[string]interface{}) {
	if !TelemetryAllowed(a.state.Policy, eventType) {
		return
	}
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
	rules := p.EdrExclusions()
	for _, proc := range a.procs.Poll() {
		parent, _ := a.procs.Lookup(proc.PPID)
		payload := map[string]interface{}{"processImagePath": proc.Exe, "commandLine": proc.Cmdline, "pid": proc.PID, "ppid": proc.PPID,
			"parentProcessImagePath": parent.Exe, "parentCommandLine": parent.Cmdline, "user": userName(proc.UID)}
		// Parent hashes are only needed (and only reported) where an exclusion names the parent's path.
		parentSha := ""
		if parent.Exe != "" && NeedsParentHash(rules, parent.Exe) {
			if parentSha = a.hashes.Hash(parent.Exe, maxExclusionHashBytes); parentSha != "" {
				payload["parentSha256"] = parentSha
			}
		}
		if p.RealtimeProtection && proc.Exe != "" && !a.suppressed(proc.Exe) {
			if sha, err := HashFile(proc.Exe, a.scanner.MaxFileBytes); err == nil {
				payload["sha256"] = sha
				if bad, family := a.scanner.Verdict(sha); bad {
					if rule := MatchExclusion(rules, "antimalware", proc.Exe, sha, parent.Exe, parentSha, proc.Cmdline); rule != nil {
						a.exclusionApplied(rule, proc, parent, parentSha, []string{"antimalware.signature:" + family})
					} else {
						switch mode := ScanOptionsFromPolicy(p).PUA; {
						case !a.scanner.IsPUA(sha) || mode == "block":
							a.blockProcess(proc, sha, family)
						case mode == "audit":
							a.emit("threat.pua.detected", "realtime", "Potentially unwanted application running: "+filepath.Base(proc.Exe),
								map[string]interface{}{"processImagePath": proc.Exe, "pid": proc.PID, "sha256": sha, "threatName": family,
									"verdict": "audit", "score": 60, "category": "pua"})
						}
					}
				}
			}
		}
		var sha string
		if v, ok := payload["sha256"].(string); ok {
			sha = v
		} else if (hasHashRules(p) || len(rules) > 0) && proc.Exe != "" {
			sha = a.hashes.Hash(proc.Exe, a.scanner.MaxFileBytes)
		}
		if decisions := EvaluateProcess(p, proc, parent, sha); len(decisions) > 0 {
			if rule := MatchExclusion(rules, "behavior", proc.Exe, sha, parent.Exe, parentSha, proc.Cmdline); rule != nil {
				names := make([]string, 0, len(decisions))
				for _, d := range decisions {
					names = append(names, d.Rule)
				}
				a.exclusionApplied(rule, proc, parent, parentSha, names)
			} else {
				a.applyDecisions(proc, decisions)
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

func hasHashRules(p Policy) bool {
	return len(p.ModuleStrings("applicationControl", "blockedApps")) > 0 || len(p.ModuleStrings("applicationControl", "allowedHashes")) > 0
}

func (a *Agent) applyDecisions(proc ProcInfo, decisions []RuleDecision) {
	terminated := false
	if strongest(decisions) == "block" && proc.PID != os.Getpid() {
		targets := []int{proc.PID}
		if a.state.Policy.TerminateProcessTreeOnBlock {
			targets = append(Descendants(a.cfg.ProcRoot, proc.PID), proc.PID)
		}
		for _, pid := range targets {
			if syscall.Kill(pid, syscall.SIGKILL) == nil {
				terminated = true
			}
		}
	}
	for _, d := range decisions {
		family := "asr.rule"
		if strings.HasPrefix(d.Rule, "applicationControl") {
			family = "appcontrol"
		}
		suffix := ".audited"
		if d.Mode == "block" {
			suffix = ".block_failed"
			if terminated {
				suffix = ".blocked"
			}
		}
		a.emit(family+suffix, "process-guard", d.Reason, map[string]interface{}{"rule": d.Rule, "mode": d.Mode, "pid": proc.PID,
			"processImagePath": proc.Exe, "commandLine": proc.Cmdline, "reason": d.Reason, "technique": d.MITRE})
	}
}

func (a *Agent) applyDeviceControl() {
	summary, notes, err := ApplyDeviceControl(a.state.Policy, "/", a.cfg.DryRunIsolation)
	switch {
	case err != nil:
		a.emit("devicecontrol.apply_failed", "device-control", "Device control could not be applied: "+err.Error(), map[string]interface{}{"notes": notes})
	case summary != "":
		a.emit("devicecontrol.applied", "device-control", "Device control applied ("+summary+")", map[string]interface{}{"summary": summary, "notes": notes})
	}
}

func mlThreshold(m *ml.Model, sensitivity string) float64 {
	if m == nil || sensitivity == "off" {
		return 0
	}
	if sensitivity == "" {
		sensitivity = "balanced"
	}
	t, ok := m.Threshold(sensitivity)
	if !ok {
		return 0
	}
	return t
}

func (a *Agent) refreshModel() {
	path := filepath.Join(a.cfg.StateDir, "models", "fenrir-pe.json.gz")
	versionPath := path + ".version"
	manifest, err := a.client.FetchModelManifest()
	if err == nil && manifest.Version != "" {
		installed, _ := os.ReadFile(versionPath)
		if strings.TrimSpace(string(installed)) != manifest.Version {
			if data, err := a.client.DownloadModel(); err == nil {
				if _, err := ml.LoadModel(data); err == nil {
					_ = os.MkdirAll(filepath.Dir(path), 0o700)
					if os.WriteFile(path+".tmp", data, 0o600) == nil && os.Rename(path+".tmp", path) == nil {
						_ = os.WriteFile(versionPath, []byte(manifest.Version), 0o600)
						a.emit("ml.model.updated", "ml-updater", "Installed static ML model "+manifest.Version, map[string]interface{}{"version": manifest.Version})
					}
				} else {
					a.emit("ml.model.update_failed", "ml-updater", "Downloaded model is invalid", map[string]interface{}{"error": err.Error()})
				}
			}
		}
	}
	if model, err := ml.LoadModelFile(path); err == nil {
		sens, _ := a.state.Policy.Modules["antimalware"]["mlSensitivity"].(string)
		a.scanner.SetModel(model, mlThreshold(model, sens))
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
	action, record := "observed", ""
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
				action, record = "terminated+quarantined:"+id, id
			}
		}
	}
	a.emit("threat.process.blocked", "realtime", fmt.Sprintf("Malicious process %s (%s)", filepath.Base(proc.Exe), family),
		map[string]interface{}{"processImagePath": proc.Exe, "pid": proc.PID, "sha256": sha, "threatName": family, "verdict": action, "score": 95, "recordId": record})
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
		a.applyDeviceControl()
		a.applyFirewall()
		a.applyDNSProxy()
		if a.scanner.Model != nil {
			sens, _ := policy.Modules["antimalware"]["mlSensitivity"].(string)
			a.scanner.SetModel(a.scanner.Model, mlThreshold(a.scanner.Model, sens))
		}
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
	resp, err := a.client.Heartbeat(Version, "healthy", a.state.Isolated, a.metrics.Collect())
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
	a.applyFirewall() // no-op unless the rules or the cloud's address changed
	if resp.CommandsPending > 0 {
		a.RunCommands()
	}
}

// Run blocks until Stop is called.
func (a *Agent) Run() {
	restoreStaleResolver(a.cfg.StateDir) // a previous run that crashed may have left the resolver pointed at its proxy
	a.refreshPolicy()
	a.applyDNSProxy()
	a.applyDeviceControl()
	a.refreshSignatures()
	a.refreshModel()
	a.sendInventory()
	sense := time.NewTicker(2 * time.Second)
	beat := time.NewTicker(60 * time.Second)
	commands := time.NewTicker(15 * time.Second)
	sigs := time.NewTicker(time.Duration(maxInt(5, a.state.Policy.ModuleInt("updates", "signatureIntervalMinutes", 60))) * time.Minute)
	upload := time.NewTicker(time.Duration(maxInt(5, a.state.Policy.ModuleInt("edr", "telemetryUploadSeconds", 30))) * time.Second)
	brute := time.NewTicker(20 * time.Second)
	media := time.NewTicker(5 * time.Second)
	defer func() {
		sense.Stop()
		beat.Stop()
		commands.Stop()
		sigs.Stop()
		upload.Stop()
		brute.Stop()
		media.Stop()
	}()
	a.metrics.Collect() // prime the CPU counters so the first heartbeat has a real value
	a.heartbeat()
	go a.listenRealtime()
	for {
		select {
		case <-a.stop:
			a.stopDNSProxy() // never leave the system resolver pointing at a proxy that is gone
			_ = a.Flush()
			return
		case <-a.wake:
			a.RunCommands()
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
			a.maybeAutoUpdate()
			a.maybeScheduledScans(time.Now())
			if time.Since(a.lastProfile) > profileInterval {
				a.startProfile()
			}
		case <-commands.C:
			a.RunCommands()
		case now := <-brute.C:
			a.checkBruteForce(now)
		case now := <-media.C:
			a.checkRemovableMedia(now)
		case <-sigs.C:
			a.refreshSignatures()
			a.refreshModel()
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
	a.cmdMu.Lock()
	defer a.cmdMu.Unlock()
	a.replayCancellationReceipts()
	cmds, err := a.client.PendingCommands(20)
	if err != nil {
		log.Printf("command poll failed: %v", err)
		return
	}
	for _, cmd := range cmds {
		receipt, found, receiptErr := a.loadCommandReceipt(cmd.ID)
		if receiptErr != nil {
			// Corrupt or inaccessible receipts are NOT a reason to re-execute an
			// unknown remote action. An operator must investigate the local state.
			log.Printf("unsafe command replay prevented for %s: %v", cmd.ID, receiptErr)
			continue
		}
		if found {
			if receipt.Status == "cancelled_ack" {
				continue
			}
			if receipt.Status == "started" {
				receipt = commandReceipt{Status: "failed", Result: map[string]interface{}{
					"error":            "Agent restarted while the command outcome was uncertain. No automatic replay was attempted.",
					"outcomeUncertain": true,
				}}
				if err := a.saveCommandReceipt(cmd.ID, receipt.Status, receipt.Result); err != nil {
					log.Printf("cannot persist interrupted command %s: %v", cmd.ID, err)
					continue
				}
			}
			// A previously executed action is NEVER executed again to recover
			// from a lost HTTP acknowledgement.
			if err := a.client.CompleteCommand(cmd.ID, receipt.Status, receipt.Result); err != nil {
				log.Printf("command %s result replay failed: %v", cmd.ID, err)
			}
			continue
		}
		if err := a.saveCommandReceipt(cmd.ID, "started", nil); err != nil {
			log.Printf("cannot journal command %s; execution blocked: %v", cmd.ID, err)
			continue
		}
		result, status, err := a.executeControlled(cmd)
		if err != nil {
			if status != "cancelled" {
				status = "failed"
			}
			if result == nil {
				result = map[string]interface{}{}
			}
			result["error"] = err.Error()
		}
		if err := a.saveCommandReceipt(cmd.ID, status, result); err != nil {
			log.Printf("command %s executed but could not persist its result; NOT sending an unjournaled outcome: %v", cmd.ID, err)
			continue
		}
		if err := a.client.CompleteCommand(cmd.ID, status, result); err != nil {
			log.Printf("could not report command %s; saved result will be replayed: %v", cmd.ID, err)
		} else if status == "cancelled" {
			_ = a.saveCommandReceipt(cmd.ID, "cancelled_ack", result)
		}
		a.emit("command."+status, "command-executor", cmd.Type, map[string]interface{}{"commandId": cmd.ID, "type": cmd.Type})
	}
	_ = a.Flush()
}

func (a *Agent) Execute(cmd Command) (map[string]interface{}, error) {
	return a.ExecuteContext(context.Background(), cmd)
}

func (a *Agent) ExecuteContext(ctx context.Context, cmd Command) (map[string]interface{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
		var payload struct {
			PID int `json:"pid"`
		}
		_ = json.Unmarshal([]byte(cmd.PayloadJSON), &payload)
		candidates := FindByExe(a.cfg.ProcRoot, cmd.TargetPath)
		if payload.PID > 0 {
			// PID-targeted: only that process (and its children), and only if it is still the same program.
			info, ok := a.procs.Lookup(payload.PID)
			if !ok || info.Exe != cmd.TargetPath {
				return map[string]interface{}{"terminatedCount": 0, "note": "process already exited or no longer matches"}, nil
			}
			candidates = []int{payload.PID}
		}
		for _, pid := range candidates {
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
			roots = a.quickScanRoots()
		case "scan.full":
			roots = []string{"/"}
		}
		if cmd.TargetPath == "" && cmd.Type == "scan.targeted" {
			return nil, errors.New("targetPath is required")
		}
		scanned, findings := a.runScanContext(ctx, roots, a.state.Policy.SuppressionPathRoots, a.state.Policy.QuarantineOnMalicious, false)
		return map[string]interface{}{"scanned": scanned, "findings": findings}, ctx.Err()
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
	case "network.probe":
		return NetworkProbe(cmd.PayloadJSON, nil)
	case "inventory.refresh":
		a.sendInventory()
		a.startProfile()
		return map[string]interface{}{"ok": true}, nil
	case "policy.refresh":
		a.refreshPolicy()
		a.refreshSignatures()
		return map[string]interface{}{"revision": a.state.Policy.Revision, "signatures": a.scanner.Version}, nil
	case "support.bundle", "forensics.collect":
		return a.collectBundle(cmd), nil
	case "update.apply":
		var p struct {
			Force bool `json:"force"`
		}
		_ = json.Unmarshal([]byte(cmd.PayloadJSON), &p)
		return a.selfUpdate(p.Force)
	case "agent.repair":
		return map[string]interface{}{"repaired": true, "version": Version}, a.saveState()
	case "script.run":
		if !a.state.Policy.ModuleBool("response", "scriptExecution", true) {
			return nil, errors.New("script execution is turned off by policy")
		}
		return RunScriptContext(ctx, a.cfg.StateDir, cmd.PayloadJSON)
	case "patch.scan":
		return PatchScanContext(ctx)
	case "pii.scan":
		return PIIScanContext(ctx, cmd.PayloadJSON)
	case "network.discover":
		return a.DiscoverContext(ctx, cmd.PayloadJSON)
	case "patch.install":
		return PatchInstallContext(ctx, cmd.PayloadJSON)
	case "software.install":
		return SoftwareInstallContext(ctx, cmd.PayloadJSON, false)
	case "software.uninstall":
		return SoftwareInstallContext(ctx, cmd.PayloadJSON, true)
	case "service.control":
		return ServiceControlContext(ctx, cmd.TargetPath, cmd.PayloadJSON)
	case "device.reboot", "device.shutdown":
		return PowerActionContext(ctx, cmd.Type == "device.reboot", cmd.PayloadJSON)
	case "remote.session.start":
		var opts remote.Options
		if err := json.Unmarshal([]byte(cmd.PayloadJSON), &opts); err != nil {
			return nil, fmt.Errorf("bad remote session payload: %w", err)
		}
		if !a.state.Policy.ModuleBool("remoteAccess", "enabled", true) {
			return map[string]interface{}{"consent": "denied"}, errors.New("remote access is turned off by policy")
		}
		opts.RelayURL = RelayURLForServer(a.cfg.Server, opts.RelayURL)
		if err := a.remote.Start(opts); err != nil {
			return nil, err
		}
		return map[string]interface{}{"started": true, "consent": "not_required"}, nil
	case "remote.session.end":
		var p struct {
			SessionID string `json:"sessionId"`
		}
		_ = json.Unmarshal([]byte(cmd.PayloadJSON), &p)
		return map[string]interface{}{"ended": a.remote.End(p.SessionID)}, nil
	}
	return nil, fmt.Errorf("%s is not supported by the Linux agent %s", cmd.Type, Version)
}

// ---------------------------------------------------------------------------
// Isolation via nftables (falls back to a dry run when nft is unavailable)
// ---------------------------------------------------------------------------

// RelayURLForServer points the relay URL at the server this agent already talks to. The cloud builds
// relayUrl from its public URL, which may not be reachable from here (a placeholder, or a name that
// only resolves outside the LAN); the path and query are kept.
func RelayURLForServer(server, relay string) string {
	s, err := url.Parse(strings.TrimSpace(server))
	if err != nil || s.Host == "" {
		return relay
	}
	r, err := url.Parse(relay)
	if err != nil || !strings.HasPrefix(r.Path, "/ws/remote/") {
		return relay
	}
	r.Host = s.Host
	if s.Scheme == "https" {
		r.Scheme = "wss"
	} else {
		r.Scheme = "ws"
	}
	if prefix := strings.TrimSuffix(strings.TrimSuffix(s.Path, "/"), "/api/v1"); prefix != "" && prefix != "/" {
		r.Path = prefix + r.Path
	}
	return r.String()
}

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
		if !a.cfg.DryRunIsolation && IsMacOS {
			if err := macIsolate(true, allow); err != nil {
				return err
			}
		} else if !a.cfg.DryRunIsolation {
			cmd := exec.Command("nft", "-f", "-")
			cmd.Stdin = strings.NewReader(IsolationRuleset(allow))
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("nft failed: %v: %s", err, strings.TrimSpace(string(out)))
			}
		}
	} else if !a.cfg.DryRunIsolation && IsMacOS {
		if err := macIsolate(false, nil); err != nil {
			return err
		}
	} else if !a.cfg.DryRunIsolation {
		if out, err := exec.Command("nft", "delete", "table", "inet", "fenrir_isolation").CombinedOutput(); err != nil &&
			!strings.Contains(string(out), "No such file") {
			return fmt.Errorf("nft failed: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	a.state.Isolated = on
	err := a.saveState()
	a.applyFirewall() // macOS: the policy anchor steps aside while isolated
	return err
}

// ---------------------------------------------------------------------------
// Inventory and triage
// ---------------------------------------------------------------------------

func installedPackages() []map[string]string {
	if IsMacOS {
		return macInstalledApps()
	}
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
	snapshot := map[string]interface{}{
		"osName": readOSRelease(), "hostname": host, "arch": runtime.GOARCH, "ipAddresses": addrs, "software": installedPackages(),
	}
	if IsMacOS {
		snapshot["permissions"] = macPermissions()
		if user := consoleUser(); user != "" {
			snapshot["loggedOnUser"] = user
		}
	}
	a.emit("device.inventory.snapshot", "inventory", "Inventory snapshot", snapshot)
	a.lastInv = time.Now()
	_ = a.Flush()
}

func (a *Agent) triage() map[string]interface{} {
	var procs []map[string]interface{}
	for _, p := range processTable(a.cfg.ProcRoot) {
		if p.Exe != "" {
			procs = append(procs, map[string]interface{}{"pid": p.PID, "ppid": p.PPID, "exe": p.Exe, "cmdline": p.Cmdline, "uid": p.UID})
		}
	}
	var conns interface{}
	if IsMacOS {
		out, _ := run(20*time.Second, "lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcn")
		conns = ParseLsofConnections(out)
	} else {
		conns = append(readConns(filepath.Join(a.cfg.ProcRoot, "net/tcp")), readConns(filepath.Join(a.cfg.ProcRoot, "net/tcp6"))...)
	}
	persistence := map[string]string{}
	for path, fp := range a.files.snapshot() {
		persistence[path] = fp
	}
	return map[string]interface{}{"collectedAt": nowISO(), "processes": procs, "connections": conns, "persistence": persistence,
		"agentVersion": Version, "signatures": a.scanner.Version, "queuedEvents": a.QueueLength()}
}
