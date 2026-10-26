package fleet

// SSH brute-force protection (firewall.bruteForceProtection) on Linux and macOS: failed SSH sign-ins are read
// from the system log, and an address that fails 10 times inside 10 minutes is dropped by the firewall for an
// hour (four times longer for each repeat, up to a day). Same thresholds as the Windows agent.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	bruteThreshold      = 10
	bruteWindowSeconds  = 600
	bruteBaseBlockSecs  = 3600
	bruteMaxBlockSecs   = 86400
	bruteNftTable       = "fenrir_bruteforce"
	brutePFAnchor       = "com.apple/fenrir-bruteforce"
	brutePFTable        = "fenrir_bruteforce"
	bruteMaxLogReadSize = 4 << 20
)

type bruteBlock struct {
	Address  string
	Until    int64
	Strikes  int
	Failures int
	Accounts []string
}

type bruteTracker struct {
	failures map[string][]int64
	accounts map[string]map[string]bool
	blocks   map[string]bruteBlock
	strikes  map[string][2]int64 // address -> {strikes, last block time}
}

func newBruteTracker() *bruteTracker {
	return &bruteTracker{failures: map[string][]int64{}, accounts: map[string]map[string]bool{},
		blocks: map[string]bruteBlock{}, strikes: map[string][2]int64{}}
}

// normaliseRemoteAddress returns the canonical form of an IP literal worth counting, or "".
func normaliseRemoteAddress(s string) string {
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(s), "[]"))
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.Equal(net.IPv4bcast) {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func (t *bruteTracker) onFailure(raw, account string, now int64) *bruteBlock {
	addr := normaliseRemoteAddress(raw)
	if addr == "" {
		return nil
	}
	if _, blocked := t.blocks[addr]; blocked {
		return nil
	}
	times := t.failures[addr]
	for len(times) > 0 && times[0]+bruteWindowSeconds <= now {
		times = times[1:]
	}
	times = append(times, now)
	t.failures[addr] = times
	if account != "" {
		if t.accounts[addr] == nil {
			t.accounts[addr] = map[string]bool{}
		}
		if len(t.accounts[addr]) < 10 {
			t.accounts[addr][account] = true
		}
	}
	if len(times) < bruteThreshold {
		if len(t.failures) > 10000 {
			for a, ts := range t.failures {
				if len(ts) == 0 || ts[len(ts)-1]+bruteWindowSeconds <= now {
					delete(t.failures, a)
					delete(t.accounts, a)
				}
			}
		}
		return nil
	}
	s := t.strikes[addr]
	if s[1]+bruteMaxBlockSecs < now {
		s[0] = 0
	}
	if s[0] < 5 {
		s[0]++
	}
	s[1] = now
	t.strikes[addr] = s
	duration := int64(bruteBaseBlockSecs)
	for i := int64(1); i < s[0]; i++ {
		duration *= 4
	}
	if duration > bruteMaxBlockSecs {
		duration = bruteMaxBlockSecs
	}
	accounts := make([]string, 0, len(t.accounts[addr]))
	for a := range t.accounts[addr] {
		accounts = append(accounts, a)
	}
	sort.Strings(accounts)
	block := bruteBlock{Address: addr, Until: now + duration, Strikes: int(s[0]), Failures: len(times), Accounts: accounts}
	t.blocks[addr] = block
	delete(t.failures, addr)
	delete(t.accounts, addr)
	return &block
}

func (t *bruteTracker) expire(now int64) []string {
	var out []string
	for a, b := range t.blocks {
		if b.Until <= now {
			out = append(out, a)
			delete(t.blocks, a)
		}
	}
	sort.Strings(out)
	return out
}

func (t *bruteTracker) clear() []string {
	var out []string
	for a := range t.blocks {
		out = append(out, a)
	}
	t.blocks = map[string]bruteBlock{}
	t.failures = map[string][]int64{}
	t.accounts = map[string]map[string]bool{}
	return out
}

// sshd: "Failed password for root from 1.2.3.4 port 22 ssh2", "Invalid user admin from 1.2.3.4 port 5555".
// "Failed ... for invalid user x" follows an "Invalid user x" line for the same attempt, so it is not counted again.
var sshFailureLine = regexp.MustCompile(`(?:Failed (?:password|publickey|keyboard-interactive/pam|none) for (invalid user )?(\S*)|Invalid user (\S*)) from (\S+)`)

func parseSSHFailure(line string) (addr, user string, ok bool) {
	m := sshFailureLine.FindStringSubmatch(line)
	if m == nil || m[1] != "" {
		return "", "", false
	}
	user = m[2]
	if user == "" {
		user = m[3]
	}
	return m[4], user, true
}

// sshLogReader returns sshd log lines written since the previous call.
type sshLogReader struct {
	path    string
	offset  int64
	started bool
	cursor  string // journalctl
	since   time.Time
	macLast string // macOS unified log: last timestamp seen
}

func (r *sshLogReader) lines() []string {
	if IsMacOS {
		return r.macLines()
	}
	if r.path == "" {
		for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
				r.path = p
				break
			}
		}
	}
	if r.path != "" {
		return r.fileLines()
	}
	return r.journalLines()
}

func (r *sshLogReader) fileLines() []string {
	f, err := os.Open(r.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	if !r.started {
		// Start at the end: attempts from before the agent started are history, not an attack in progress.
		r.started, r.offset = true, st.Size()
		return nil
	}
	if st.Size() < r.offset {
		r.offset = 0 // rotated
	}
	if st.Size()-r.offset > bruteMaxLogReadSize {
		r.offset = st.Size() - bruteMaxLogReadSize
	}
	if _, err := f.Seek(r.offset, io.SeekStart); err != nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(f, bruteMaxLogReadSize))
	if err != nil {
		return nil
	}
	// Leave a partly written last line for next time.
	if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
		data = data[:i+1]
	} else {
		data = nil
	}
	r.offset += int64(len(data))
	return splitLines(data)
}

func (r *sshLogReader) journalLines() []string {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil
	}
	args := []string{"--no-pager", "-o", "cat", "--show-cursor", "_COMM=sshd", "+", "_COMM=sshd-session"}
	if r.cursor != "" {
		args = append(args, "--after-cursor="+r.cursor)
	} else {
		if r.since.IsZero() {
			r.since = time.Now()
			return nil
		}
		args = append(args, "--since="+r.since.Format("2006-01-02 15:04:05"))
	}
	out, err := exec.Command("journalctl", args...).Output()
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range splitLines(out) {
		if strings.HasPrefix(l, "-- cursor: ") {
			r.cursor = strings.TrimPrefix(l, "-- cursor: ")
			continue
		}
		lines = append(lines, l)
	}
	r.since = time.Now()
	return lines
}

func (r *sshLogReader) macLines() []string {
	start := r.macLast
	if start == "" {
		r.macLast = time.Now().Format("2006-01-02 15:04:05")
		return nil
	}
	out, err := exec.Command("log", "show", "--style", "syslog", "--start", start,
		"--predicate", `(process == "sshd") OR (process == "sshd-session")`).Output()
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range splitLines(out) {
		// "2026-10-26 22:42:21.123456+0000 host sshd[123]: ..."
		if len(l) < 26 || l[4] != '-' {
			continue
		}
		stamp := l[:26]
		if stamp <= r.macLast {
			continue
		}
		r.macLast = stamp
		lines = append(lines, l)
	}
	// log show --start takes whole seconds; lines from that second are filtered by the comparison above.
	return lines
}

func splitLines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// bruteFirewall applies and lifts blocks.
type bruteFirewall interface {
	block(addr string, seconds int64) error
	unblock(addr string) error
	reset() error
}

type nftBrute struct{ ready bool }

func (n *nftBrute) ensure() error {
	if n.ready {
		return nil
	}
	if exec.Command("nft", "list", "table", "inet", bruteNftTable).Run() != nil {
		rules := "table inet " + bruteNftTable + " {\n" +
			"  set blocked4 { type ipv4_addr; flags timeout; }\n" +
			"  set blocked6 { type ipv6_addr; flags timeout; }\n" +
			"  chain input { type filter hook input priority -5; policy accept;\n" +
			"    ip saddr @blocked4 drop\n    ip6 saddr @blocked6 drop\n  }\n}\n"
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(rules)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	n.ready = true
	return nil
}

func nftSet(addr string) string {
	if strings.Contains(addr, ":") {
		return "blocked6"
	}
	return "blocked4"
}

func (n *nftBrute) block(addr string, seconds int64) error {
	if err := n.ensure(); err != nil {
		return err
	}
	out, err := exec.Command("nft", "add", "element", "inet", bruteNftTable, nftSet(addr),
		fmt.Sprintf("{ %s timeout %ds }", addr, seconds)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (n *nftBrute) unblock(addr string) error {
	// The element times out by itself; deleting it early just keeps the set tidy.
	_ = exec.Command("nft", "delete", "element", "inet", bruteNftTable, nftSet(addr), "{ "+addr+" }").Run()
	return nil
}

func (n *nftBrute) reset() error {
	n.ready = false
	_ = exec.Command("nft", "delete", "table", "inet", bruteNftTable).Run()
	return nil
}

type pfBrute struct{ ready bool }

func (p *pfBrute) ensure() error {
	if p.ready {
		return nil
	}
	_ = exec.Command("pfctl", "-E").Run()
	cmd := exec.Command("pfctl", "-a", brutePFAnchor, "-f", "-")
	cmd.Stdin = strings.NewReader("table <" + brutePFTable + "> persist\nblock drop in quick from <" + brutePFTable + "> to any\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl: %v: %s", err, strings.TrimSpace(string(out)))
	}
	p.ready = true
	return nil
}

func (p *pfBrute) block(addr string, _ int64) error {
	if err := p.ensure(); err != nil {
		return err
	}
	if out, err := exec.Command("pfctl", "-a", brutePFAnchor, "-t", brutePFTable, "-T", "add", addr).CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *pfBrute) unblock(addr string) error {
	_ = exec.Command("pfctl", "-a", brutePFAnchor, "-t", brutePFTable, "-T", "delete", addr).Run()
	return nil
}

func (p *pfBrute) reset() error {
	p.ready = false
	_ = exec.Command("pfctl", "-a", brutePFAnchor, "-F", "all").Run()
	return nil
}

// bruteGuard ties the pieces together; checkBruteForce runs it from the agent loop.
type bruteGuard struct {
	tracker   *bruteTracker
	reader    *sshLogReader
	firewall  bruteFirewall
	enabled   bool
	resetDone bool
	lastPoll  time.Time
}

func (a *Agent) checkBruteForce(now time.Time) {
	if a.brute == nil {
		var fw bruteFirewall = &nftBrute{}
		if IsMacOS {
			fw = &pfBrute{}
		}
		a.brute = &bruteGuard{tracker: newBruteTracker(), reader: &sshLogReader{}, firewall: fw}
	}
	g := a.brute
	enabled := a.state.Policy.ModuleBool("firewall", "bruteForceProtection", true)
	if !enabled {
		if !g.resetDone || len(g.tracker.blocks) > 0 {
			g.tracker.clear()
			if !a.cfg.DryRunIsolation {
				_ = g.firewall.reset()
			}
			g.resetDone = true
		}
		g.enabled = false
		return
	}
	g.enabled, g.resetDone = true, false
	// The macOS unified log is slow to query, so read it once a minute.
	if IsMacOS && now.Sub(g.lastPoll) < time.Minute {
		return
	}
	g.lastPoll = now
	unix := now.Unix()
	for _, line := range g.reader.lines() {
		addr, user, ok := parseSSHFailure(line)
		if !ok {
			continue
		}
		block := g.tracker.onFailure(addr, user, unix)
		if block == nil {
			continue
		}
		var err error
		if !a.cfg.DryRunIsolation {
			err = g.firewall.block(block.Address, block.Until-unix)
		}
		action, summary := "blocked", fmt.Sprintf("Blocked %s after %d failed SSH sign-ins in 10 minutes (for %d minutes)",
			block.Address, block.Failures, (block.Until-unix)/60)
		payload := map[string]interface{}{"remoteAddress": block.Address, "failures": block.Failures, "accounts": block.Accounts,
			"blockMinutes": (block.Until - unix) / 60, "strikes": block.Strikes, "service": "ssh", "mitre": "T1110"}
		if err != nil {
			action, summary = "block failed", fmt.Sprintf("Could not block %s after %d failed SSH sign-ins: %v", block.Address, block.Failures, err)
			payload["error"] = err.Error()
		}
		payload["action"] = action
		a.emit("auth.bruteforce.blocked", "brute-force-guard", summary, payload)
	}
	for _, addr := range g.tracker.expire(unix) {
		if !a.cfg.DryRunIsolation {
			_ = g.firewall.unblock(addr)
		}
		a.emit("auth.bruteforce.unblocked", "brute-force-guard", "Lifted the brute-force block on "+addr,
			map[string]interface{}{"remoteAddress": addr})
	}
}
