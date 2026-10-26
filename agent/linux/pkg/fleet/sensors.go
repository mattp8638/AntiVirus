package fleet

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// These sensors use /proc polling so the agent works on any kernel without
// eBPF or root-only tracing. The eBPF sensor in cmd/fenrir-linux-agent can
// feed the same pipeline where available.

type ProcInfo struct {
	PID        int
	PPID       int
	Exe        string
	Cmdline    string
	UID        int
	StartTicks uint64
}

func readProc(root string, pid int) (ProcInfo, error) {
	base := filepath.Join(root, strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return ProcInfo{}, err
	}
	// Fields after the parenthesised comm, which may itself contain spaces.
	text := string(stat)
	end := strings.LastIndexByte(text, ')')
	if end < 0 {
		return ProcInfo{}, fmt.Errorf("bad stat")
	}
	fields := strings.Fields(text[end+1:])
	if len(fields) < 20 {
		return ProcInfo{}, fmt.Errorf("short stat")
	}
	ppid, _ := strconv.Atoi(fields[1])
	start, _ := strconv.ParseUint(fields[19], 10, 64)
	exe, _ := os.Readlink(filepath.Join(base, "exe"))
	cmd, _ := os.ReadFile(filepath.Join(base, "cmdline"))
	info := ProcInfo{PID: pid, PPID: ppid, Exe: strings.TrimSuffix(exe, " (deleted)"), StartTicks: start,
		Cmdline: strings.TrimSpace(strings.ReplaceAll(string(cmd), "\x00", " "))}
	if st, err := os.Stat(base); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			info.UID = int(sys.Uid)
		}
	}
	return info, nil
}

func listPIDs(root string) []int {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

func userName(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return strconv.Itoa(uid)
}

// ProcessSensor reports newly started processes.
type ProcessSensor struct {
	Root  string
	known map[int]uint64
}

func NewProcessSensor(root string) *ProcessSensor {
	s := &ProcessSensor{Root: root, known: map[int]uint64{}}
	for pid, p := range processTable(root) { // baseline: don't report what was running at startup
		s.known[pid] = p.StartTicks
	}
	return s
}

func (s *ProcessSensor) Poll() []ProcInfo {
	seen := map[int]bool{}
	var started []ProcInfo
	for pid, p := range processTable(s.Root) {
		seen[pid] = true
		if ticks, ok := s.known[pid]; ok && ticks == p.StartTicks {
			continue
		}
		s.known[pid] = p.StartTicks
		if p.Exe == "" && p.Cmdline == "" { // kernel thread
			continue
		}
		started = append(started, p)
	}
	for pid := range s.known {
		if !seen[pid] {
			delete(s.known, pid)
		}
	}
	return started
}

func (s *ProcessSensor) Lookup(pid int) (ProcInfo, bool) {
	if IsMacOS {
		p, ok := processTable(s.Root)[pid]
		return p, ok
	}
	p, err := readProc(s.Root, pid)
	return p, err == nil
}

// FindByExe returns PIDs whose executable matches path.
func FindByExe(root, path string) []int {
	var out []int
	for pid, p := range processTable(root) {
		if p.Exe == path {
			out = append(out, pid)
		}
	}
	sort.Ints(out)
	return out
}

// Descendants returns all child PIDs of pid (recursively).
func Descendants(root string, pid int) []int {
	children := map[int][]int{}
	for p, info := range processTable(root) {
		children[info.PPID] = append(children[info.PPID], p)
	}
	var out []int
	stack := []int{pid}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, c := range children[cur] {
			out = append(out, c)
			stack = append(stack, c)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Network connections (/proc/net/tcp, tcp6)
// ---------------------------------------------------------------------------

type Conn struct {
	Inode      string
	RemoteIP   string
	RemotePort int
	LocalPort  int
}

func parseHexAddr(s string) (string, int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0
	}
	port, _ := strconv.ParseInt(parts[1], 16, 32)
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", int(port)
	}
	// /proc/net stores each 32-bit word in host (little-endian) order.
	for i := 0; i+4 <= len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	return net.IP(raw).String(), int(port)
}

func readConns(path string) []Conn {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Conn
	scanner := bufio.NewScanner(f)
	scanner.Scan() // header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[3] != "01" { // 01 = ESTABLISHED
			continue
		}
		_, lport := parseHexAddr(fields[1])
		rip, rport := parseHexAddr(fields[2])
		out = append(out, Conn{Inode: fields[9], RemoteIP: rip, RemotePort: rport, LocalPort: lport})
	}
	return out
}

// NetworkSensor reports new established connections with the owning process.
type NetworkSensor struct {
	Root string
	seen map[string]bool
	last time.Time // macOS: lsof is costly, so poll at most every 10 s
}

func NewNetworkSensor(root string) *NetworkSensor {
	s := &NetworkSensor{Root: root, seen: map[string]bool{}}
	s.Poll()
	return s
}

type ConnEvent struct {
	Conn
	PID int
	Exe string
}

func (s *NetworkSensor) Poll() []ConnEvent {
	if IsMacOS {
		return s.pollMac()
	}
	conns := append(readConns(filepath.Join(s.Root, "net/tcp")), readConns(filepath.Join(s.Root, "net/tcp6"))...)
	fresh := map[string]Conn{}
	current := map[string]bool{}
	for _, c := range conns {
		key := fmt.Sprintf("%s:%d:%d", c.RemoteIP, c.RemotePort, c.LocalPort)
		current[key] = true
		if !s.seen[key] && c.RemoteIP != "127.0.0.1" && c.RemoteIP != "::1" {
			fresh[c.Inode] = c
		}
	}
	s.seen = current
	if len(fresh) == 0 {
		return nil
	}
	var out []ConnEvent
	for _, pid := range listPIDs(s.Root) {
		fdDir := filepath.Join(s.Root, strconv.Itoa(pid), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if c, ok := fresh[inode]; ok {
				exe, _ := os.Readlink(filepath.Join(s.Root, strconv.Itoa(pid), "exe"))
				out = append(out, ConnEvent{Conn: c, PID: pid, Exe: exe})
				delete(fresh, inode)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Persistence and canary file monitor (mtime/hash polling)
// ---------------------------------------------------------------------------

type FileChange struct {
	Path   string
	Kind   string // created | modified | deleted
	Canary bool
}

type FileMonitor struct {
	state  map[string]string
	canary map[string]bool
	globs  []string
}

func NewFileMonitor(globs []string) *FileMonitor {
	m := &FileMonitor{state: map[string]string{}, canary: map[string]bool{}, globs: globs}
	m.state = m.snapshot()
	return m
}

func fingerprint(path string, info os.FileInfo) string {
	if info.Size() < 1<<20 {
		if data, err := os.ReadFile(path); err == nil {
			sum := sha256.Sum256(data)
			return hex.EncodeToString(sum[:8])
		}
	}
	return fmt.Sprintf("%d-%d", info.Size(), info.ModTime().UnixNano())
}

func (m *FileMonitor) snapshot() map[string]string {
	out := map[string]string{}
	add := func(path string) {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			out[path] = fingerprint(path, info)
		}
	}
	for _, pattern := range m.globs {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			if info, err := os.Stat(match); err == nil && info.IsDir() {
				entries, _ := os.ReadDir(match)
				for _, e := range entries {
					add(filepath.Join(match, e.Name()))
				}
			} else {
				add(match)
			}
		}
	}
	for path := range m.canary {
		add(path)
	}
	return out
}

// AddCanary registers a canary file (it must already exist).
func (m *FileMonitor) AddCanary(path string) {
	m.canary[path] = true
	if info, err := os.Stat(path); err == nil {
		m.state[path] = fingerprint(path, info)
	}
}

func (m *FileMonitor) Poll() []FileChange {
	next := m.snapshot()
	var changes []FileChange
	for path, fp := range next {
		if old, ok := m.state[path]; !ok {
			changes = append(changes, FileChange{Path: path, Kind: "created", Canary: m.canary[path]})
		} else if old != fp {
			changes = append(changes, FileChange{Path: path, Kind: "modified", Canary: m.canary[path]})
		}
	}
	for path := range m.state {
		if _, ok := next[path]; !ok {
			changes = append(changes, FileChange{Path: path, Kind: "deleted", Canary: m.canary[path]})
		}
	}
	m.state = next
	return changes
}

// PlantCanaries writes decoy documents into each home directory.
func PlantCanaries(homes []string) []string {
	var planted []string
	content := []byte("Fenrir ransomware canary. Do not edit or delete this file.\n")
	for _, home := range homes {
		dir := filepath.Join(home, "Documents")
		if _, err := os.Stat(dir); err != nil {
			dir = home
		}
		path := filepath.Join(dir, ".~fenrir-canary-2024-budget.docx")
		if _, err := os.Stat(path); err != nil {
			if err := os.WriteFile(path, content, 0o644); err != nil {
				continue
			}
		}
		planted = append(planted, path)
	}
	return planted
}

func homeDirs() []string {
	if IsMacOS {
		return macHomeDirs()
	}
	dirs, _ := filepath.Glob("/home/*")
	if info, err := os.Stat("/root"); err == nil && info.IsDir() {
		dirs = append(dirs, "/root")
	}
	return dirs
}

func nowISO() string { return time.Now().UTC().Format(time.RFC3339Nano) }
