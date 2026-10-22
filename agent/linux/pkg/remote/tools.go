package remote

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// ---------------------------------------------------------------------------
// Terminal (PTY)
// ---------------------------------------------------------------------------

type terminal struct {
	cmd  *exec.Cmd
	ptmx *os.File
	once sync.Once
}

func availableShells() []string {
	var out []string
	for _, shell := range []string{"/bin/bash", "/bin/zsh", "/bin/sh"} {
		if _, err := os.Stat(shell); err == nil {
			out = append(out, shell)
		}
	}
	return out
}

func (s *Session) handleTerm(t string, m Message) {
	if !s.opts.AllowTerminal {
		_ = s.send(Message{"ch": "term", "t": "error", "message": "remote terminal is turned off by policy"})
		return
	}
	switch t {
	case "open":
		if s.term != nil {
			s.term.close()
		}
		shell := m.str("shell")
		allowed := availableShells()
		if !contains(allowed, shell) {
			if len(allowed) == 0 {
				_ = s.send(Message{"ch": "term", "t": "error", "message": "no shell found"})
				return
			}
			shell = allowed[0]
		}
		cmd := exec.Command(shell, "-l")
		cmd.Env = append(os.Environ(), "TERM=xterm-256color", "FENRIR_REMOTE_SESSION="+s.opts.SessionID)
		cmd.Dir = "/root"
		if _, err := os.Stat(cmd.Dir); err != nil {
			cmd.Dir = "/"
		}
		size := &pty.Winsize{Cols: uint16(clamp(int(m.num("cols")), 20, 500, 120)), Rows: uint16(clamp(int(m.num("rows")), 5, 300, 32))}
		ptmx, err := pty.StartWithSize(cmd, size)
		if err != nil {
			_ = s.send(Message{"ch": "term", "t": "error", "message": err.Error()})
			return
		}
		term := &terminal{cmd: cmd, ptmx: ptmx}
		s.term = term
		_ = s.send(Message{"ch": "term", "t": "opened", "shell": shell})
		go func() {
			buf := make([]byte, 32<<10)
			for {
				n, err := ptmx.Read(buf)
				if n > 0 {
					if s.send(Message{"ch": "term", "t": "out", "data": base64.StdEncoding.EncodeToString(buf[:n])}) != nil {
						break
					}
				}
				if err != nil {
					break
				}
			}
			code := 0
			if err := cmd.Wait(); err != nil {
				var exit *exec.ExitError
				if errors.As(err, &exit) {
					code = exit.ExitCode()
				}
			}
			_ = s.send(Message{"ch": "term", "t": "exit", "code": code})
		}()
	case "in":
		if s.term == nil {
			return
		}
		if data, err := base64.StdEncoding.DecodeString(m.str("data")); err == nil {
			_, _ = s.term.ptmx.Write(data)
		}
	case "resize":
		if s.term != nil {
			_ = pty.Setsize(s.term.ptmx, &pty.Winsize{Cols: uint16(clamp(int(m.num("cols")), 20, 500, 120)),
				Rows: uint16(clamp(int(m.num("rows")), 5, 300, 32))})
		}
	case "close":
		if s.term != nil {
			s.term.close()
			s.term = nil
		}
	}
}

func (t *terminal) close() {
	t.once.Do(func() {
		if t.cmd.Process != nil {
			_ = t.cmd.Process.Signal(syscall.SIGHUP)
			go func(p *os.Process) {
				time.Sleep(2 * time.Second)
				_ = p.Kill()
			}(t.cmd.Process)
		}
		_ = t.ptmx.Close()
	})
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

type upload struct {
	file     *os.File
	path     string
	expected int64
	written  int64
	err      error
}

type fileTransfers struct {
	s       *Session
	mu      sync.Mutex
	uploads map[uint32]*upload
}

func newFileTransfers(s *Session) *fileTransfers {
	return &fileTransfers{s: s, uploads: map[uint32]*upload{}}
}

func (f *fileTransfers) handle(t string, m Message) {
	s := f.s
	req := m["req"]
	if !s.opts.AllowFileTransfer {
		s.fail("files", req, errors.New("file transfer is turned off by policy"))
		return
	}
	path := m.str("path")
	if path != "" {
		path = filepath.Clean(path)
	}
	switch t {
	case "ls":
		if path == "" {
			path = "/"
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			s.reply(req, "files", Message{"t": "ls", "path": path, "error": err.Error()})
			return
		}
		list := make([]Message, 0, len(entries))
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				continue
			}
			isDir := e.IsDir()
			if info.Mode()&os.ModeSymlink != 0 {
				if target, err := os.Stat(filepath.Join(path, e.Name())); err == nil {
					isDir = target.IsDir()
				}
			}
			list = append(list, Message{"name": e.Name(), "dir": isDir, "size": info.Size(), "mtime": info.ModTime().Unix()})
		}
		var parent interface{}
		if path != "/" {
			parent = filepath.Dir(path)
		}
		s.reply(req, "files", Message{"t": "ls", "path": path, "parent": parent, "sep": "/", "entries": list})
	case "get":
		id := uint32(m.num("id"))
		go f.download(path, id)
	case "put":
		id := uint32(m.num("id"))
		file, err := os.OpenFile(path+".fenrir-part", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		f.mu.Lock()
		f.uploads[id] = &upload{file: file, path: path, expected: int64(m.num("size")), err: err}
		f.mu.Unlock()
	case "put.end":
		id := uint32(m.num("id"))
		f.mu.Lock()
		up := f.uploads[id]
		delete(f.uploads, id)
		f.mu.Unlock()
		reply := Message{"t": "put.ok", "id": id}
		switch {
		case up == nil:
			reply["error"] = "unknown upload"
		case up.err != nil:
			reply["error"] = up.err.Error()
		default:
			_ = up.file.Close()
			if up.expected > 0 && up.written != up.expected {
				reply["error"] = fmt.Sprintf("received %d of %d bytes", up.written, up.expected)
				_ = os.Remove(up.path + ".fenrir-part")
			} else if err := os.Rename(up.path+".fenrir-part", up.path); err != nil {
				reply["error"] = err.Error()
			}
		}
		s.reply(nil, "files", reply)
	case "delete":
		if path == "" || path == "/" {
			s.fail("files", req, errors.New("refusing to delete the root"))
			return
		}
		if err := os.RemoveAll(path); err != nil {
			s.fail("files", req, err)
			return
		}
		s.reply(req, "files", Message{"t": "done"})
	case "mkdir":
		if err := os.MkdirAll(path, 0o755); err != nil {
			s.fail("files", req, err)
			return
		}
		s.reply(req, "files", Message{"t": "done"})
	}
}

func (f *fileTransfers) uploadChunk(id uint32, data []byte) {
	f.mu.Lock()
	up := f.uploads[id]
	f.mu.Unlock()
	if up == nil || up.err != nil {
		return
	}
	n, err := up.file.Write(data)
	up.written += int64(n)
	if err != nil {
		up.err = err
	}
}

func (f *fileTransfers) download(path string, id uint32) {
	s := f.s
	file, err := os.Open(path)
	if err == nil {
		var info os.FileInfo
		if info, err = file.Stat(); err == nil && info.IsDir() {
			err = errors.New("folders cannot be downloaded; open it instead")
		}
		if err == nil {
			_ = s.send(Message{"ch": "files", "t": "get.start", "id": id, "size": info.Size()})
		}
	}
	if err != nil {
		s.reply(nil, "files", Message{"t": "get.end", "id": id, "error": err.Error()})
		return
	}
	defer file.Close()
	buf := make([]byte, 5+60*1024)
	buf[0] = 0x02
	binary.BigEndian.PutUint32(buf[1:5], id)
	for {
		n, err := file.Read(buf[5:])
		if n > 0 {
			if s.sendBinary(append([]byte(nil), buf[:5+n]...)) != nil {
				return
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			s.reply(nil, "files", Message{"t": "get.end", "id": id, "error": err.Error()})
			return
		}
	}
	s.reply(nil, "files", Message{"t": "get.end", "id": id})
}

func (f *fileTransfers) closeAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, up := range f.uploads {
		if up.file != nil {
			_ = up.file.Close()
			_ = os.Remove(up.path + ".fenrir-part")
		}
		delete(f.uploads, id)
	}
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

type procSampler struct {
	mu       sync.Mutex
	lastAt   time.Time
	lastTick map[int]uint64
}

var clockTicks = 100.0

func (s *Session) handleProcs(t string, m Message) {
	req := m["req"]
	switch t {
	case "list":
		s.reply(req, "procs", Message{"t": "list", "items": s.procs.list()})
	case "kill":
		pid := int(m.num("pid"))
		if pid <= 1 || pid == os.Getpid() {
			s.fail("procs", req, errors.New("that process cannot be ended"))
			return
		}
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			s.fail("procs", req, err)
			return
		}
		go func() {
			time.Sleep(3 * time.Second)
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}()
		s.reply(req, "procs", Message{"t": "done"})
	}
}

func (p *procSampler) list() []Message {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(p.lastAt).Seconds()
	ticks := map[int]uint64{}
	users := map[string]string{}
	var items []Message
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		text := string(stat)
		open, close := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
		if open < 0 || close < open {
			continue
		}
		name := text[open+1 : close]
		fields := strings.Fields(text[close+2:])
		if len(fields) < 22 {
			continue
		}
		utime, _ := strconv.ParseUint(fields[11], 10, 64)
		stime, _ := strconv.ParseUint(fields[12], 10, 64)
		rss, _ := strconv.ParseInt(fields[21], 10, 64)
		total := utime + stime
		ticks[pid] = total
		cpu := 0.0
		if prev, ok := p.lastTick[pid]; ok && elapsed > 0 && total >= prev {
			cpu = float64(total-prev) / clockTicks / elapsed * 100
		}
		uid := ""
		if st, err := os.Stat(filepath.Join("/proc", e.Name())); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				uid = strconv.Itoa(int(sys.Uid))
			}
		}
		username, ok := users[uid]
		if !ok {
			username = uid
			if u, err := user.LookupId(uid); err == nil {
				username = u.Username
			}
			users[uid] = username
		}
		exe, _ := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		items = append(items, Message{"pid": pid, "name": name, "user": username, "cpu": cpu,
			"memMb": float64(rss*int64(os.Getpagesize())) / (1 << 20), "path": exe})
	}
	p.lastTick, p.lastAt = ticks, now
	return items
}

// ---------------------------------------------------------------------------
// Services (systemd)
// ---------------------------------------------------------------------------

var serviceName = regexp.MustCompile(`^[A-Za-z0-9@._:\\-]+$`)

func (s *Session) handleServices(t string, m Message) {
	req := m["req"]
	switch t {
	case "list":
		items, err := listServices()
		if err != nil {
			s.fail("svc", req, err)
			return
		}
		s.reply(req, "svc", Message{"t": "list", "items": items})
	case "control":
		name, action := m.str("name"), m.str("action")
		if !serviceName.MatchString(name) || strings.HasPrefix(name, "-") {
			s.fail("svc", req, errors.New("invalid service name"))
			return
		}
		if action != "start" && action != "stop" && action != "restart" {
			s.fail("svc", req, errors.New("action must be start, stop or restart"))
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "systemctl", action, "--", name).CombinedOutput(); err != nil {
			s.fail("svc", req, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out))))
			return
		}
		s.reply(req, "svc", Message{"t": "done"})
	}
}

func listServices() ([]Message, error) {
	out, err := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager").Output()
	if err != nil {
		return nil, errors.New("systemd is not available on this device")
	}
	startTypes := map[string]string{}
	if files, err := exec.Command("systemctl", "list-unit-files", "--type=service", "--no-legend", "--plain", "--no-pager").Output(); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(files)))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 {
				startTypes[fields[0]] = fields[1]
			}
		}
	}
	var items []Message
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		unit, active, sub := fields[0], fields[2], fields[3]
		status := sub
		if active == "active" && sub == "running" {
			status = "running"
		} else if active == "failed" {
			status = "failed"
		} else if active == "inactive" {
			status = "stopped"
		}
		items = append(items, Message{"name": unit, "display": strings.Join(fields[4:], " "), "status": status,
			"startType": startTypes[unit]})
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["name"].(string) < items[j]["name"].(string) })
	return items, nil
}

// ---------------------------------------------------------------------------
// Consent, lock, users
// ---------------------------------------------------------------------------

// needsConsent: "always" prompts; "when_user_present" prompts only when someone is signed in at the console.
func needsConsent(opts Options) bool {
	switch opts.Consent {
	case "never", "":
		return false
	case "always":
		return true
	default:
		return consoleUser() != ""
	}
}

// askConsent shows a yes/no prompt on the desktop with zenity or kdialog when available.
func askConsent(opts Options) bool {
	timeout := opts.ConsentTimeout
	if timeout <= 0 {
		timeout = 30
	}
	display, xauth := findDisplay()
	text := fmt.Sprintf("%s from your IT provider wants to connect to this computer.\n\nAllow remote access?", firstNonEmpty(opts.Technician, "A technician"))
	var cmd *exec.Cmd
	if path, err := exec.LookPath("zenity"); err == nil {
		cmd = exec.Command(path, "--question", "--title=Remote support request", "--text="+text, fmt.Sprintf("--timeout=%d", timeout))
	} else if path, err := exec.LookPath("kdialog"); err == nil {
		cmd = exec.Command(path, "--title", "Remote support request", "--yesno", text)
	}
	if cmd == nil || display == "" {
		// Nobody can be asked. Fall back to the policy's timeout action.
		return opts.OnConsentTimeout == "allow"
	}
	cmd.Env = append(os.Environ(), "DISPLAY="+display, "XAUTHORITY="+xauth)
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return opts.OnConsentTimeout == "allow"
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			return true
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 5 { // zenity timeout
			return opts.OnConsentTimeout == "allow"
		}
		return false
	case <-time.After(time.Duration(timeout+5) * time.Second):
		_ = cmd.Process.Kill()
		return opts.OnConsentTimeout == "allow"
	}
}

func lockSessions() error {
	return exec.Command("loginctl", "lock-sessions").Run()
}

// consoleUser is the user signed in at the graphical console, if any.
func consoleUser() string {
	out, err := exec.Command("loginctl", "list-sessions", "--no-legend").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				detail, _ := exec.Command("loginctl", "show-session", fields[0], "-p", "Type", "-p", "Active").Output()
				text := string(detail)
				if strings.Contains(text, "Active=yes") && (strings.Contains(text, "Type=x11") || strings.Contains(text, "Type=wayland")) {
					return fields[2]
				}
			}
		}
	}
	return ""
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

func clamp(v, lo, hi, def int) int {
	if v == 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
