// Package remote implements the agent side of Fenrir remote access: it dials
// the cloud relay and serves the desktop, terminal, file, process and service
// channels described in docs/REMOTE_PROTOCOL.md.
package remote

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Options come from the remote.session.start command payload.
type Options struct {
	SessionID          string `json:"sessionId"`
	RelayURL           string `json:"relayUrl"`
	Token              string `json:"token"`
	Mode               string `json:"mode"`
	ViewOnly           bool   `json:"viewOnly"`
	Technician         string `json:"technician"`
	Consent            string `json:"consent"`
	ConsentTimeout     int    `json:"consentTimeoutSeconds"`
	OnConsentTimeout   string `json:"onConsentTimeout"`
	AllowTerminal      bool   `json:"allowTerminal"`
	AllowFileTransfer  bool   `json:"allowFileTransfer"`
	ShowBanner         bool   `json:"showBanner"`
	MaxFps             int    `json:"maxFps"`
	Quality            int    `json:"quality"`
	IdleTimeoutMinutes int    `json:"idleTimeoutMinutes"`
}

// Message is a JSON control frame.
type Message map[string]interface{}

func (m Message) str(key string) string {
	v, _ := m[key].(string)
	return v
}

func (m Message) num(key string) float64 {
	v, _ := m[key].(float64)
	return v
}

// Desktop is a captured, controllable screen. The X11 implementation lives in desktop_x11.go.
type Desktop interface {
	Size() (int, int)
	// Capture returns the screen as tightly packed BGRA rows.
	Capture() ([]byte, int, int, error)
	MouseMove(x, y int) error
	MouseButton(button int, down bool) error
	Wheel(dy, dx int) error
	Key(code string, down bool) error
	Type(text string) error
	Close()
}

// MonitorDesktop is a Desktop with several displays the viewer can switch between (macOS).
type MonitorDesktop interface {
	Monitors() []Message
	SelectMonitor(index int) error
}

// DesktopOpener finds the console display. Replaced in tests.
var DesktopOpener = OpenX11Desktop

// Session is one live connection to the relay.
type Session struct {
	opts       Options
	conn       *websocket.Conn
	writeMu    sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	lastInput  time.Time
	inputMu    sync.Mutex
	screen     *screenStreamer
	desktop    Desktop
	desktopErr error
	term       *terminal
	files      *fileTransfers
	procs      *procSampler
	logf       func(string, ...interface{})
}

// Dial connects to the relay. The token rides in the query string because browsers cannot set WebSocket headers either.
func Dial(ctx context.Context, opts Options) (*Session, error) {
	if opts.RelayURL == "" || opts.Token == "" {
		return nil, errors.New("relayUrl and token are required")
	}
	u, err := url.Parse(opts.RelayURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("token", opts.Token)
	u.RawQuery = q.Encode()
	dialer := websocket.Dialer{HandshakeTimeout: 20 * time.Second, Proxy: http.ProxyFromEnvironment,
		ReadBufferSize: 64 << 10, WriteBufferSize: 256 << 10}
	conn, resp, err := dialer.DialContext(ctx, u.String(), http.Header{"X-Fenrir-Session-Token": {opts.Token}})
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("relay refused the connection (%s): %w", resp.Status, err)
		}
		return nil, err
	}
	conn.SetReadLimit(16 << 20)
	sctx, cancel := context.WithCancel(ctx)
	if opts.MaxFps <= 0 {
		opts.MaxFps = 15
	}
	if opts.Quality <= 0 {
		opts.Quality = 70
	}
	s := &Session{opts: opts, conn: conn, ctx: sctx, cancel: cancel, lastInput: time.Now(), logf: log.Printf}
	s.files = newFileTransfers(s)
	s.procs = &procSampler{}
	return s, nil
}

func (s *Session) send(m Message) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return s.conn.WriteMessage(websocket.TextMessage, data)
}

func (s *Session) sendBinary(data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return s.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (s *Session) reply(req interface{}, ch string, m Message) {
	m["ch"] = ch
	if req != nil {
		m["req"] = req
	}
	_ = s.send(m)
}

func (s *Session) fail(ch string, req interface{}, err error) {
	s.reply(req, ch, Message{"t": "done", "error": err.Error()})
}

// Close ends the session.
func (s *Session) Close(reason string) {
	select {
	case <-s.ctx.Done():
		return
	default:
	}
	_ = s.send(Message{"ch": "sys", "t": "end", "reason": reason})
	s.cancel()
	s.writeMu.Lock()
	_ = s.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason), time.Now().Add(time.Second))
	s.writeMu.Unlock()
	_ = s.conn.Close()
}

func (s *Session) capabilities() []string {
	caps := []string{"processes", "services"}
	if s.opts.AllowTerminal {
		caps = append(caps, "terminal")
	}
	if s.opts.AllowFileTransfer {
		caps = append(caps, "files")
	}
	if s.desktop != nil {
		caps = append([]string{"desktop"}, caps...)
	}
	return caps
}

func (s *Session) info() Message {
	host, _ := os.Hostname()
	home := "/"
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		home = u.HomeDir
	}
	m := Message{"ch": "sys", "t": "info", "hostname": host, "os": runtime.GOOS + " " + osRelease(), "user": consoleUser(),
		"home": home, "capabilities": s.capabilities(), "shells": availableShells(), "quality": s.opts.Quality, "maxFps": s.opts.MaxFps}
	if md, ok := s.desktop.(MonitorDesktop); ok && len(md.Monitors()) > 0 {
		m["monitors"] = md.Monitors()
	} else if s.desktop != nil {
		w, h := s.desktop.Size()
		m["monitors"] = []Message{{"index": 0, "x": 0, "y": 0, "w": w, "h": h, "primary": true}}
	} else if s.desktopErr != nil {
		m["desktopUnavailable"] = s.desktopErr.Error()
	}
	return m
}

// Serve runs the session until either side ends it. It always closes the connection.
func (s *Session) Serve() error {
	defer s.cleanup()
	if s.opts.Mode == "desktop" || s.opts.Mode == "" {
		s.desktop, s.desktopErr = DesktopOpener()
		if s.desktopErr != nil {
			s.logf("remote: desktop unavailable: %v", s.desktopErr)
		} else if needsConsent(s.opts) {
			_ = s.send(Message{"ch": "sys", "t": "consent", "state": "pending"})
			if !askConsent(s.opts) {
				_ = s.send(Message{"ch": "sys", "t": "consent", "state": "denied"})
				s.Close("the user declined the connection")
				return errors.New("consent denied")
			}
			_ = s.send(Message{"ch": "sys", "t": "consent", "state": "granted"})
		}
	}
	_ = s.send(s.info())
	go s.idleWatch()
	for {
		kind, data, err := s.conn.ReadMessage()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil
			default:
			}
			return err
		}
		if kind == websocket.BinaryMessage {
			if len(data) > 5 && data[0] == 0x03 {
				s.files.uploadChunk(binary.BigEndian.Uint32(data[1:5]), data[5:])
			}
			continue
		}
		var m Message
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		if done := s.dispatch(m); done {
			return nil
		}
	}
}

func (s *Session) touch() {
	s.inputMu.Lock()
	s.lastInput = time.Now()
	s.inputMu.Unlock()
}

func (s *Session) idleWatch() {
	limit := time.Duration(s.opts.IdleTimeoutMinutes) * time.Minute
	if limit <= 0 {
		limit = 30 * time.Minute
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.inputMu.Lock()
			idle := time.Since(s.lastInput)
			s.inputMu.Unlock()
			if idle > limit {
				s.Close("idle timeout")
				return
			}
		}
	}
}

func (s *Session) dispatch(m Message) bool {
	ch, t := m.str("ch"), m.str("t")
	if ch != "screen" || t != "ack" {
		s.touch()
	}
	switch ch {
	case "sys":
		switch t {
		case "ping":
			_ = s.send(Message{"ch": "sys", "t": "pong", "ts": m["ts"]})
		case "viewer.joined":
			_ = s.send(s.info())
		case "end":
			s.Close("ended by technician")
			return true
		}
	case "screen":
		s.handleScreen(t, m)
	case "input":
		s.handleInput(t, m)
	case "term":
		s.handleTerm(t, m)
	case "files":
		s.files.handle(t, m)
	case "procs":
		s.handleProcs(t, m)
	case "svc":
		s.handleServices(t, m)
	case "chat":
		_ = s.send(Message{"ch": "sys", "t": "error", "message": "chat is not available on this device"})
	}
	return false
}

func (s *Session) handleScreen(t string, m Message) {
	if s.desktop == nil {
		if t == "start" {
			msg := "no graphical desktop on this device"
			if s.desktopErr != nil {
				msg = s.desktopErr.Error()
			}
			_ = s.send(Message{"ch": "sys", "t": "error", "message": msg})
		}
		return
	}
	switch t {
	case "start":
		if md, ok := s.desktop.(MonitorDesktop); ok {
			if idx, present := m["monitor"].(float64); present && idx >= 0 {
				if err := md.SelectMonitor(int(idx)); err != nil {
					_ = s.send(Message{"ch": "sys", "t": "error", "message": err.Error()})
				}
			}
		}
		if s.screen == nil {
			s.screen = newScreenStreamer(s, s.desktop)
			go s.screen.run()
		}
		s.screen.configure(int(m.num("quality")), int(m.num("fps")))
		s.screen.refresh()
	case "settings":
		if s.screen != nil {
			s.screen.configure(int(m.num("quality")), int(m.num("fps")))
			s.screen.refresh()
		}
	case "refresh":
		if s.screen != nil {
			s.screen.refresh()
		}
	case "ack":
		if s.screen != nil {
			s.screen.ack()
		}
	case "stop":
		if s.screen != nil {
			s.screen.stop()
			s.screen = nil
		}
	}
}

func (s *Session) handleInput(t string, m Message) {
	if s.desktop == nil || s.opts.ViewOnly {
		return
	}
	var err error
	switch t {
	case "mm":
		err = s.desktop.MouseMove(int(m.num("x")), int(m.num("y")))
	case "md", "mu":
		if err = s.desktop.MouseMove(int(m.num("x")), int(m.num("y"))); err == nil {
			err = s.desktop.MouseButton(int(m.num("b")), t == "md")
		}
	case "wh":
		err = s.desktop.Wheel(int(m.num("dy")), int(m.num("dx")))
	case "kd", "ku":
		err = s.desktop.Key(m.str("code"), t == "kd")
	case "type":
		err = s.desktop.Type(m.str("text"))
	case "lock":
		err = lockSessions()
	case "cad":
		_ = s.send(Message{"ch": "sys", "t": "error", "message": "Ctrl+Alt+Del is a Windows-only action"})
	}
	if err != nil {
		s.logf("remote input %s: %v", t, err)
	}
}

func (s *Session) cleanup() {
	s.cancel()
	if s.screen != nil {
		s.screen.stop()
	}
	if s.term != nil {
		s.term.close()
	}
	s.files.closeAll()
	if s.desktop != nil {
		s.desktop.Close()
	}
	_ = s.conn.Close()
}

// ---------------------------------------------------------------------------
// Manager: one goroutine per session, ended by remote.session.end or the relay.
// ---------------------------------------------------------------------------

type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	Logf     func(string, ...interface{})
	// OnEvent lets the agent emit telemetry (session started/ended).
	OnEvent func(eventType, summary string, payload map[string]interface{})
}

func NewManager() *Manager {
	return &Manager{sessions: map[string]*Session{}, Logf: log.Printf}
}

// Start dials the relay and serves the session in the background.
func (mgr *Manager) Start(opts Options) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := Dial(ctx, opts)
	if err != nil {
		return err
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.logf = mgr.Logf
	mgr.mu.Lock()
	if old := mgr.sessions[opts.SessionID]; old != nil {
		old.Close("replaced")
	}
	mgr.sessions[opts.SessionID] = s
	mgr.mu.Unlock()
	if mgr.OnEvent != nil {
		mgr.OnEvent("remote.session.started", "Remote "+opts.Mode+" session started by "+opts.Technician,
			map[string]interface{}{"sessionId": opts.SessionID, "technician": opts.Technician, "mode": opts.Mode})
	}
	go func() {
		err := s.Serve()
		mgr.mu.Lock()
		if mgr.sessions[opts.SessionID] == s {
			delete(mgr.sessions, opts.SessionID)
		}
		mgr.mu.Unlock()
		if mgr.OnEvent != nil {
			payload := map[string]interface{}{"sessionId": opts.SessionID, "technician": opts.Technician}
			if err != nil {
				payload["error"] = err.Error()
			}
			mgr.OnEvent("remote.session.ended", "Remote session ended", payload)
		}
	}()
	return nil
}

func (mgr *Manager) End(sessionID string) bool {
	mgr.mu.Lock()
	s := mgr.sessions[sessionID]
	mgr.mu.Unlock()
	if s == nil {
		return false
	}
	s.Close("ended from the console")
	return true
}

func (mgr *Manager) Active() int {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	return len(mgr.sessions)
}

func osRelease() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return ""
}
