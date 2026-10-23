package remote

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jezek/xgb/xproto"
)

// fakeDesktop is a 300x200 screen whose pixels change when the mouse moves.
type fakeDesktop struct {
	moves  [][2]int
	keys   []string
	pixels []byte
}

func newFakeDesktop() *fakeDesktop {
	return &fakeDesktop{pixels: make([]byte, 300*200*4)}
}
func (f *fakeDesktop) Size() (int, int) { return 300, 200 }
func (f *fakeDesktop) Capture() ([]byte, int, int, error) {
	return append([]byte(nil), f.pixels...), 300, 200, nil
}
func (f *fakeDesktop) MouseMove(x, y int) error {
	f.moves = append(f.moves, [2]int{x, y})
	f.pixels[(y*300+x)*4] = 0xff
	return nil
}
func (f *fakeDesktop) MouseButton(int, bool) error { return nil }
func (f *fakeDesktop) Wheel(int, int) error        { return nil }
func (f *fakeDesktop) Key(code string, down bool) error {
	f.keys = append(f.keys, fmt.Sprintf("%s:%v", code, down))
	return nil
}
func (f *fakeDesktop) Type(string) error { return nil }
func (f *fakeDesktop) Close()            {}

// relay is a minimal stand-in for the cloud relay: the test plays the viewer.
type relay struct {
	server *httptest.Server
	agent  chan *websocket.Conn
}

func newRelay(t *testing.T) *relay {
	r := &relay{agent: make(chan *websocket.Conn, 1)}
	upgrader := websocket.Upgrader{}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("token") != "tok" {
			http.Error(w, "bad token", 401)
			return
		}
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			t.Error(err)
			return
		}
		r.agent <- conn
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *relay) url() string { return "ws" + strings.TrimPrefix(r.server.URL, "http") + "/ws/remote/rs_1/agent" }

func readJSON(t *testing.T, conn *websocket.Conn, want func(Message) bool) Message {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(deadline)
		kind, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if kind != websocket.TextMessage {
			continue
		}
		var m Message
		if json.Unmarshal(data, &m) == nil && want(m) {
			return m
		}
	}
	t.Fatal("timed out waiting for message")
	return nil
}

func startSession(t *testing.T, opts Options) (*websocket.Conn, *fakeDesktop) {
	t.Helper()
	desk := newFakeDesktop()
	DesktopOpener = func() (Desktop, error) { return desk, nil }
	t.Cleanup(func() { DesktopOpener = OpenX11Desktop })
	r := newRelay(t)
	opts.RelayURL, opts.Token = r.url(), "tok"
	mgr := NewManager()
	if err := mgr.Start(opts); err != nil {
		t.Fatal(err)
	}
	viewer := <-r.agent
	t.Cleanup(func() { viewer.Close() })
	return viewer, desk
}

func send(t *testing.T, conn *websocket.Conn, m Message) {
	t.Helper()
	if err := conn.WriteJSON(m); err != nil {
		t.Fatal(err)
	}
}

func TestBadTokenIsRejected(t *testing.T) {
	r := newRelay(t)
	if _, err := Dial(context.Background(), Options{RelayURL: r.url(), Token: "nope"}); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401, got %v", err)
	}
}

func TestScreenTilesAckAndInput(t *testing.T) {
	conn, desk := startSession(t, Options{SessionID: "rs_1", Mode: "desktop", Consent: "never", AllowTerminal: true, AllowFileTransfer: true})
	info := readJSON(t, conn, func(m Message) bool { return m.str("t") == "info" })
	if caps := fmt.Sprint(info["capabilities"]); !strings.Contains(caps, "desktop") || !strings.Contains(caps, "terminal") {
		t.Fatalf("capabilities: %v", caps)
	}
	send(t, conn, Message{"ch": "screen", "t": "start", "quality": 60, "fps": 30})
	tiles := 0
	for {
		kind, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if kind == websocket.BinaryMessage {
			if data[0] != 0x01 || binary.BigEndian.Uint16(data[9:]) != 300 || binary.BigEndian.Uint16(data[11:]) != 200 {
				t.Fatalf("bad tile header % x", data[:13])
			}
			if _, err := jpeg.Decode(bytes.NewReader(data[13:])); err != nil {
				t.Fatalf("tile is not a JPEG: %v", err)
			}
			tiles++
			continue
		}
		var m Message
		_ = json.Unmarshal(data, &m)
		if m.str("t") == "frame.end" {
			break
		}
	}
	if tiles != 6 { // 300x200 in 128px tiles = 3 x 2
		t.Fatalf("full frame should be 6 tiles, got %d", tiles)
	}
	send(t, conn, Message{"ch": "screen", "t": "ack", "seq": 1})
	send(t, conn, Message{"ch": "input", "t": "mm", "x": 10, "y": 150})
	send(t, conn, Message{"ch": "input", "t": "kd", "code": "KeyA"})
	// Only the tile under the changed pixel is resent.
	changed := 0
	for {
		kind, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if kind == websocket.BinaryMessage {
			if binary.BigEndian.Uint16(data[1:]) != 0 || binary.BigEndian.Uint16(data[3:]) != 128 {
				t.Fatalf("expected the tile at 0,128, got %d,%d", binary.BigEndian.Uint16(data[1:]), binary.BigEndian.Uint16(data[3:]))
			}
			changed++
			continue
		}
		var m Message
		_ = json.Unmarshal(data, &m)
		if m.str("t") == "frame.end" {
			break
		}
	}
	if changed != 1 || len(desk.moves) != 1 || desk.keys[0] != "KeyA:true" {
		t.Fatalf("changed=%d moves=%v keys=%v", changed, desk.moves, desk.keys)
	}
	send(t, conn, Message{"ch": "sys", "t": "ping", "ts": 42})
	if pong := readJSON(t, conn, func(m Message) bool { return m.str("t") == "pong" }); pong.num("ts") != 42 {
		t.Fatalf("pong %v", pong)
	}
}

func TestViewOnlyIgnoresInput(t *testing.T) {
	conn, desk := startSession(t, Options{SessionID: "rs_1", Mode: "desktop", Consent: "never", ViewOnly: true})
	readJSON(t, conn, func(m Message) bool { return m.str("t") == "info" })
	send(t, conn, Message{"ch": "input", "t": "mm", "x": 1, "y": 1})
	send(t, conn, Message{"ch": "sys", "t": "ping", "ts": 1})
	readJSON(t, conn, func(m Message) bool { return m.str("t") == "pong" })
	if len(desk.moves) != 0 {
		t.Fatal("view-only session moved the mouse")
	}
}

func TestTerminalFilesProcessesAndPolicy(t *testing.T) {
	conn, _ := startSession(t, Options{SessionID: "rs_1", Mode: "terminal", AllowTerminal: true, AllowFileTransfer: true})
	readJSON(t, conn, func(m Message) bool { return m.str("t") == "info" })

	send(t, conn, Message{"ch": "term", "t": "open", "cols": 80, "rows": 24, "shell": "/bin/sh"})
	opened := readJSON(t, conn, func(m Message) bool { return m.str("ch") == "term" && (m.str("t") == "opened" || m.str("t") == "error") })
	if opened.str("t") != "opened" {
		t.Fatalf("terminal failed to open: %v", opened)
	}
	send(t, conn, Message{"ch": "term", "t": "in", "data": base64.StdEncoding.EncodeToString([]byte("echo fenrir-$((40+2))\n"))})
	var output strings.Builder
	readJSON(t, conn, func(m Message) bool {
		if m.str("t") == "out" {
			data, _ := base64.StdEncoding.DecodeString(m.str("data"))
			output.Write(data)
		}
		return strings.Contains(output.String(), "fenrir-42")
	})
	send(t, conn, Message{"ch": "term", "t": "close"})

	dir := t.TempDir()
	content := bytes.Repeat([]byte("fenrir!"), 20000) // 140 KB: several chunks
	send(t, conn, Message{"ch": "files", "t": "put", "path": filepath.Join(dir, "up.bin"), "id": 7, "size": len(content)})
	for off := 0; off < len(content); off += 60 << 10 {
		end := off + 60<<10
		if end > len(content) {
			end = len(content)
		}
		frame := append([]byte{0x03, 0, 0, 0, 7}, content[off:end]...)
		if err := conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
			t.Fatal(err)
		}
	}
	send(t, conn, Message{"ch": "files", "t": "put.end", "id": 7})
	if ok := readJSON(t, conn, func(m Message) bool { return m.str("t") == "put.ok" }); ok["error"] != nil {
		t.Fatalf("upload failed: %v", ok["error"])
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "up.bin")); !bytes.Equal(got, content) {
		t.Fatal("uploaded file differs")
	}
	send(t, conn, Message{"ch": "files", "t": "ls", "path": dir, "req": 1})
	listing := readJSON(t, conn, func(m Message) bool { return m.str("t") == "ls" })
	if !strings.Contains(fmt.Sprint(listing["entries"]), "up.bin") || listing.str("parent") != filepath.Dir(dir) {
		t.Fatalf("listing %v", listing)
	}
	send(t, conn, Message{"ch": "files", "t": "get", "path": filepath.Join(dir, "up.bin"), "id": 9})
	var downloaded []byte
	for {
		kind, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if kind == websocket.BinaryMessage && data[0] == 0x02 && binary.BigEndian.Uint32(data[1:]) == 9 {
			downloaded = append(downloaded, data[5:]...)
			continue
		}
		var m Message
		_ = json.Unmarshal(data, &m)
		if m.str("t") == "get.end" {
			break
		}
	}
	if !bytes.Equal(downloaded, content) {
		t.Fatalf("downloaded %d bytes, want %d", len(downloaded), len(content))
	}

	send(t, conn, Message{"ch": "procs", "t": "list", "req": 2})
	procs := readJSON(t, conn, func(m Message) bool { return m.str("ch") == "procs" })
	if !strings.Contains(fmt.Sprint(procs["items"]), fmt.Sprint(os.Getpid())) {
		t.Fatal("process list does not include the test process")
	}
	send(t, conn, Message{"ch": "procs", "t": "kill", "pid": 1, "req": 3})
	if refused := readJSON(t, conn, func(m Message) bool { return m.str("ch") == "procs" && m.num("req") == 3 }); refused["error"] == nil {
		t.Fatal("killing PID 1 must be refused")
	}
	send(t, conn, Message{"ch": "sys", "t": "end"})
	readJSON(t, conn, func(m Message) bool { return m.str("t") == "end" })
}

func TestPolicyBlocksTerminalAndFiles(t *testing.T) {
	conn, _ := startSession(t, Options{SessionID: "rs_1", Mode: "terminal", AllowTerminal: false, AllowFileTransfer: false})
	info := readJSON(t, conn, func(m Message) bool { return m.str("t") == "info" })
	if caps := fmt.Sprint(info["capabilities"]); strings.Contains(caps, "terminal") || strings.Contains(caps, "files") {
		t.Fatalf("capabilities should hide terminal and files: %v", caps)
	}
	send(t, conn, Message{"ch": "term", "t": "open"})
	readJSON(t, conn, func(m Message) bool { return m.str("ch") == "term" && m.str("t") == "error" })
	send(t, conn, Message{"ch": "files", "t": "ls", "path": "/", "req": 5})
	if denied := readJSON(t, conn, func(m Message) bool { return m.str("ch") == "files" }); denied["error"] == nil {
		t.Fatal("file listing should be refused")
	}
}

func TestKeysyms(t *testing.T) {
	cases := map[string]xproto.Keysym{"KeyA": 'a', "Digit7": '7', "F5": 0xffc2, "Enter": 0xff0d, "ShiftLeft": 0xffe1, "Numpad3": 0xffb3}
	for code, want := range cases {
		if got, ok := KeysymForCode(code); !ok || got != want {
			t.Errorf("%s: got %#x", code, got)
		}
	}
	if _, ok := KeysymForCode("LaunchMail"); ok {
		t.Error("unknown keys should be ignored")
	}
}

func TestChangedTiles(t *testing.T) {
	a := make([]byte, 260*130*4)
	b := append([]byte(nil), a...)
	if len(ChangedTiles(a, b, 260, 130, false)) != 0 {
		t.Fatal("identical frames should have no changed tiles")
	}
	b[(129*260+259)*4] = 1 // bottom-right pixel
	tiles := ChangedTiles(a, b, 260, 130, false)
	if len(tiles) != 1 || tiles[0] != image.Rect(256, 128, 260, 130) {
		t.Fatalf("tiles %v", tiles)
	}
	if len(ChangedTiles(a, b, 260, 130, true)) != 6 {
		t.Fatal("a full 260x130 frame is 3 x 2 tiles")
	}
}

// TestX11Desktop runs against a real X server (Xvfb) when one is installed.
func TestX11Desktop(t *testing.T) {
	xvfb, err := exec.LookPath("Xvfb")
	if err != nil {
		t.Skip("Xvfb not installed")
	}
	display := ":97"
	cmd := exec.Command(xvfb, display, "-screen", "0", "640x480x24", "-nolisten", "tcp")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Process.Kill()
	t.Setenv("FENRIR_DISPLAY", display)
	var desk Desktop
	for i := 0; i < 50; i++ {
		if desk, err = OpenX11Desktop(); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer desk.Close()
	pixels, w, h, err := desk.Capture()
	if err != nil || w != 640 || h != 480 || len(pixels) != 640*480*4 {
		t.Fatalf("capture: %v %dx%d %d bytes", err, w, h, len(pixels))
	}
	if err := desk.MouseMove(123, 77); err != nil {
		t.Fatal(err)
	}
	x := desk.(*x11Desktop)
	pointer, err := xproto.QueryPointer(x.conn, x.root).Reply()
	if err != nil || pointer.RootX != 123 || pointer.RootY != 77 {
		t.Fatalf("pointer at %d,%d (%v)", pointer.RootX, pointer.RootY, err)
	}
	if err := desk.Key("KeyA", true); err != nil {
		t.Fatal(err)
	}
	if err := desk.Key("KeyA", false); err != nil {
		t.Fatal(err)
	}
	if err := desk.Type("Hi!"); err != nil {
		t.Fatal(err)
	}
}
