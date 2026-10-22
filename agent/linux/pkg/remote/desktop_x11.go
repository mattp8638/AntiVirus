package remote

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
	"github.com/jezek/xgb/xtest"
)

// x11Desktop captures the root window and injects input through the XTEST extension.
// Wayland sessions are not supported: they deliberately block both.
type x11Desktop struct {
	mu        sync.Mutex
	conn      *xgb.Conn
	root      xproto.Window
	width     int
	height    int
	depth     byte
	keycodes  map[xproto.Keysym]xproto.Keycode
	shifted   map[xproto.Keysym]xproto.Keycode
	shiftCode xproto.Keycode
}

// OpenX11Desktop finds the active X display (FENRIR_DISPLAY, $DISPLAY, or the console user's) and connects to it.
func OpenX11Desktop() (Desktop, error) {
	display, xauth := findDisplay()
	if display == "" {
		if os.Getenv("WAYLAND_DISPLAY") != "" || waylandSessionActive() {
			return nil, errors.New("the signed-in desktop uses Wayland, which does not allow remote control; terminal and files still work")
		}
		return nil, errors.New("no graphical desktop is running on this device; terminal and files still work")
	}
	if xauth != "" {
		_ = os.Setenv("XAUTHORITY", xauth)
	}
	conn, err := xgb.NewConnDisplay(display)
	if err != nil {
		return nil, fmt.Errorf("cannot open display %s: %w", display, err)
	}
	if err := xtest.Init(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("the X server has no XTEST extension: %w", err)
	}
	setup := xproto.Setup(conn)
	screen := setup.DefaultScreen(conn)
	d := &x11Desktop{conn: conn, root: screen.Root, width: int(screen.WidthInPixels), height: int(screen.HeightInPixels),
		depth: screen.RootDepth}
	if err := d.loadKeyboard(setup); err != nil {
		conn.Close()
		return nil, err
	}
	return d, nil
}

func (d *x11Desktop) Size() (int, int) { return d.width, d.height }

func (d *x11Desktop) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.conn.Close()
}

// Capture grabs the root window in horizontal strips (keeps each reply well under the X11 size limit).
func (d *x11Desktop) Capture() ([]byte, int, int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	geom, err := xproto.GetGeometry(d.conn, xproto.Drawable(d.root)).Reply()
	if err == nil {
		d.width, d.height = int(geom.Width), int(geom.Height)
	}
	w, h := d.width, d.height
	out := make([]byte, 0, w*h*4)
	strip := maxInt(1, (4<<20)/(w*4))
	for y := 0; y < h; y += strip {
		rows := minInt(strip, h-y)
		reply, err := xproto.GetImage(d.conn, xproto.ImageFormatZPixmap, xproto.Drawable(d.root), 0, int16(y), uint16(w), uint16(rows),
			0xffffffff).Reply()
		if err != nil {
			return nil, 0, 0, err
		}
		if len(reply.Data) < w*rows*4 {
			return nil, 0, 0, fmt.Errorf("unsupported X visual (depth %d, %d bytes for %dx%d)", reply.Depth, len(reply.Data), w, rows)
		}
		out = append(out, reply.Data[:w*rows*4]...)
	}
	return out, w, h, nil
}

func (d *x11Desktop) fake(kind byte, detail byte, x, y int16) error {
	return xtest.FakeInputChecked(d.conn, kind, detail, 0, d.root, x, y, 0).Check()
}

func (d *x11Desktop) MouseMove(x, y int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.fake(xproto.MotionNotify, 0, int16(x), int16(y))
}

func (d *x11Desktop) MouseButton(button int, down bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	xbutton := map[int]byte{0: 1, 1: 2, 2: 3}[button]
	if xbutton == 0 {
		return nil
	}
	kind := byte(xproto.ButtonRelease)
	if down {
		kind = xproto.ButtonPress
	}
	return d.fake(kind, xbutton, 0, 0)
}

func (d *x11Desktop) Wheel(dy, dx int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	click := func(b byte) error {
		if err := d.fake(xproto.ButtonPress, b, 0, 0); err != nil {
			return err
		}
		return d.fake(xproto.ButtonRelease, b, 0, 0)
	}
	switch {
	case dy < 0:
		return click(4)
	case dy > 0:
		return click(5)
	case dx < 0:
		return click(6)
	case dx > 0:
		return click(7)
	}
	return nil
}

func (d *x11Desktop) Key(code string, down bool) error {
	sym, ok := KeysymForCode(code)
	if !ok {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	keycode, ok := d.keycodes[sym]
	if !ok {
		if keycode, ok = d.shifted[sym]; !ok {
			return nil
		}
	}
	kind := byte(xproto.KeyRelease)
	if down {
		kind = xproto.KeyPress
	}
	return d.fake(kind, byte(keycode), 0, 0)
}

// Type sends text as key presses, holding Shift for characters on the shifted level.
func (d *x11Desktop) Type(text string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range text {
		if r == '\n' {
			r = '\r'
		}
		sym := runeKeysym(r)
		keycode, plain := d.keycodes[sym]
		shift := false
		if !plain {
			if keycode, shift = d.shifted[sym]; !shift {
				continue
			}
		}
		if shift {
			_ = d.fake(xproto.KeyPress, byte(d.shiftCode), 0, 0)
		}
		_ = d.fake(xproto.KeyPress, byte(keycode), 0, 0)
		_ = d.fake(xproto.KeyRelease, byte(keycode), 0, 0)
		if shift {
			_ = d.fake(xproto.KeyRelease, byte(d.shiftCode), 0, 0)
		}
	}
	return nil
}

func (d *x11Desktop) loadKeyboard(setup *xproto.SetupInfo) error {
	first, count := setup.MinKeycode, byte(int(setup.MaxKeycode)-int(setup.MinKeycode)+1)
	mapping, err := xproto.GetKeyboardMapping(d.conn, first, count).Reply()
	if err != nil {
		return fmt.Errorf("cannot read the keyboard map: %w", err)
	}
	per := int(mapping.KeysymsPerKeycode)
	d.keycodes, d.shifted = map[xproto.Keysym]xproto.Keycode{}, map[xproto.Keysym]xproto.Keycode{}
	for i := 0; i < int(count); i++ {
		code := xproto.Keycode(int(first) + i)
		for level := 0; level < per && level < 2; level++ {
			sym := mapping.Keysyms[i*per+level]
			if sym == 0 {
				continue
			}
			target := d.keycodes
			if level == 1 {
				target = d.shifted
			}
			if _, seen := target[sym]; !seen {
				target[sym] = code
			}
		}
	}
	d.shiftCode = d.keycodes[0xffe1]
	return nil
}

func runeKeysym(r rune) xproto.Keysym {
	switch {
	case r == '\r':
		return 0xff0d
	case r == '\t':
		return 0xff09
	case r == '\b':
		return 0xff08
	case r >= 0x20 && r <= 0x7e, r >= 0xa0 && r <= 0xff:
		return xproto.Keysym(r)
	}
	return xproto.Keysym(0x01000000 | uint32(r))
}

// KeysymForCode maps a browser KeyboardEvent.code (a physical key) to its unshifted X keysym.
func KeysymForCode(code string) (xproto.Keysym, bool) {
	if strings.HasPrefix(code, "Key") && len(code) == 4 {
		return xproto.Keysym(strings.ToLower(code[3:])[0]), true
	}
	if strings.HasPrefix(code, "Digit") && len(code) == 6 {
		return xproto.Keysym(code[5]), true
	}
	if strings.HasPrefix(code, "F") {
		if n, err := strconv.Atoi(code[1:]); err == nil && n >= 1 && n <= 24 {
			return xproto.Keysym(0xffbe + n - 1), true
		}
	}
	if strings.HasPrefix(code, "Numpad") && len(code) == 7 && code[6] >= '0' && code[6] <= '9' {
		return xproto.Keysym(0xffb0 + int(code[6]-'0')), true
	}
	sym, ok := namedKeysyms[code]
	return sym, ok
}

var namedKeysyms = map[string]xproto.Keysym{
	"Enter": 0xff0d, "Escape": 0xff1b, "Backspace": 0xff08, "Tab": 0xff09, "Space": 0x20,
	"ArrowLeft": 0xff51, "ArrowUp": 0xff52, "ArrowRight": 0xff53, "ArrowDown": 0xff54,
	"Home": 0xff50, "End": 0xff57, "PageUp": 0xff55, "PageDown": 0xff56, "Insert": 0xff63, "Delete": 0xffff,
	"ShiftLeft": 0xffe1, "ShiftRight": 0xffe2, "ControlLeft": 0xffe3, "ControlRight": 0xffe4,
	"AltLeft": 0xffe9, "AltRight": 0xfe03, "MetaLeft": 0xffeb, "MetaRight": 0xffec, "CapsLock": 0xffe5,
	"Minus": 0x2d, "Equal": 0x3d, "BracketLeft": 0x5b, "BracketRight": 0x5d, "Backslash": 0x5c, "Semicolon": 0x3b,
	"Quote": 0x27, "Backquote": 0x60, "Comma": 0x2c, "Period": 0x2e, "Slash": 0x2f, "IntlBackslash": 0x3c,
	"NumpadEnter": 0xff8d, "NumpadAdd": 0xffab, "NumpadSubtract": 0xffad, "NumpadMultiply": 0xffaa, "NumpadDivide": 0xffaf,
	"NumpadDecimal": 0xffae, "NumLock": 0xff7f, "PrintScreen": 0xff61, "ScrollLock": 0xff14, "Pause": 0xff13, "ContextMenu": 0xff67,
}

// findDisplay returns the X display and Xauthority file of the active graphical session.
func findDisplay() (string, string) {
	if d := os.Getenv("FENRIR_DISPLAY"); d != "" {
		return d, os.Getenv("FENRIR_XAUTHORITY")
	}
	// A desktop process tells us both the display and its cookie file.
	entries, _ := os.ReadDir("/proc")
	type candidate struct{ display, xauth string }
	var found []candidate
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", e.Name(), "environ"))
		if err != nil || !bytes.Contains(data, []byte("DISPLAY=")) {
			continue
		}
		var c candidate
		for _, kv := range bytes.Split(data, []byte{0}) {
			switch {
			case bytes.HasPrefix(kv, []byte("DISPLAY=")):
				c.display = string(kv[len("DISPLAY="):])
			case bytes.HasPrefix(kv, []byte("XAUTHORITY=")):
				c.xauth = string(kv[len("XAUTHORITY="):])
			}
		}
		if strings.HasPrefix(c.display, ":") {
			found = append(found, c)
		}
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].xauth != "" && found[j].xauth == "" })
	if len(found) > 0 {
		return found[0].display, found[0].xauth
	}
	if d := os.Getenv("DISPLAY"); d != "" {
		return d, os.Getenv("XAUTHORITY")
	}
	if sockets, _ := filepath.Glob("/tmp/.X11-unix/X*"); len(sockets) > 0 {
		sort.Strings(sockets)
		return ":" + strings.TrimPrefix(filepath.Base(sockets[0]), "X"), ""
	}
	return "", ""
}

func waylandSessionActive() bool {
	matches, _ := filepath.Glob("/run/user/*/wayland-*")
	return len(matches) > 0
}
