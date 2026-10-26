package remote

import (
	"errors"
	"io"
	"testing"
)

type helperFakeDesktop struct {
	calls []string
	w, h  int
}

func (f *helperFakeDesktop) Size() (int, int) { return f.w, f.h }
func (f *helperFakeDesktop) Capture() ([]byte, int, int, error) {
	f.w, f.h = 3, 2
	px := make([]byte, 3*2*4)
	for i := range px {
		px[i] = byte(i)
	}
	return px, 3, 2, nil
}
func (f *helperFakeDesktop) MouseMove(x, y int) error { f.calls = append(f.calls, "move"); return nil }
func (f *helperFakeDesktop) MouseButton(b int, d bool) error {
	f.calls = append(f.calls, "button")
	return nil
}
func (f *helperFakeDesktop) Wheel(dy, dx int) error { f.calls = append(f.calls, "wheel"); return nil }
func (f *helperFakeDesktop) Key(code string, down bool) error {
	if code == "Bad" {
		return errors.New("no such key")
	}
	f.calls = append(f.calls, "key:"+code)
	return nil
}
func (f *helperFakeDesktop) Type(text string) error {
	f.calls = append(f.calls, "type:"+text)
	return nil
}
func (f *helperFakeDesktop) Close() {}

func TestDesktopHelperRoundTrip(t *testing.T) {
	toHelperR, toHelperW := io.Pipe()
	fromHelperR, fromHelperW := io.Pipe()
	fake := &helperFakeDesktop{w: 1440, h: 900}
	served := make(chan error, 1)
	go func() {
		_ = writeHelperFrame(fromHelperW, helperOK, nil)
		served <- ServeDesktop(toHelperR, fromHelperW, fake)
		fromHelperW.Close()
	}()
	closed := false
	d, err := newHelperDesktop(toHelperW, fromHelperR, func() { closed = true })
	if err != nil {
		t.Fatal(err)
	}
	if w, h := d.Size(); w != 1440 || h != 900 {
		t.Fatalf("size %dx%d", w, h)
	}
	px, w, h, err := d.Capture()
	if err != nil || w != 3 || h != 2 || len(px) != 24 || px[23] != 23 {
		t.Fatalf("capture: %v %dx%d %d", err, w, h, len(px))
	}
	_ = d.MouseMove(10, 20)
	_ = d.MouseButton(0, true)
	_ = d.Wheel(1, 0)
	_ = d.Key("KeyA", true)
	_ = d.Type("hé")
	if err := d.Key("Bad", true); err == nil || err.Error() != "no such key" {
		t.Fatalf("helper errors must come back: %v", err)
	}
	want := []string{"move", "button", "wheel", "key:KeyA", "type:hé"}
	for i, c := range want {
		if fake.calls[i] != c {
			t.Fatalf("calls %v", fake.calls)
		}
	}
	d.Close()
	if err := <-served; err != nil || !closed {
		t.Fatalf("helper should stop when the agent closes its stdin: %v %v", err, closed)
	}
}

func TestDesktopHelperOpenFailure(t *testing.T) {
	r, w := io.Pipe()
	go func() { _ = writeHelperFrame(w, helperError, []byte("allow Screen Recording")) }()
	_, sink := io.Pipe()
	if _, err := newHelperDesktop(sink, r, nil); err == nil || err.Error() != "allow Screen Recording" {
		t.Fatalf("open error must reach the agent: %v", err)
	}
}

func TestMacKeysAndModifiers(t *testing.T) {
	cases := map[string]uint16{"KeyA": 0x00, "KeyQ": 0x0C, "Digit0": 0x1D, "Enter": 0x24, "F1": 0x7A, "F12": 0x6F,
		"ArrowUp": 0x7E, "MetaLeft": 0x37, "Backspace": 0x33, "Delete": 0x75}
	for code, want := range cases {
		if got, ok := MacKeyCode(code); !ok || got != want {
			t.Fatalf("%s -> %#x, want %#x", code, got, want)
		}
	}
	if _, ok := MacKeyCode("F25"); ok {
		t.Fatal("F25 does not exist")
	}
	var m macModifierState
	m.update("ShiftLeft", true)
	m.update("MetaLeft", true)
	if m.flags() != macFlagShift|macFlagCommand {
		t.Fatalf("flags %#x", m.flags())
	}
	m.update("ShiftLeft", false)
	m.update("CapsLock", true)
	m.update("CapsLock", false)
	if m.flags() != macFlagCommand|macFlagCapsLock {
		t.Fatalf("flags %#x", m.flags())
	}
	if x, y := pointsFromPixels(2880, 1800, 2); x != 1440 || y != 900 {
		t.Fatalf("retina scale: %v %v", x, y)
	}
}

func TestPackBGRA(t *testing.T) {
	// 2x1 image with 4 bytes of row padding, ARGB big-endian.
	src := []byte{255, 1, 2, 3, 255, 4, 5, 6, 0, 0, 0, 0}
	if got := packBGRA(src, 2, 1, 12, true); string(got) != string([]byte{3, 2, 1, 255, 6, 5, 4, 255}) {
		t.Fatalf("argb: %v", got)
	}
	if got := packBGRA(src, 2, 1, 12, false); string(got) != string(src[:8]) {
		t.Fatalf("bgra: %v", got)
	}
}
