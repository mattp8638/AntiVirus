//go:build darwin

package remote

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/ebitengine/purego"
)

func init() { DesktopOpener = OpenMacDesktop }

// OpenMacDesktop gives the agent the signed-in user's screen. The agent runs as a root LaunchDaemon,
// which has no window-server connection, so it starts a copy of itself in the console user's session
// (launchctl asuser + sudo -u) and talks to it over pipes.
func OpenMacDesktop() (Desktop, error) {
	if os.Geteuid() != 0 {
		return openNativeDesktop()
	}
	info, err := os.Stat("/dev/console")
	if err != nil {
		return nil, errors.New("cannot find the console user")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid == 0 {
		return nil, errors.New("nobody is signed in at the Mac's screen (it is at the login window); terminal and files still work")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	user := strconv.Itoa(int(stat.Uid))
	if name := consoleUserName(); name != "" {
		user = name
	}
	cmd := exec.Command("/bin/launchctl", "asuser", strconv.Itoa(int(stat.Uid)), "/usr/bin/sudo", "-n", "-u", user, "-H",
		exe, HelperCommand)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start the screen helper: %w", err)
	}
	stop := func() {
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
		}
	}
	d, err := newHelperDesktop(stdin, stdout, stop)
	if err != nil {
		return nil, fmt.Errorf("screen sharing is unavailable: %w", err)
	}
	return d, nil
}

func consoleUserName() string {
	out, err := exec.Command("/usr/bin/stat", "-f", "%Su", "/dev/console").Output()
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(out))
}

type cgPoint struct{ X, Y float64 }

type cgRect struct {
	Origin cgPoint
	Width  float64
	Height float64
}

var cg struct {
	once sync.Once
	err  error

	mainDisplayID       func() uint32
	activeDisplays      func(uint32, *uint32, *uint32) int32
	displayBounds       func(uint32) cgRect
	displayPixelsWide   func(uint32) uint64
	displayCreateImage  func(uint32) uintptr
	imageGetWidth       func(uintptr) uint64
	imageGetHeight      func(uintptr) uint64
	imageGetBytesPerRow func(uintptr) uint64
	imageGetBitsPerPix  func(uintptr) uint64
	imageGetBitmapInfo  func(uintptr) uint32
	imageGetProvider    func(uintptr) uintptr
	providerCopyData    func(uintptr) uintptr
	imageRelease        func(uintptr)
	dataGetBytePtr      func(uintptr) *byte
	dataGetLength       func(uintptr) int64
	release             func(uintptr)
	preflightCapture    func() bool
	requestCapture      func() bool
	mouseEvent          func(uintptr, uint32, cgPoint, uint32) uintptr
	keyboardEvent       func(uintptr, uint16, bool) uintptr
	setUnicode          func(uintptr, uint64, *uint16)
	scrollEvent         func(uintptr, uint32, uint32, int32, int32, int32) uintptr
	setFlags            func(uintptr, uint64)
	setIntField         func(uintptr, uint32, int64)
	post                func(uint32, uintptr)
	axTrusted           func() bool
	haveCreateImage     bool
}

func loadCoreGraphics() error {
	cg.once.Do(func() {
		core, err := purego.Dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			cg.err = fmt.Errorf("CoreGraphics unavailable: %w", err)
			return
		}
		cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			cg.err = fmt.Errorf("CoreFoundation unavailable: %w", err)
			return
		}
		reg := func(fn interface{}, lib uintptr, name string) {
			purego.RegisterLibFunc(fn, lib, name)
		}
		reg(&cg.mainDisplayID, core, "CGMainDisplayID")
		reg(&cg.activeDisplays, core, "CGGetActiveDisplayList")
		reg(&cg.displayBounds, core, "CGDisplayBounds")
		reg(&cg.displayPixelsWide, core, "CGDisplayPixelsWide")
		if _, err := purego.Dlsym(core, "CGDisplayCreateImage"); err == nil {
			reg(&cg.displayCreateImage, core, "CGDisplayCreateImage")
			cg.haveCreateImage = true
		}
		reg(&cg.imageGetWidth, core, "CGImageGetWidth")
		reg(&cg.imageGetHeight, core, "CGImageGetHeight")
		reg(&cg.imageGetBytesPerRow, core, "CGImageGetBytesPerRow")
		reg(&cg.imageGetBitsPerPix, core, "CGImageGetBitsPerPixel")
		reg(&cg.imageGetBitmapInfo, core, "CGImageGetBitmapInfo")
		reg(&cg.imageGetProvider, core, "CGImageGetDataProvider")
		reg(&cg.providerCopyData, core, "CGDataProviderCopyData")
		reg(&cg.imageRelease, core, "CGImageRelease")
		reg(&cg.dataGetBytePtr, cf, "CFDataGetBytePtr")
		reg(&cg.dataGetLength, cf, "CFDataGetLength")
		reg(&cg.release, cf, "CFRelease")
		reg(&cg.preflightCapture, core, "CGPreflightScreenCaptureAccess")
		reg(&cg.requestCapture, core, "CGRequestScreenCaptureAccess")
		reg(&cg.mouseEvent, core, "CGEventCreateMouseEvent")
		reg(&cg.keyboardEvent, core, "CGEventCreateKeyboardEvent")
		reg(&cg.setUnicode, core, "CGEventKeyboardSetUnicodeString")
		reg(&cg.scrollEvent, core, "CGEventCreateScrollWheelEvent2")
		reg(&cg.setFlags, core, "CGEventSetFlags")
		reg(&cg.setIntField, core, "CGEventSetIntegerValueField")
		reg(&cg.post, core, "CGEventPost")
		if ax, err := purego.Dlopen("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices", purego.RTLD_NOW|purego.RTLD_GLOBAL); err == nil {
			reg(&cg.axTrusted, ax, "AXIsProcessTrusted")
		}
	})
	return cg.err
}

// CGEvent constants.
const (
	cgHIDEventTap          = 0
	cgEventLeftDown        = 1
	cgEventLeftUp          = 2
	cgEventRightDown       = 3
	cgEventRightUp         = 4
	cgEventMouseMoved      = 5
	cgEventLeftDragged     = 6
	cgEventRightDragged    = 7
	cgEventOtherDown       = 25
	cgEventOtherUp         = 26
	cgEventOtherDragged    = 27
	cgScrollUnitLine       = 1
	cgMouseClickStateFld   = 1
	cgBitmapByteOrderMask  = 0x7000
	cgBitmapByteOrder32Big = 0x4000
)

// cgDesktop captures the main display and posts input through CoreGraphics. It needs the Screen
// Recording and Accessibility permissions for /usr/local/bin/fenrir-agent.
type cgDesktop struct {
	mu        sync.Mutex
	display   uint32
	displays  []uint32 // main display first
	selected  int
	origin    cgPoint // top-left of the selected display in global points
	width     int
	height    int
	scale     float64 // backing pixels per point (2 on Retina)
	x, y      int
	buttons   map[int]bool
	mods      macModifierState
	lastClick time.Time
	lastBtn   int
	clicks    int64
}

func openNativeDesktop() (Desktop, error) {
	if err := loadCoreGraphics(); err != nil {
		return nil, err
	}
	if !cg.preflightCapture() {
		cg.requestCapture() // shows the system prompt to the user once
		return nil, errors.New("allow Screen Recording for fenrir-agent in System Settings > Privacy & Security, then reconnect")
	}
	d := &cgDesktop{display: cg.mainDisplayID(), buttons: map[int]bool{}, scale: 1}
	d.displays = activeDisplayList()
	if len(d.displays) > 0 {
		d.display = d.displays[0]
	}
	d.origin = cg.displayBounds(d.display).Origin
	if _, _, _, err := d.Capture(); err != nil {
		return nil, err
	}
	if cg.axTrusted != nil && !cg.axTrusted() {
		fmt.Fprintln(os.Stderr, "fenrir: Accessibility permission missing; the screen is view-only until it is granted")
	}
	return d, nil
}

func activeDisplayList() []uint32 {
	ids := make([]uint32, 16)
	var count uint32
	if cg.activeDisplays(uint32(len(ids)), &ids[0], &count) != 0 || count == 0 {
		return []uint32{cg.mainDisplayID()}
	}
	ids = ids[:count]
	main := cg.mainDisplayID()
	for i, id := range ids {
		if id == main {
			ids[0], ids[i] = ids[i], ids[0]
		}
	}
	return ids
}

// Monitors lists the displays (index, position and size in points; the first is the main display).
func (d *cgDesktop) Monitors() []Message {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Message, 0, len(d.displays))
	for i, id := range d.displays {
		b := cg.displayBounds(id)
		out = append(out, Message{"index": i, "x": int(b.Origin.X), "y": int(b.Origin.Y), "w": int(b.Width), "h": int(b.Height),
			"primary": i == 0})
	}
	return out
}

func (d *cgDesktop) SelectMonitor(index int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if index < 0 || index >= len(d.displays) {
		return fmt.Errorf("this Mac has %d display(s)", len(d.displays))
	}
	d.selected, d.display = index, d.displays[index]
	d.origin = cg.displayBounds(d.display).Origin
	return nil
}

func (d *cgDesktop) Size() (int, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.width, d.height
}

func (d *cgDesktop) Close() {}

func (d *cgDesktop) Capture() ([]byte, int, int, error) {
	pixels, w, h, err := d.captureCG()
	if err != nil || pixels == nil {
		d.mu.Lock()
		selected := d.selected
		d.mu.Unlock()
		pixels, w, h, err = captureWithTool(selected + 1)
	}
	if err != nil {
		return nil, 0, 0, err
	}
	d.mu.Lock()
	d.width, d.height = w, h
	if points := int(cg.displayPixelsWide(d.display)); points > 0 {
		d.scale = float64(w) / float64(points)
	}
	d.mu.Unlock()
	return pixels, w, h, nil
}

func (d *cgDesktop) captureCG() ([]byte, int, int, error) {
	if !cg.haveCreateImage {
		return nil, 0, 0, nil
	}
	d.mu.Lock()
	display := d.display
	d.mu.Unlock()
	img := cg.displayCreateImage(display)
	if img == 0 {
		return nil, 0, 0, nil
	}
	defer cg.imageRelease(img)
	w, h := int(cg.imageGetWidth(img)), int(cg.imageGetHeight(img))
	stride := int(cg.imageGetBytesPerRow(img))
	if cg.imageGetBitsPerPix(img) != 32 || w <= 0 || h <= 0 || stride < w*4 {
		return nil, 0, 0, nil
	}
	data := cg.providerCopyData(cg.imageGetProvider(img))
	if data == 0 {
		return nil, 0, 0, nil
	}
	defer cg.release(data)
	length := int(cg.dataGetLength(data))
	if length < stride*h {
		return nil, 0, 0, errors.New("screen capture returned too little data")
	}
	raw := unsafe.Slice(cg.dataGetBytePtr(data), length)
	bigEndian := cg.imageGetBitmapInfo(img)&cgBitmapByteOrderMask == cgBitmapByteOrder32Big
	return packBGRA(raw, w, h, stride, bigEndian), w, h, nil
}

// captureWithTool is the fallback when CGDisplayCreateImage is gone (newer macOS).
func captureWithTool(displayNumber int) ([]byte, int, int, error) {
	file := filepath.Join(os.TempDir(), "fenrir-screen-"+strconv.Itoa(os.Getpid())+".png")
	defer os.Remove(file)
	if out, err := exec.Command("/usr/sbin/screencapture", "-x", "-C", "-D", strconv.Itoa(displayNumber), "-t", "png", file).CombinedOutput(); err != nil {
		return nil, 0, 0, fmt.Errorf("screencapture failed: %s", bytes.TrimSpace(out))
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, 0, 0, err
	}
	defer f.Close()
	src, err := png.Decode(f)
	if err != nil {
		return nil, 0, 0, err
	}
	b := src.Bounds()
	rgba := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(rgba, rgba.Bounds(), src, b.Min, draw.Src)
	out := rgba.Pix
	for i := 0; i+3 < len(out); i += 4 {
		out[i], out[i+2] = out[i+2], out[i] // RGBA -> BGRA
	}
	return out, b.Dx(), b.Dy(), nil
}

func (d *cgDesktop) postMouse(kind uint32, button uint32) {
	x, y := pointsFromPixels(d.x, d.y, d.scale)
	event := cg.mouseEvent(0, kind, cgPoint{X: d.origin.X + x, Y: d.origin.Y + y}, button)
	if event == 0 {
		return
	}
	if kind != cgEventMouseMoved && kind != cgEventLeftDragged && kind != cgEventRightDragged && kind != cgEventOtherDragged {
		cg.setIntField(event, cgMouseClickStateFld, d.clicks)
	}
	cg.setFlags(event, d.mods.flags())
	cg.post(cgHIDEventTap, event)
	cg.release(event)
}

func (d *cgDesktop) MouseMove(x, y int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.x, d.y = x, y
	switch {
	case d.buttons[0]:
		d.postMouse(cgEventLeftDragged, 0)
	case d.buttons[2]:
		d.postMouse(cgEventRightDragged, 1)
	case d.buttons[1]:
		d.postMouse(cgEventOtherDragged, 2)
	default:
		d.postMouse(cgEventMouseMoved, 0)
	}
	return nil
}

// MouseButton takes browser buttons: 0 left, 1 middle, 2 right.
func (d *cgDesktop) MouseButton(button int, down bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if down {
		if button == d.lastBtn && time.Since(d.lastClick) < 400*time.Millisecond {
			d.clicks++
		} else {
			d.clicks = 1
		}
		d.lastBtn, d.lastClick = button, time.Now()
	}
	d.buttons[button] = down
	switch button {
	case 0:
		d.postMouse(map[bool]uint32{true: cgEventLeftDown, false: cgEventLeftUp}[down], 0)
	case 2:
		d.postMouse(map[bool]uint32{true: cgEventRightDown, false: cgEventRightUp}[down], 1)
	case 1:
		d.postMouse(map[bool]uint32{true: cgEventOtherDown, false: cgEventOtherUp}[down], 2)
	}
	return nil
}

func (d *cgDesktop) Wheel(dy, dx int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	clamp := func(v int) int32 {
		switch {
		case v > 0:
			return -3
		case v < 0:
			return 3
		}
		return 0
	}
	event := cg.scrollEvent(0, cgScrollUnitLine, 2, clamp(dy), clamp(dx), 0)
	if event != 0 {
		cg.post(cgHIDEventTap, event)
		cg.release(event)
	}
	return nil
}

func (d *cgDesktop) Key(code string, down bool) error {
	key, ok := MacKeyCode(code)
	if !ok {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.mods.update(code, down)
	event := cg.keyboardEvent(0, key, down)
	if event == 0 {
		return nil
	}
	cg.setFlags(event, d.mods.flags())
	cg.post(cgHIDEventTap, event)
	cg.release(event)
	return nil
}

// Type sends text as Unicode keyboard events, so it works whatever the keyboard layout.
func (d *cgDesktop) Type(text string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range text {
		if r == '\n' {
			r = '\r'
		}
		units := utf16.Encode([]rune{r})
		for _, down := range []bool{true, false} {
			event := cg.keyboardEvent(0, 0, down)
			if event == 0 {
				continue
			}
			cg.setUnicode(event, uint64(len(units)), &units[0])
			cg.post(cgHIDEventTap, event)
			cg.release(event)
		}
	}
	return nil
}
