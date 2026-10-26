package remote

import "strconv"

// macKeyCodes maps browser KeyboardEvent.code values to macOS virtual key codes (kVK_*, ANSI layout;
// the OS applies the user's keyboard layout, as with a physical keyboard).
var macKeyCodes = map[string]uint16{
	"KeyA": 0x00, "KeyS": 0x01, "KeyD": 0x02, "KeyF": 0x03, "KeyH": 0x04, "KeyG": 0x05, "KeyZ": 0x06, "KeyX": 0x07,
	"KeyC": 0x08, "KeyV": 0x09, "IntlBackslash": 0x0A, "KeyB": 0x0B, "KeyQ": 0x0C, "KeyW": 0x0D, "KeyE": 0x0E, "KeyR": 0x0F,
	"KeyY": 0x10, "KeyT": 0x11, "Digit1": 0x12, "Digit2": 0x13, "Digit3": 0x14, "Digit4": 0x15, "Digit6": 0x16,
	"Digit5": 0x17, "Equal": 0x18, "Digit9": 0x19, "Digit7": 0x1A, "Minus": 0x1B, "Digit8": 0x1C, "Digit0": 0x1D,
	"BracketRight": 0x1E, "KeyO": 0x1F, "KeyU": 0x20, "BracketLeft": 0x21, "KeyI": 0x22, "KeyP": 0x23, "Enter": 0x24,
	"KeyL": 0x25, "KeyJ": 0x26, "Quote": 0x27, "KeyK": 0x28, "Semicolon": 0x29, "Backslash": 0x2A, "Comma": 0x2B,
	"Slash": 0x2C, "KeyN": 0x2D, "KeyM": 0x2E, "Period": 0x2F, "Tab": 0x30, "Space": 0x31, "Backquote": 0x32,
	"Backspace": 0x33, "Escape": 0x35, "MetaRight": 0x36, "MetaLeft": 0x37, "ShiftLeft": 0x38, "CapsLock": 0x39,
	"AltLeft": 0x3A, "ControlLeft": 0x3B, "ShiftRight": 0x3C, "AltRight": 0x3D, "ControlRight": 0x3E,
	"NumpadDecimal": 0x41, "NumpadMultiply": 0x43, "NumpadAdd": 0x45, "NumLock": 0x47, "NumpadDivide": 0x4B,
	"NumpadEnter": 0x4C, "NumpadSubtract": 0x4E, "NumpadEqual": 0x51, "Numpad0": 0x52, "Numpad1": 0x53,
	"Numpad2": 0x54, "Numpad3": 0x55, "Numpad4": 0x56, "Numpad5": 0x57, "Numpad6": 0x58, "Numpad7": 0x59,
	"Numpad8": 0x5B, "Numpad9": 0x5C, "Insert": 0x72, "Home": 0x73, "PageUp": 0x74, "Delete": 0x75, "End": 0x77,
	"PageDown": 0x79, "ArrowLeft": 0x7B, "ArrowRight": 0x7C, "ArrowDown": 0x7D, "ArrowUp": 0x7E,
}

var macFunctionKeys = [...]uint16{0x7A, 0x78, 0x63, 0x76, 0x60, 0x61, 0x62, 0x64, 0x65, 0x6D, 0x67, 0x6F, 0x69, 0x6B,
	0x71, 0x6A, 0x40, 0x4F, 0x50, 0x5A} // F1..F20

// CGEventFlags for modifier keys.
const (
	macFlagCapsLock uint64 = 0x10000
	macFlagShift    uint64 = 0x20000
	macFlagControl  uint64 = 0x40000
	macFlagOption   uint64 = 0x80000
	macFlagCommand  uint64 = 0x100000
)

var macModifierFlags = map[string]uint64{
	"ShiftLeft": macFlagShift, "ShiftRight": macFlagShift, "ControlLeft": macFlagControl, "ControlRight": macFlagControl,
	"AltLeft": macFlagOption, "AltRight": macFlagOption, "MetaLeft": macFlagCommand, "MetaRight": macFlagCommand,
}

// MacKeyCode returns the macOS virtual key code for a browser key code.
func MacKeyCode(code string) (uint16, bool) {
	if k, ok := macKeyCodes[code]; ok {
		return k, true
	}
	if len(code) > 1 && code[0] == 'F' {
		if n, err := strconv.Atoi(code[1:]); err == nil && n >= 1 && n <= len(macFunctionKeys) {
			return macFunctionKeys[n-1], true
		}
	}
	return 0, false
}

// macModifierState tracks held modifiers so every posted event carries the right flags.
type macModifierState struct {
	held map[string]bool
	caps bool
}

func (m *macModifierState) update(code string, down bool) {
	if m.held == nil {
		m.held = map[string]bool{}
	}
	if code == "CapsLock" && down {
		m.caps = !m.caps
		return
	}
	if _, ok := macModifierFlags[code]; ok {
		m.held[code] = down
	}
}

func (m *macModifierState) flags() uint64 {
	var flags uint64
	for code, down := range m.held {
		if down {
			flags |= macModifierFlags[code]
		}
	}
	if m.caps {
		flags |= macFlagCapsLock
	}
	return flags
}

// pointsFromPixels converts a position on the captured (backing-pixel) frame to display points.
func pointsFromPixels(x, y int, scale float64) (float64, float64) {
	if scale <= 0 {
		scale = 1
	}
	return float64(x) / scale, float64(y) / scale
}

// packBGRA copies a frame with row padding into tightly packed BGRA, converting from ARGB when the
// image uses big-endian 32-bit byte order.
func packBGRA(src []byte, width, height, stride int, bigEndian bool) []byte {
	out := make([]byte, width*height*4)
	for y := 0; y < height; y++ {
		row := src[y*stride : y*stride+width*4]
		dst := out[y*width*4 : (y+1)*width*4]
		if !bigEndian {
			copy(dst, row)
			continue
		}
		for x := 0; x < width; x++ {
			a, r, g, b := row[x*4], row[x*4+1], row[x*4+2], row[x*4+3]
			dst[x*4], dst[x*4+1], dst[x*4+2], dst[x*4+3] = b, g, r, a
		}
	}
	return out
}
