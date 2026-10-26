package remote

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// A desktop helper runs inside the signed-in user's graphical session (on macOS a root LaunchDaemon
// cannot see or control the screen) and serves Desktop calls over its stdin/stdout.
//
// Wire format, both directions: [kind byte][payload length uint32 BE][payload].
// Requests use an op code as kind and JSON arguments; replies use 0 (ok) or 1 (error message).
// The helper sends one reply first, before any request: ok when its desktop opened, or why not.
const (
	helperOpSize byte = iota + 1
	helperOpCapture
	helperOpMove
	helperOpButton
	helperOpWheel
	helperOpKey
	helperOpType
	helperOpMonitors
	helperOpSelectMonitor

	helperOK    byte = 0
	helperError byte = 1

	maxHelperRequest = 1 << 20   // input arguments are tiny
	maxHelperReply   = 512 << 20 // an 8K BGRA frame is 128 MB
)

// HelperCommand is the argument that starts the agent binary as a desktop helper.
const HelperCommand = "remote-desktop-helper"

type helperArgs struct {
	X      int    `json:"x,omitempty"`
	Y      int    `json:"y,omitempty"`
	Button int    `json:"button,omitempty"`
	DY     int    `json:"dy,omitempty"`
	DX     int    `json:"dx,omitempty"`
	Down   bool   `json:"down,omitempty"`
	Code   string `json:"code,omitempty"`
	Text   string `json:"text,omitempty"`
}

func writeHelperFrame(w io.Writer, kind byte, payload []byte) error {
	frame := make([]byte, 5+len(payload))
	frame[0] = kind
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	copy(frame[5:], payload)
	_, err := w.Write(frame)
	return err
}

func readHelperFrame(r io.Reader, limit int) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	size := int(binary.BigEndian.Uint32(header[1:]))
	if size > limit {
		return 0, nil, fmt.Errorf("desktop helper frame too large (%d bytes)", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return header[0], payload, nil
}

// helperDesktop is the agent side: a Desktop whose calls run in the helper process.
type helperDesktop struct {
	mu     sync.Mutex
	w      io.WriteCloser
	r      *bufio.Reader
	closer func()
	width  int
	height int
}

func newHelperDesktop(w io.WriteCloser, r io.Reader, closer func()) (*helperDesktop, error) {
	d := &helperDesktop{w: w, r: bufio.NewReaderSize(r, 1<<20), closer: closer}
	kind, payload, err := readHelperFrame(d.r, maxHelperRequest)
	if err == nil && kind != helperOK {
		err = errors.New(string(payload))
	}
	if err != nil {
		d.Close()
		return nil, err
	}
	if _, err := d.call(helperOpSize, helperArgs{}); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

func (d *helperDesktop) call(op byte, args helperArgs) ([]byte, error) {
	data, _ := json.Marshal(args)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := writeHelperFrame(d.w, op, data); err != nil {
		return nil, fmt.Errorf("desktop helper stopped: %w", err)
	}
	kind, payload, err := readHelperFrame(d.r, maxHelperReply)
	if err != nil {
		return nil, fmt.Errorf("desktop helper stopped: %w", err)
	}
	if kind != helperOK {
		return nil, errors.New(string(payload))
	}
	if op == helperOpSize || op == helperOpCapture {
		if len(payload) < 8 {
			return nil, errors.New("desktop helper sent a short reply")
		}
		d.width, d.height = int(binary.BigEndian.Uint32(payload)), int(binary.BigEndian.Uint32(payload[4:]))
		payload = payload[8:]
	}
	return payload, nil
}

func (d *helperDesktop) Size() (int, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.width, d.height
}

func (d *helperDesktop) Capture() ([]byte, int, int, error) {
	pixels, err := d.call(helperOpCapture, helperArgs{})
	if err != nil {
		return nil, 0, 0, err
	}
	w, h := d.Size()
	if len(pixels) != w*h*4 {
		return nil, 0, 0, errors.New("desktop helper sent a frame of the wrong size")
	}
	return pixels, w, h, nil
}

func (d *helperDesktop) MouseMove(x, y int) error {
	_, err := d.call(helperOpMove, helperArgs{X: x, Y: y})
	return err
}

func (d *helperDesktop) MouseButton(button int, down bool) error {
	_, err := d.call(helperOpButton, helperArgs{Button: button, Down: down})
	return err
}

func (d *helperDesktop) Wheel(dy, dx int) error {
	_, err := d.call(helperOpWheel, helperArgs{DY: dy, DX: dx})
	return err
}

func (d *helperDesktop) Key(code string, down bool) error {
	_, err := d.call(helperOpKey, helperArgs{Code: code, Down: down})
	return err
}

func (d *helperDesktop) Type(text string) error {
	_, err := d.call(helperOpType, helperArgs{Text: text})
	return err
}

// Monitors lists the helper's displays (empty when it has only one).
func (d *helperDesktop) Monitors() []Message {
	data, err := d.call(helperOpMonitors, helperArgs{})
	if err != nil {
		return nil
	}
	var out []Message
	_ = json.Unmarshal(data, &out)
	return out
}

func (d *helperDesktop) SelectMonitor(index int) error {
	_, err := d.call(helperOpSelectMonitor, helperArgs{Button: index})
	return err
}

func (d *helperDesktop) Close() {
	_ = d.w.Close()
	if d.closer != nil {
		d.closer()
	}
}

func sizeHeader(w, h int) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint32(out, uint32(w))
	binary.BigEndian.PutUint32(out[4:], uint32(h))
	return out
}

// ServeDesktop is the helper side: answer Desktop calls from r on w until r closes.
func ServeDesktop(r io.Reader, w io.Writer, d Desktop) error {
	in := bufio.NewReader(r)
	out := bufio.NewWriterSize(w, 1<<20)
	reply := func(err error, payload []byte) error {
		if err != nil {
			payload = []byte(err.Error())
		}
		kind := helperOK
		if err != nil {
			kind = helperError
		}
		if e := writeHelperFrame(out, kind, payload); e != nil {
			return e
		}
		return out.Flush()
	}
	for {
		op, data, err := readHelperFrame(in, maxHelperRequest)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		var args helperArgs
		if len(data) > 0 && json.Unmarshal(data, &args) != nil {
			if err := reply(errors.New("bad helper request"), nil); err != nil {
				return err
			}
			continue
		}
		var payload []byte
		switch op {
		case helperOpSize:
			w, h := d.Size()
			payload = sizeHeader(w, h)
		case helperOpCapture:
			var pixels []byte
			var w, h int
			pixels, w, h, err = d.Capture()
			if err == nil {
				payload = append(sizeHeader(w, h), pixels...)
			}
		case helperOpMove:
			err = d.MouseMove(args.X, args.Y)
		case helperOpButton:
			err = d.MouseButton(args.Button, args.Down)
		case helperOpWheel:
			err = d.Wheel(args.DY, args.DX)
		case helperOpKey:
			err = d.Key(args.Code, args.Down)
		case helperOpType:
			err = d.Type(args.Text)
		case helperOpMonitors:
			var list []Message
			if md, ok := d.(MonitorDesktop); ok {
				list = md.Monitors()
			}
			payload, _ = json.Marshal(list)
		case helperOpSelectMonitor:
			if md, ok := d.(MonitorDesktop); ok {
				err = md.SelectMonitor(args.Button)
			}
		default:
			err = fmt.Errorf("unknown helper request %d", op)
		}
		if err := reply(err, payload); err != nil {
			return err
		}
	}
}

// RunDesktopHelper is the entry point of `fenrir-agent remote-desktop-helper`: open this session's
// screen and serve it on stdin/stdout.
func RunDesktopHelper() error {
	d, err := openNativeDesktop()
	if err != nil {
		_ = writeHelperFrame(os.Stdout, helperError, []byte(err.Error()))
		return err
	}
	defer d.Close()
	if err := writeHelperFrame(os.Stdout, helperOK, nil); err != nil {
		return err
	}
	return ServeDesktop(os.Stdin, os.Stdout, d)
}
