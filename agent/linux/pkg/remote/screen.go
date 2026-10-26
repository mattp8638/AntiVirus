package remote

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/jpeg"
	"sync"
	"time"
)

const tileSize = 128

// screenStreamer captures the desktop, sends changed tiles as JPEG and keeps at most
// two frames unacknowledged so a slow link lowers the frame rate instead of queueing.
type screenStreamer struct {
	s        *Session
	desktop  Desktop
	mu       sync.Mutex
	cond     *sync.Cond
	quality  int
	fps      int
	inFlight int
	full     bool
	stopped  bool
	prev     []byte
	prevW    int
	prevH    int
	seq      int
}

func newScreenStreamer(s *Session, d Desktop) *screenStreamer {
	st := &screenStreamer{s: s, desktop: d, quality: s.opts.Quality, fps: s.opts.MaxFps, full: true}
	st.cond = sync.NewCond(&st.mu)
	return st
}

func (st *screenStreamer) configure(quality, fps int) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if quality >= 10 && quality <= 100 {
		st.quality = quality
	}
	if fps >= 1 && fps <= 60 {
		// The policy's maximum still applies.
		if limit := st.s.opts.MaxFps; limit > 0 && fps > limit {
			fps = limit
		}
		st.fps = fps
	}
}

func (st *screenStreamer) refresh() {
	st.mu.Lock()
	st.full = true
	st.mu.Unlock()
	st.cond.Broadcast()
}

func (st *screenStreamer) ack() {
	st.mu.Lock()
	if st.inFlight > 0 {
		st.inFlight--
	}
	st.mu.Unlock()
	st.cond.Broadcast()
}

func (st *screenStreamer) stop() {
	st.mu.Lock()
	st.stopped = true
	st.mu.Unlock()
	st.cond.Broadcast()
}

func (st *screenStreamer) run() {
	for {
		st.mu.Lock()
		for st.inFlight >= 2 && !st.stopped {
			// Wake periodically so a lost ack cannot stall the stream forever.
			timer := time.AfterFunc(3*time.Second, func() {
				st.mu.Lock()
				st.inFlight = 0
				st.mu.Unlock()
				st.cond.Broadcast()
			})
			st.cond.Wait()
			timer.Stop()
		}
		if st.stopped {
			st.mu.Unlock()
			return
		}
		quality, fps, full := st.quality, st.fps, st.full
		st.full = false
		st.mu.Unlock()
		select {
		case <-st.s.ctx.Done():
			return
		default:
		}
		started := time.Now()
		sent, err := st.frame(quality, full)
		if err != nil {
			st.s.logf("remote: capture failed: %v", err)
			time.Sleep(time.Second)
			continue
		}
		if sent {
			st.mu.Lock()
			st.inFlight++
			st.mu.Unlock()
		}
		if wait := time.Second/time.Duration(maxInt(fps, 1)) - time.Since(started); wait > 0 {
			time.Sleep(wait)
		}
	}
}

// frame captures once and sends every changed tile followed by frame.end. Returns whether anything was sent.
func (st *screenStreamer) frame(quality int, full bool) (bool, error) {
	pixels, w, h, err := st.desktop.Capture()
	if err != nil {
		return false, err
	}
	if w != st.prevW || h != st.prevH || len(st.prev) != len(pixels) {
		full = true
	}
	tiles := ChangedTiles(st.prev, pixels, w, h, full)
	st.prev, st.prevW, st.prevH = pixels, w, h
	if len(tiles) == 0 {
		return false, nil
	}
	for _, r := range tiles {
		data, err := EncodeTile(pixels, w, r, quality)
		if err != nil {
			return false, err
		}
		if err := st.s.sendBinary(TileFrame(r, w, h, data)); err != nil {
			return false, err
		}
	}
	st.seq++
	return true, st.s.send(Message{"ch": "screen", "t": "frame.end", "seq": st.seq, "tiles": len(tiles)})
}

// ChangedTiles compares two BGRA frames tile by tile.
func ChangedTiles(prev, cur []byte, w, h int, full bool) []image.Rectangle {
	var out []image.Rectangle
	stride := w * 4
	for ty := 0; ty < h; ty += tileSize {
		for tx := 0; tx < w; tx += tileSize {
			r := image.Rect(tx, ty, minInt(tx+tileSize, w), minInt(ty+tileSize, h))
			if full || len(prev) != len(cur) {
				out = append(out, r)
				continue
			}
			for y := r.Min.Y; y < r.Max.Y; y++ {
				start, end := y*stride+r.Min.X*4, y*stride+r.Max.X*4
				if !bytes.Equal(prev[start:end], cur[start:end]) {
					out = append(out, r)
					break
				}
			}
		}
	}
	return out
}

// EncodeTile converts one BGRA tile to JPEG.
func EncodeTile(pixels []byte, stride int, r image.Rectangle, quality int) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, r.Dx(), r.Dy()))
	for y := 0; y < r.Dy(); y++ {
		src := pixels[((r.Min.Y+y)*stride+r.Min.X)*4 : ((r.Min.Y+y)*stride+r.Max.X)*4]
		dst := img.Pix[y*img.Stride : y*img.Stride+r.Dx()*4]
		for i := 0; i < len(src); i += 4 {
			dst[i], dst[i+1], dst[i+2], dst[i+3] = src[i+2], src[i+1], src[i], 0xff
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// TileFrame builds the 0x01 binary frame: kind, x, y, w, h, screen w, screen h, JPEG.
func TileFrame(r image.Rectangle, screenW, screenH int, jpegData []byte) []byte {
	frame := make([]byte, 13+len(jpegData))
	frame[0] = 0x01
	binary.BigEndian.PutUint16(frame[1:], uint16(r.Min.X))
	binary.BigEndian.PutUint16(frame[3:], uint16(r.Min.Y))
	binary.BigEndian.PutUint16(frame[5:], uint16(r.Dx()))
	binary.BigEndian.PutUint16(frame[7:], uint16(r.Dy()))
	binary.BigEndian.PutUint16(frame[9:], uint16(screenW))
	binary.BigEndian.PutUint16(frame[11:], uint16(screenH))
	copy(frame[13:], jpegData)
	return frame
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
