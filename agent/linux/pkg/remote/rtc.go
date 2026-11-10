package remote

// Direct (peer-to-peer) screen sharing over a WebRTC data channel, set up through the relay.
//
// The viewer offers a data channel ("fenrir") with {"ch":"rtc","t":"offer"} on the relay; the agent answers and both
// trickle ICE candidates the same way. Once the channel opens, screen frames go over it and the viewer sends screen and
// ordinary input messages over it; everything else (terminal, files, chat, Ctrl+Alt+Del, lock, clipboard) stays on the
// relay, where policy is enforced and audited. If the channel cannot open or later closes, frames return to the relay
// on their own. Large frames are split into chunks so they fit any browser's data channel message limit.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
)

// ICEServer is a STUN/TURN server the relay told the session to use (normally the Fenrir server's own STUN port).
type ICEServer struct {
	URLs []string `json:"urls"`
}

const (
	chunkMarker  = 0xFE
	chunkHeader  = 9 // marker, message id (u32), index (u16), count (u16)
	chunkPayload = 16000
	// Frames queue in the data channel while it is congested; past this the next frame waits for the relay path instead.
	maxBuffered = 8 << 20
)

// directInput is what may arrive over the data channel. The rest of the input channel stays on the audited relay.
var directInput = map[string]bool{"mm": true, "md": true, "mu": true, "wh": true, "kd": true, "ku": true, "type": true, "nav": true}

// DirectAllowed reports whether a message that arrived over the data channel may be acted on.
func DirectAllowed(m Message) bool {
	switch m.str("ch") {
	case "screen":
		return true
	case "input":
		return directInput[m.str("t")]
	case "sys":
		return m.str("t") == "ping"
	}
	return false
}

// SplitChunks cuts a binary frame into data channel messages.
func SplitChunks(id uint32, frame []byte) [][]byte {
	count := (len(frame) + chunkPayload - 1) / chunkPayload
	if count == 0 {
		count = 1
	}
	out := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		end := (i + 1) * chunkPayload
		if end > len(frame) {
			end = len(frame)
		}
		part := frame[i*chunkPayload : end]
		msg := make([]byte, chunkHeader+len(part))
		msg[0] = chunkMarker
		binary.BigEndian.PutUint32(msg[1:], id)
		binary.BigEndian.PutUint16(msg[5:], uint16(i))
		binary.BigEndian.PutUint16(msg[7:], uint16(count))
		copy(msg[chunkHeader:], part)
		out = append(out, msg)
	}
	return out
}

// Reassembler puts chunked frames back together (the channel is ordered and reliable, so chunks arrive in order).
type Reassembler struct {
	id    uint32
	parts [][]byte
}

// Add returns the whole frame once its last chunk arrives.
func (r *Reassembler) Add(msg []byte) ([]byte, error) {
	if len(msg) < chunkHeader || msg[0] != chunkMarker {
		return nil, errors.New("not a frame chunk")
	}
	id := binary.BigEndian.Uint32(msg[1:])
	index, count := int(binary.BigEndian.Uint16(msg[5:])), int(binary.BigEndian.Uint16(msg[7:]))
	if index == 0 {
		r.id, r.parts = id, make([][]byte, 0, count)
	}
	if id != r.id || index != len(r.parts) || count == 0 || index >= count {
		r.parts = nil
		return nil, errors.New("chunk out of order")
	}
	r.parts = append(r.parts, msg[chunkHeader:])
	if len(r.parts) < count {
		return nil, nil
	}
	size := 0
	for _, p := range r.parts {
		size += len(p)
	}
	frame := make([]byte, 0, size)
	for _, p := range r.parts {
		frame = append(frame, p...)
	}
	r.parts = nil
	return frame, nil
}

// rtcLink is the agent's end of a direct connection. signal sends set-up messages over the relay; deliver hands
// messages received over the data channel to the session (after DirectAllowed).
type rtcLink struct {
	pc      *webrtc.PeerConnection
	dc      atomic.Pointer[webrtc.DataChannel]
	open    atomic.Bool
	nextID  atomic.Uint32
	sendMu  sync.Mutex
	signal  func(Message)
	deliver func(Message)
	logf    func(string, ...interface{})
}

func newRTCLink(servers []ICEServer, signal, deliver func(Message), logf func(string, ...interface{})) (*rtcLink, error) {
	config := webrtc.Configuration{}
	for _, s := range servers {
		if len(s.URLs) > 0 {
			config.ICEServers = append(config.ICEServers, webrtc.ICEServer{URLs: s.URLs})
		}
	}
	settings := webrtc.SettingEngine{}
	settings.SetICETimeouts(5*time.Second, 15*time.Second, 2*time.Second)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settings))
	pc, err := api.NewPeerConnection(config)
	if err != nil {
		return nil, err
	}
	l := &rtcLink{pc: pc, signal: signal, deliver: deliver, logf: logf}
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		init := c.ToJSON()
		m := Message{"ch": "rtc", "t": "candidate", "candidate": init.Candidate}
		if init.SDPMid != nil {
			m["sdpMid"] = *init.SDPMid
		}
		if init.SDPMLineIndex != nil {
			m["sdpMLineIndex"] = *init.SDPMLineIndex
		}
		l.signal(m)
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed ||
			state == webrtc.PeerConnectionStateDisconnected {
			if l.open.Swap(false) {
				l.signal(Message{"ch": "rtc", "t": "closed", "reason": state.String()})
			}
		}
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		if dc.Label() != "fenrir" {
			_ = dc.Close()
			return
		}
		l.dc.Store(dc)
		dc.OnOpen(func() {
			l.open.Store(true)
			l.signal(Message{"ch": "rtc", "t": "open"})
		})
		dc.OnClose(func() {
			if l.open.Swap(false) {
				l.signal(Message{"ch": "rtc", "t": "closed", "reason": "channel closed"})
			}
		})
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			if !msg.IsString {
				return // the viewer sends no binary over the direct channel
			}
			var m Message
			if json.Unmarshal(msg.Data, &m) != nil || !DirectAllowed(m) {
				return
			}
			l.deliver(m)
		})
	})
	return l, nil
}

// handle processes a set-up message from the viewer (offer or candidate).
func (l *rtcLink) handle(t string, m Message) error {
	switch t {
	case "offer":
		if err := l.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: m.str("sdp")}); err != nil {
			return err
		}
		answer, err := l.pc.CreateAnswer(nil)
		if err != nil {
			return err
		}
		if err := l.pc.SetLocalDescription(answer); err != nil {
			return err
		}
		l.signal(Message{"ch": "rtc", "t": "answer", "sdp": answer.SDP})
	case "candidate":
		if m.str("candidate") == "" {
			return nil
		}
		init := webrtc.ICECandidateInit{Candidate: m.str("candidate")}
		if mid := m.str("sdpMid"); mid != "" {
			init.SDPMid = &mid
		}
		if v, ok := m["sdpMLineIndex"].(float64); ok {
			index := uint16(v)
			init.SDPMLineIndex = &index
		}
		return l.pc.AddICECandidate(init)
	}
	return nil
}

// sendFrame sends a binary screen frame over the data channel. False means "use the relay for this one".
func (l *rtcLink) sendFrame(frame []byte) bool {
	dc := l.dc.Load()
	if dc == nil || !l.open.Load() || dc.BufferedAmount() > maxBuffered {
		return false
	}
	l.sendMu.Lock()
	defer l.sendMu.Unlock()
	for _, part := range SplitChunks(l.nextID.Add(1), frame) {
		if err := dc.Send(part); err != nil {
			l.open.Store(false)
			return false
		}
	}
	return true
}

// sendText sends a JSON control message (frame.end) over the data channel, so it stays in order with its tiles.
func (l *rtcLink) sendText(m Message) bool {
	dc := l.dc.Load()
	if dc == nil || !l.open.Load() {
		return false
	}
	data, err := json.Marshal(m)
	if err != nil {
		return false
	}
	l.sendMu.Lock()
	defer l.sendMu.Unlock()
	if dc.SendText(string(data)) != nil {
		l.open.Store(false)
		return false
	}
	return true
}

func (l *rtcLink) close() {
	l.open.Store(false)
	_ = l.pc.Close()
}
