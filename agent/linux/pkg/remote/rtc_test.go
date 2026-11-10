package remote

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

func TestChunksRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, chunkPayload - 1, chunkPayload, chunkPayload + 1, 5*chunkPayload + 77} {
		frame := bytes.Repeat([]byte{0xAB}, size)
		for i := range frame {
			frame[i] = byte(i * 7)
		}
		var r Reassembler
		var got []byte
		parts := SplitChunks(42, frame)
		for i, p := range parts {
			if len(p) > chunkHeader+chunkPayload {
				t.Fatalf("chunk %d is %d bytes", i, len(p))
			}
			out, err := r.Add(p)
			if err != nil {
				t.Fatalf("size %d chunk %d: %v", size, i, err)
			}
			if out != nil {
				got = out
			}
		}
		if got == nil || !bytes.Equal(got, frame) {
			t.Fatalf("size %d: frame did not reassemble", size)
		}
	}
}

func TestReassemblerRejectsGaps(t *testing.T) {
	parts := SplitChunks(1, make([]byte, 3*chunkPayload))
	var r Reassembler
	if _, err := r.Add(parts[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(parts[2]); err == nil {
		t.Fatal("a missing chunk should be an error")
	}
	// The next frame starts cleanly.
	next := SplitChunks(2, []byte("hello"))
	if out, err := r.Add(next[0]); err != nil || string(out) != "hello" {
		t.Fatalf("got %q, %v", out, err)
	}
}

func TestDirectAllowed(t *testing.T) {
	allowed := []Message{
		{"ch": "screen", "t": "ack"}, {"ch": "input", "t": "mm"}, {"ch": "input", "t": "kd"}, {"ch": "sys", "t": "ping"},
	}
	for _, m := range allowed {
		if !DirectAllowed(m) {
			t.Errorf("%v should go direct", m)
		}
	}
	refused := []Message{
		{"ch": "input", "t": "cad"}, {"ch": "input", "t": "lock"}, {"ch": "term", "t": "open"}, {"ch": "files", "t": "list"},
		{"ch": "sys", "t": "end"}, {"ch": "chat", "t": "msg"}, {"ch": "rtc", "t": "offer"}, {"ch": "input", "t": "clip"},
	}
	for _, m := range refused {
		if DirectAllowed(m) {
			t.Errorf("%v must stay on the relay", m)
		}
	}
}

// TestDirectLoopback connects a pion "viewer" to the agent's link on this machine and checks frames and input flow.
func TestDirectLoopback(t *testing.T) {
	viewer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer viewer.Close()

	toViewer := make(chan Message, 64)
	delivered := make(chan Message, 8)
	link, err := newRTCLink(nil, func(m Message) { toViewer <- m }, func(m Message) { delivered <- m }, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer link.close()

	viewer.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		init := c.ToJSON()
		m := Message{"candidate": init.Candidate}
		if init.SDPMid != nil {
			m["sdpMid"] = *init.SDPMid
		}
		go func() { _ = link.handle("candidate", m) }()
	})
	dc, err := viewer.CreateDataChannel("fenrir", nil)
	if err != nil {
		t.Fatal(err)
	}
	frames := make(chan []byte, 4)
	var r Reassembler
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if out, err := r.Add(msg.Data); err == nil && out != nil {
			frames <- out
		}
	})
	offer, err := viewer.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := viewer.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	if err := link.handle("offer", Message{"sdp": offer.SDP}); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(20 * time.Second)
	open := false
	for !open {
		select {
		case m := <-toViewer:
			switch m.str("t") {
			case "answer":
				if err := viewer.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: m.str("sdp")}); err != nil {
					t.Fatal(err)
				}
			case "candidate":
				init := webrtc.ICECandidateInit{Candidate: m.str("candidate")}
				if mid := m.str("sdpMid"); mid != "" {
					init.SDPMid = &mid
				}
				_ = viewer.AddICECandidate(init)
			case "open":
				open = true
			}
		case <-deadline:
			t.Skip("no local ICE path in this environment")
		}
	}

	frame := make([]byte, 3*chunkPayload+123)
	for i := range frame {
		frame[i] = byte(i)
	}
	if !link.sendFrame(frame) {
		t.Fatal("sendFrame refused an open channel")
	}
	select {
	case got := <-frames:
		if !bytes.Equal(got, frame) {
			t.Fatal("frame changed in transit")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("frame never arrived")
	}

	for _, m := range []Message{{"ch": "input", "t": "cad"}, {"ch": "term", "t": "open"}, {"ch": "input", "t": "mm", "x": 5.0}} {
		data, _ := json.Marshal(m)
		if err := dc.SendText(string(data)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case m := <-delivered:
		if m.str("t") != "mm" {
			t.Fatalf("a relay-only message came through the direct channel: %v", m)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("input never arrived")
	}
	select {
	case m := <-delivered:
		t.Fatalf("unexpected extra message %v", m)
	case <-time.After(300 * time.Millisecond):
	}
}
