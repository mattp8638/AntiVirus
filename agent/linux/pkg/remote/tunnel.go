package remote

// TCP tunnels for session routing: the agent connects to a host on its own LAN (an agentless server, switch,
// printer or Intel AMT engine) and relays the byte streams to the technician's tunnel client.
//
// Viewer → agent: {"ch":"tunnel","t":"open","id":n} and {"ch":"tunnel","t":"close","id":n}; binary 0x05 id:u32 <bytes>.
// Agent → viewer: {"ch":"tunnel","t":"opened","id":n}, {"ch":"tunnel","t":"error","id":n,"message":...},
// {"ch":"tunnel","t":"close","id":n}; binary 0x05 id:u32 <bytes>.
// Several streams share one session, so a browser-based web UI (many connections) works as well as RDP or SSH.

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	tunnelFrame      = 0x05
	maxTunnelStreams = 32
	tunnelChunk      = 32 << 10
)

// TunnelDialer is replaced in tests.
var TunnelDialer = func(address string) (net.Conn, error) { return net.DialTimeout("tcp", address, 10*time.Second) }

// TunnelTargetAllowed checks a target against the session's allowed ports and the private ranges a tunnel may reach.
func TunnelTargetAllowed(host string, port int, allowed []int) error {
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("tunnel target %s is not a private LAN address", host)
	}
	for _, p := range allowed {
		if p == port {
			return nil
		}
	}
	return fmt.Errorf("port %d is not an allowed tunnel port", port)
}

type tunnels struct {
	s       *Session
	mu      sync.Mutex
	streams map[uint32]net.Conn
}

func newTunnels(s *Session) *tunnels { return &tunnels{s: s, streams: map[uint32]net.Conn{}} }

func (t *tunnels) handle(kind string, m Message) {
	id := uint32(m.num("id"))
	switch kind {
	case "open":
		t.open(id)
	case "close":
		t.closeStream(id, false)
	}
}

func (t *tunnels) open(id uint32) {
	opts := t.s.opts
	if err := TunnelTargetAllowed(opts.TargetHost, opts.TargetPort, opts.AllowedPorts); err != nil {
		_ = t.s.send(Message{"ch": "tunnel", "t": "error", "id": id, "message": err.Error()})
		return
	}
	t.mu.Lock()
	if _, exists := t.streams[id]; exists || len(t.streams) >= maxTunnelStreams {
		t.mu.Unlock()
		_ = t.s.send(Message{"ch": "tunnel", "t": "error", "id": id, "message": "stream id in use or too many streams"})
		return
	}
	t.streams[id] = nil // reserved while dialling
	t.mu.Unlock()
	go func() {
		conn, err := TunnelDialer(net.JoinHostPort(opts.TargetHost, strconv.Itoa(opts.TargetPort)))
		t.mu.Lock()
		if err != nil {
			delete(t.streams, id)
			t.mu.Unlock()
			_ = t.s.send(Message{"ch": "tunnel", "t": "error", "id": id, "message": err.Error()})
			return
		}
		t.streams[id] = conn
		t.mu.Unlock()
		_ = t.s.send(Message{"ch": "tunnel", "t": "opened", "id": id})
		buf := make([]byte, tunnelChunk+5)
		buf[0] = tunnelFrame
		binary.BigEndian.PutUint32(buf[1:5], id)
		for {
			n, err := conn.Read(buf[5:])
			if n > 0 {
				t.s.touch()
				if t.s.sendBinary(append([]byte(nil), buf[:5+n]...)) != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		t.closeStream(id, true)
	}()
}

// data writes a viewer frame (0x05 id:u32 payload) to its stream.
func (t *tunnels) data(frame []byte) {
	if len(frame) < 5 {
		return
	}
	id := binary.BigEndian.Uint32(frame[1:5])
	t.mu.Lock()
	conn := t.streams[id]
	t.mu.Unlock()
	if conn == nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(frame[5:]); err != nil {
		t.closeStream(id, true)
	}
}

func (t *tunnels) closeStream(id uint32, notify bool) {
	t.mu.Lock()
	conn, ok := t.streams[id]
	delete(t.streams, id)
	t.mu.Unlock()
	if !ok {
		return
	}
	if conn != nil {
		_ = conn.Close()
	}
	if notify {
		_ = t.s.send(Message{"ch": "tunnel", "t": "close", "id": id})
	}
}

func (t *tunnels) closeAll() {
	t.mu.Lock()
	ids := make([]uint32, 0, len(t.streams))
	for id := range t.streams {
		ids = append(ids, id)
	}
	t.mu.Unlock()
	for _, id := range ids {
		t.closeStream(id, false)
	}
}
