// fenrir-tunnel opens a local port that leads, through a Fenrir agent, to a machine on a customer's LAN.
//
//	fenrir-tunnel -url "wss://fenrir.example.com/ws/remote/rs_.../viewer?token=..." -listen 127.0.0.1:13389
//
// Copy the URL from the tunnel session in the console (it carries a short-lived viewer token), then point the usual
// client at the local port: mstsc /v:127.0.0.1:13389, ssh -p 2222 admin@127.0.0.1, a VNC viewer or a browser.
// Every local connection becomes its own stream in the session; the relay audits each one and the session ends when
// this program exits or the technician ends it in the console.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const frameKind = 0x05

type tunnel struct {
	ws      *websocket.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	next    uint32
	streams map[uint32]net.Conn
	ready   map[uint32]chan error
}

func (t *tunnel) sendJSON(m map[string]interface{}) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.ws.WriteJSON(m)
}

func (t *tunnel) sendData(id uint32, data []byte) error {
	frame := make([]byte, 5+len(data))
	frame[0] = frameKind
	binary.BigEndian.PutUint32(frame[1:5], id)
	copy(frame[5:], data)
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.ws.WriteMessage(websocket.BinaryMessage, frame)
}

func (t *tunnel) drop(id uint32, notify bool) {
	t.mu.Lock()
	conn := t.streams[id]
	delete(t.streams, id)
	t.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
		if notify {
			_ = t.sendJSON(map[string]interface{}{"ch": "tunnel", "t": "close", "id": id})
		}
	}
}

// readLoop hands agent frames to their local connections.
func (t *tunnel) readLoop() error {
	for {
		kind, data, err := t.ws.ReadMessage()
		if err != nil {
			return err
		}
		if kind == websocket.BinaryMessage {
			if len(data) < 5 || data[0] != frameKind {
				continue
			}
			id := binary.BigEndian.Uint32(data[1:5])
			t.mu.Lock()
			conn := t.streams[id]
			t.mu.Unlock()
			if conn != nil {
				if _, err := conn.Write(data[5:]); err != nil {
					t.drop(id, true)
				}
			}
			continue
		}
		var m struct {
			Ch, T, Message, Reason string
			ID                     uint32
			AgentConnected         *bool
		}
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		switch {
		case m.Ch == "sys" && m.T == "end":
			return fmt.Errorf("session ended %s", m.Reason)
		case m.Ch == "sys" && m.T == "agent.disconnected":
			return fmt.Errorf("the agent disconnected")
		case m.Ch == "tunnel" && (m.T == "opened" || m.T == "error"):
			t.mu.Lock()
			ch := t.ready[m.ID]
			delete(t.ready, m.ID)
			t.mu.Unlock()
			if ch != nil {
				if m.T == "error" {
					ch <- fmt.Errorf("%s", m.Message)
				} else {
					ch <- nil
				}
			}
		case m.Ch == "tunnel" && m.T == "close":
			t.drop(m.ID, false)
		}
	}
}

func (t *tunnel) serve(local net.Conn) {
	t.mu.Lock()
	t.next++
	id := t.next
	ready := make(chan error, 1)
	t.ready[id] = ready
	t.mu.Unlock()
	if err := t.sendJSON(map[string]interface{}{"ch": "tunnel", "t": "open", "id": id}); err != nil {
		local.Close()
		return
	}
	select {
	case err := <-ready:
		if err != nil {
			log.Printf("stream %d refused: %v", id, err)
			local.Close()
			return
		}
	case <-time.After(20 * time.Second):
		log.Printf("stream %d: the agent did not answer", id)
		local.Close()
		return
	}
	t.mu.Lock()
	t.streams[id] = local
	t.mu.Unlock()
	log.Printf("stream %d open", id)
	buf := make([]byte, 32<<10)
	for {
		n, err := local.Read(buf)
		if n > 0 && t.sendData(id, buf[:n]) != nil {
			break
		}
		if err != nil {
			break
		}
	}
	t.drop(id, true)
	log.Printf("stream %d closed", id)
}

func main() {
	url := flag.String("url", "", "the tunnel URL shown in the console (wss://.../viewer?token=...)")
	listen := flag.String("listen", "127.0.0.1:13389", "local address to listen on")
	flag.Parse()
	if *url == "" {
		flag.Usage()
		os.Exit(2)
	}
	ws, resp, err := (&websocket.Dialer{HandshakeTimeout: 20 * time.Second, Proxy: http.ProxyFromEnvironment}).Dial(*url, nil)
	if err != nil {
		if resp != nil {
			log.Fatalf("the relay refused the tunnel (%s); copy a fresh URL from the console", resp.Status)
		}
		log.Fatalf("could not reach the relay: %v", err)
	}
	ws.SetReadLimit(16 << 20)
	t := &tunnel{ws: ws, streams: map[uint32]net.Conn{}, ready: map[uint32]chan error{}}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	log.Printf("tunnel ready: connect your client to %s (Ctrl+C to end)", listener.Addr())
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go t.serve(conn)
		}
	}()
	err = t.readLoop()
	listener.Close()
	log.Printf("tunnel closed: %v", err)
}
