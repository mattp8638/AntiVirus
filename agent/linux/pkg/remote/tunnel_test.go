package remote

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestTunnelTargetAllowed(t *testing.T) {
	ok := []int{3389, 22}
	for host, want := range map[string]bool{"192.168.1.20": true, "10.0.0.5": true, "8.8.8.8": false, "127.0.0.1": false,
		"169.254.169.254": false, "printer.local": false} {
		if err := TunnelTargetAllowed(host, 3389, ok); (err == nil) != want {
			t.Fatalf("%s: got %v", host, err)
		}
	}
	if TunnelTargetAllowed("192.168.1.20", 445, ok) == nil {
		t.Fatal("a port outside the allowed list must be refused")
	}
}

func TestTunnelRelaysStreamsToTheTarget(t *testing.T) {
	// An "RDP server" on the LAN that echoes with a prefix.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				_, _ = conn.Write(append([]byte("echo:"), buf[:n]...))
				conn.Close()
			}()
		}
	}()
	var dialled string
	TunnelDialer = func(address string) (net.Conn, error) {
		dialled = address
		return net.Dial("tcp", target.Addr().String())
	}
	t.Cleanup(func() { TunnelDialer = func(a string) (net.Conn, error) { return net.DialTimeout("tcp", a, 10*time.Second) } })

	conn, _ := startSession(t, Options{SessionID: "rs_1", Mode: "tunnel", TargetHost: "192.168.10.50", TargetPort: 3389, AllowedPorts: []int{3389}})
	info := readJSON(t, conn, func(m Message) bool { return m.str("t") == "info" })
	if caps := fmt.Sprint(info["capabilities"]); caps != "[tunnel]" {
		t.Fatalf("a tunnel session offers only the tunnel: %v", caps)
	}
	send(t, conn, Message{"ch": "term", "t": "open"}) // ignored in a tunnel session
	send(t, conn, Message{"ch": "tunnel", "t": "open", "id": 7})
	readJSON(t, conn, func(m Message) bool { return m.str("t") == "opened" && m.num("id") == 7 })
	if dialled != "192.168.10.50:3389" {
		t.Fatalf("dialled %q", dialled)
	}
	frame := append([]byte{tunnelFrame, 0, 0, 0, 7}, []byte("hello")...)
	if err := conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		t.Fatal(err)
	}
	var got []byte
	for got == nil {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		kind, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if kind == websocket.TextMessage && strings.Contains(string(data), `"term"`) {
			t.Fatal("a tunnel session must not answer terminal messages")
		}
		if kind == websocket.BinaryMessage {
			if data[0] != tunnelFrame || binary.BigEndian.Uint32(data[1:5]) != 7 {
				t.Fatalf("bad frame %v", data[:5])
			}
			got = data[5:]
		}
	}
	if string(got) != "echo:hello" {
		t.Fatalf("got %q", got)
	}
	readJSON(t, conn, func(m Message) bool { return m.str("ch") == "tunnel" && m.str("t") == "close" && m.num("id") == 7 })
}

func TestBackstageNeverOpensTheDesktop(t *testing.T) {
	opened := false
	DesktopOpener = func() (Desktop, error) { opened = true; return newFakeDesktop(), nil }
	r := newRelay(t)
	mgr := NewManager()
	if err := mgr.Start(Options{SessionID: "rs_1", Mode: "backstage", RelayURL: r.url(), Token: "tok", AllowTerminal: true}); err != nil {
		t.Fatal(err)
	}
	conn := <-r.agent
	defer conn.Close()
	t.Cleanup(func() { DesktopOpener = OpenX11Desktop })
	info := readJSON(t, conn, func(m Message) bool { return m.str("t") == "info" })
	if caps := fmt.Sprint(info["capabilities"]); strings.Contains(caps, "desktop") || !strings.Contains(caps, "backstage") {
		t.Fatalf("capabilities: %v", caps)
	}
	send(t, conn, Message{"ch": "screen", "t": "start"})
	send(t, conn, Message{"ch": "sys", "t": "ping", "ts": 1})
	readJSON(t, conn, func(m Message) bool { return m.str("t") == "pong" })
	if opened {
		t.Fatal("a backstage session must never open the user's desktop")
	}
}
