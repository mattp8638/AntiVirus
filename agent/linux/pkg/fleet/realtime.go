package fleet

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// RealtimeURL derives the wake-channel URL from the server URL.
func RealtimeURL(server, deviceID string) string {
	base := strings.TrimRight(strings.TrimSuffix(strings.TrimRight(server, "/"), "/api/v1"), "/")
	switch {
	case strings.HasPrefix(base, "https://"):
		base = "wss://" + strings.TrimPrefix(base, "https://")
	case strings.HasPrefix(base, "http://"):
		base = "ws://" + strings.TrimPrefix(base, "http://")
	}
	return base + "/api/v1/devices/" + deviceID + "/realtime"
}

// listenRealtime holds the wake channel open and signals wake whenever the cloud queues a command.
// It reconnects with backoff and never blocks the main loop.
func (a *Agent) listenRealtime() {
	backoff := 5 * time.Second
	for {
		select {
		case <-a.stop:
			return
		default:
		}
		started := time.Now()
		err := a.realtimeOnce()
		if time.Since(started) > time.Minute {
			backoff = 5 * time.Second
		}
		if err != nil {
			log.Printf("realtime channel: %v (retrying in %s)", err, backoff)
		}
		select {
		case <-a.stop:
			return
		case <-time.After(backoff):
		}
		if backoff < 2*time.Minute {
			backoff = min(backoff*2, 2*time.Minute)
		}
	}
}

func (a *Agent) realtimeOnce() error {
	dialer := websocket.Dialer{HandshakeTimeout: 20 * time.Second, Proxy: http.ProxyFromEnvironment}
	conn, _, err := dialer.Dial(RealtimeURL(a.cfg.Server, a.state.DeviceID), http.Header{"X-Device-Api-Key": {a.client.Key()}})
	if err != nil {
		return err
	}
	defer conn.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-a.stop:
				_ = conn.Close()
				return
			case <-ticker.C:
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if conn.WriteMessage(websocket.TextMessage, []byte("ping")) != nil {
					_ = conn.Close()
					return
				}
			}
		}
	}()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var msg struct {
			Type    string `json:"type"`
			PollNow bool   `json:"pollNow"`
		}
		if json.Unmarshal(data, &msg) == nil && (msg.Type == "commands" || msg.PollNow) {
			select {
			case a.wake <- struct{}{}:
			default:
			}
		}
	}
}

// Presence remains independent of scans, inventory, command execution and WebSocket availability.
func (a *Agent) reportPresence(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-ticker.C:
			if err := a.client.do("POST", "/api/v1/devices/"+a.client.DeviceID+"/presence", nil, nil, nil); err != nil {
				log.Printf("presence check-in failed: %v", err)
			}
		}
	}
}
