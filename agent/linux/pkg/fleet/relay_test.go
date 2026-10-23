package fleet

import "testing"

func TestRelayURLForServer(t *testing.T) {
	cases := []struct{ server, relay, want string }{
		{"http://localhost:8080", "wss://fenrir.example.com/ws/remote/rs_1/agent", "ws://localhost:8080/ws/remote/rs_1/agent"},
		{"https://fenrir.lan/api/v1", "ws://localhost:8080/ws/remote/rs_2/agent?x=1", "wss://fenrir.lan/ws/remote/rs_2/agent?x=1"},
		{"https://msp.test/fenrir/", "wss://other/ws/remote/rs_3/agent", "wss://msp.test/fenrir/ws/remote/rs_3/agent"},
		{"http://localhost:8080", "wss://elsewhere/not-a-relay", "wss://elsewhere/not-a-relay"},
		{"", "wss://x/ws/remote/rs_4/agent", "wss://x/ws/remote/rs_4/agent"},
	}
	for _, c := range cases {
		if got := RelayURLForServer(c.server, c.relay); got != c.want {
			t.Errorf("RelayURLForServer(%q, %q) = %q, want %q", c.server, c.relay, got, c.want)
		}
	}
}
