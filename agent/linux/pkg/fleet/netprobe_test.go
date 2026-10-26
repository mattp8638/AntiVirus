package fleet

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func TestNetworkProbe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	// Loopback is refused as a target, so dial through a stub that maps the LAN address to the test listener.
	dial := func(network, address string, timeout time.Duration) (net.Conn, error) {
		if address == net.JoinHostPort("192.168.1.50", "9100") {
			return net.DialTimeout(network, net.JoinHostPort("127.0.0.1", itoa(port)), timeout)
		}
		return nil, &net.OpError{Op: "dial", Err: errRefused{}}
	}
	out, err := NetworkProbe(`{"targets":[{"monitorId":"a","address":"192.168.1.50","port":9100},
		{"monitorId":"b","address":"192.168.1.51","port":22},{"monitorId":"c","address":"127.0.0.1","port":22},
		{"monitorId":"d","address":"169.254.169.254","port":80}]}`, dial)
	if err != nil {
		t.Fatal(err)
	}
	results := out["results"].([]map[string]interface{})
	if results[0]["up"] != true || results[0]["latencyMs"] == nil {
		t.Fatalf("reachable target: %+v", results[0])
	}
	if results[1]["up"] != false || results[1]["error"] == nil {
		t.Fatalf("refused target: %+v", results[1])
	}
	for _, r := range results[2:] {
		if r["error"] != "target not allowed" {
			t.Fatalf("loopback/metadata must be refused: %+v", r)
		}
	}
	if _, err := NetworkProbe("not json", dial); err == nil {
		t.Fatal("bad payload accepted")
	}
}

type errRefused struct{}

func (errRefused) Error() string { return "connection refused" }

func itoa(n int) string { return strconv.Itoa(n) }
