package fleet

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestSweepTargetsStayPrivateAndBounded(t *testing.T) {
	_, n24, _ := net.ParseCIDR("192.168.1.0/24")
	targets := SweepTargets(net.ParseIP("192.168.1.10"), n24, 1024)
	if len(targets) != 253 {
		t.Fatalf("a /24 has 253 other hosts, got %d", len(targets))
	}
	for _, ip := range targets {
		if ip.Equal(net.ParseIP("192.168.1.10")) || ip.Equal(net.ParseIP("192.168.1.0")) || ip.Equal(net.ParseIP("192.168.1.255")) {
			t.Fatalf("unexpected target %s", ip)
		}
	}
	_, n16, _ := net.ParseCIDR("10.20.0.0/16")
	if got := SweepTargets(net.ParseIP("10.20.5.7"), n16, 1024); len(got) != 253 || got[0].String() != "10.20.5.1" {
		t.Fatalf("a /16 narrows to the /24 around the device: %d %v", len(got), got[0])
	}
	_, public, _ := net.ParseCIDR("8.8.8.0/24")
	if SweepTargets(net.ParseIP("8.8.8.8"), public, 1024) != nil {
		t.Fatal("public ranges are never swept")
	}
}

func TestNeighbourAndGatewayParsers(t *testing.T) {
	arp := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.168.1.1      0x1         0x2         AA:BB:CC:00:11:22     *        eth0\n" +
		"192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
	n := ParseLinuxARP(arp)
	if len(n) != 1 || n[0].MAC != "aa:bb:cc:00:11:22" {
		t.Fatalf("arp: %+v", n)
	}
	bsd := "? (192.168.1.1) at 0:1b:2c:3d:4e:5f on en0 ifscope [ethernet]\n? (192.168.1.7) at (incomplete) on en0 ifscope [ethernet]\n"
	m := ParseBSDARP(bsd)
	if len(m) != 1 || m[0].MAC != "00:1b:2c:3d:4e:5f" {
		t.Fatalf("bsd arp: %+v", m)
	}
	route := "Iface\tDestination\tGateway \tFlags\nnet0\t00000000\t0101A8C0\t0003\nnet0\t0001A8C0\t00000000\t0001\n"
	if gw := ParseLinuxGateway(route); gw != "192.168.1.1" {
		t.Fatalf("gateway %q", gw)
	}
}

func TestSweepFindsOpenPorts(t *testing.T) {
	open := map[string]bool{"192.168.1.5:9100": true, "192.168.1.6:22": true}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if open[address] {
			c1, c2 := net.Pipe()
			c2.Close()
			return c1, nil
		}
		return nil, errors.New("refused")
	}
	targets := []net.IP{net.ParseIP("192.168.1.5"), net.ParseIP("192.168.1.6"), net.ParseIP("192.168.1.7")}
	got := sweep(context.Background(), targets, []int{22, 9100}, 50*time.Millisecond, dial)
	if len(got) != 2 || got["192.168.1.5"][0] != 9100 || got["192.168.1.6"][0] != 22 {
		t.Fatalf("sweep: %v", got)
	}
}

func TestDiscoverOnThisHost(t *testing.T) {
	off := false
	a := New(Config{StateDir: t.TempDir()})
	result, err := a.Discover(context.Background(), DiscoverOptions{Sweep: &off, ResolveNames: &off})
	if err != nil {
		t.Fatal(err)
	}
	if result.Swept != nil {
		t.Fatal("sweep was turned off")
	}
}
