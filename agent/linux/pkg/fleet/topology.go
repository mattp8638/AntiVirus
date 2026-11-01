package fleet

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Network topology discovery (command network.discover; cloud: topology.py).
//
// Reports the device's own interfaces, default gateway and the neighbours it can see: the ARP/neighbour
// table, optionally refreshed by a short TCP sweep of its own private subnets. The sweep only touches
// private (RFC 1918, CGNAT) IPv4 ranges, at most 1024 addresses, with short timeouts, and records which
// common ports answered so the cloud can tell printers, servers and network gear apart. It never scans
// public addresses or anything outside the device's own subnets.

type DiscoverOptions struct {
	Sweep          *bool `json:"sweep"`
	Ports          []int `json:"ports"`
	TimeoutMs      int   `json:"timeoutMs"`
	MaxHosts       int   `json:"maxHosts"`
	ResolveNames   *bool `json:"resolveNames"`
	TimeoutSeconds int   `json:"timeoutSeconds"`
}

type TopologyInterface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	Addresses []string `json:"addresses"`
}

type TopologyNeighbor struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	OpenPorts []int  `json:"openPorts,omitempty"`
	Source    string `json:"source"`
}

type TopologyResult struct {
	Interfaces []TopologyInterface `json:"interfaces"`
	Gateway    string              `json:"gateway,omitempty"`
	Neighbors  []TopologyNeighbor  `json:"neighbors"`
	Swept      []string            `json:"swept"`
	Truncated  bool                `json:"truncated"`
}

var DefaultDiscoveryPorts = []int{22, 23, 53, 80, 135, 139, 443, 445, 515, 554, 631, 3389, 5900, 8080, 8443, 9100, 16992, 16993}

var privateRanges = func() []*net.IPNet {
	var out []*net.IPNet
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"} {
		_, n, _ := net.ParseCIDR(cidr)
		out = append(out, n)
	}
	return out
}()

// IsPrivateIPv4 reports whether an address may be swept.
func IsPrivateIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	for _, n := range privateRanges {
		if n.Contains(v4) {
			return true
		}
	}
	return false
}

// SweepTargets lists the host addresses of a private subnet, narrowed to the /24 around self when larger
// than maxHosts. The device's own address, network and broadcast addresses are skipped.
func SweepTargets(self net.IP, network *net.IPNet, maxHosts int) []net.IP {
	v4 := self.To4()
	if v4 == nil || !IsPrivateIPv4(v4) {
		return nil
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil
	}
	if 1<<(32-ones) > maxHosts+2 {
		network = &net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}
		ones = 24
	}
	base := network.IP.To4()
	size := 1 << (32 - ones)
	var out []net.IP
	for i := 1; i < size-1; i++ {
		n := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
		n += uint32(i)
		ip := net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		if !ip.Equal(v4) {
			out = append(out, ip)
		}
	}
	return out
}

// ParseLinuxARP reads /proc/net/arp; incomplete entries (flags 0x0) are skipped.
func ParseLinuxARP(data string) []TopologyNeighbor {
	var out []TopologyNeighbor
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) < 6 || f[0] == "IP" || f[2] == "0x0" || f[3] == "00:00:00:00:00:00" {
			continue
		}
		out = append(out, TopologyNeighbor{IP: f[0], MAC: strings.ToLower(f[3]), Source: "arp"})
	}
	return out
}

// ParseBSDARP reads `arp -an` output: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]".
func ParseBSDARP(data string) []TopologyNeighbor {
	var out []TopologyNeighbor
	for _, line := range strings.Split(data, "\n") {
		open, closeIdx := strings.Index(line, "("), strings.Index(line, ")")
		at := strings.Index(line, " at ")
		if open < 0 || closeIdx < open || at < 0 {
			continue
		}
		mac := strings.Fields(line[at+4:])
		if len(mac) == 0 || strings.Contains(mac[0], "incomplete") {
			continue
		}
		out = append(out, TopologyNeighbor{IP: line[open+1 : closeIdx], MAC: normaliseMAC(mac[0]), Source: "arp"})
	}
	return out
}

// normaliseMAC pads BSD's short octets ("0:1b:2c") to aa:bb:cc form.
func normaliseMAC(mac string) string {
	parts := strings.Split(strings.ToLower(mac), ":")
	if len(parts) != 6 {
		return strings.ToLower(mac)
	}
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}

// ParseLinuxGateway reads the default route from /proc/net/route (little-endian hex).
func ParseLinuxGateway(data string) string {
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) >= 3 && f[1] == "00000000" && len(f[2]) == 8 && f[2] != "00000000" {
			var b [4]byte
			for i := 0; i < 4; i++ {
				var v byte
				for _, c := range f[2][i*2 : i*2+2] {
					v <<= 4
					switch {
					case c >= '0' && c <= '9':
						v |= byte(c - '0')
					case c >= 'A' && c <= 'F':
						v |= byte(c-'A') + 10
					case c >= 'a' && c <= 'f':
						v |= byte(c-'a') + 10
					}
				}
				b[3-i] = v
			}
			return net.IPv4(b[0], b[1], b[2], b[3]).String()
		}
	}
	return ""
}

func localInterfaces() ([]TopologyInterface, []struct {
	ip  net.IP
	net *net.IPNet
}) {
	var out []TopologyInterface
	var subnets []struct {
		ip  net.IP
		net *net.IPNet
	}
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		entry := TopologyInterface{Name: iface.Name, MAC: strings.ToLower(iface.HardwareAddr.String())}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			entry.Addresses = append(entry.Addresses, ipnet.String())
			if IsPrivateIPv4(ipnet.IP) {
				subnets = append(subnets, struct {
					ip  net.IP
					net *net.IPNet
				}{ipnet.IP, ipnet})
			}
		}
		if len(entry.Addresses) > 0 {
			out = append(out, entry)
		}
	}
	return out, subnets
}

// sweep connects to each target/port with a short timeout; returns open ports per address.
func sweep(ctx context.Context, targets []net.IP, ports []int, timeout time.Duration,
	dial func(ctx context.Context, network, address string) (net.Conn, error)) map[string][]int {
	open := map[string][]int{}
	var mu sync.Mutex
	work := make(chan [2]interface{})
	var wg sync.WaitGroup
	for w := 0; w < 64; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range work {
				ip, port := item[0].(net.IP), item[1].(int)
				c, cancel := context.WithTimeout(ctx, timeout)
				conn, err := dial(c, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
				cancel()
				if err == nil {
					conn.Close()
					mu.Lock()
					open[ip.String()] = append(open[ip.String()], port)
					mu.Unlock()
				}
			}
		}()
	}
feed:
	for _, ip := range targets {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				break feed
			case work <- [2]interface{}{ip, port}:
			}
		}
	}
	close(work)
	wg.Wait()
	for ip := range open {
		sort.Ints(open[ip])
	}
	return open
}

// Discover runs network.discover.
func (a *Agent) Discover(ctx context.Context, opts DiscoverOptions) (TopologyResult, error) {
	if opts.TimeoutSeconds <= 0 || opts.TimeoutSeconds > 600 {
		opts.TimeoutSeconds = 180
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(opts.TimeoutSeconds)*time.Second)
	defer cancel()
	if opts.MaxHosts <= 0 || opts.MaxHosts > 1024 {
		opts.MaxHosts = 1024
	}
	if len(opts.Ports) == 0 {
		opts.Ports = DefaultDiscoveryPorts
	}
	if opts.TimeoutMs <= 0 || opts.TimeoutMs > 3000 {
		opts.TimeoutMs = 400
	}
	result := TopologyResult{}
	ifaces, subnets := localInterfaces()
	result.Interfaces = ifaces
	result.Gateway = defaultGateway(a.cfg.ProcRoot)
	open := map[string][]int{}
	if opts.Sweep == nil || *opts.Sweep {
		var dialer net.Dialer
		budget := opts.MaxHosts
		for _, s := range subnets {
			targets := SweepTargets(s.ip, s.net, opts.MaxHosts)
			if len(targets) > budget {
				targets, result.Truncated = targets[:budget], true
			}
			budget -= len(targets)
			if len(targets) == 0 {
				continue
			}
			result.Swept = append(result.Swept, s.net.String())
			for ip, ports := range sweep(ctx, targets, opts.Ports, time.Duration(opts.TimeoutMs)*time.Millisecond, dialer.DialContext) {
				open[ip] = ports
			}
		}
	}
	neighbours := map[string]TopologyNeighbor{}
	for _, n := range readNeighbours(a.cfg.ProcRoot) {
		neighbours[n.IP] = n
	}
	for ip, ports := range open {
		n := neighbours[ip]
		if n.IP == "" {
			n = TopologyNeighbor{IP: ip, Source: "sweep"}
		}
		n.OpenPorts = ports
		neighbours[ip] = n
	}
	resolve := opts.ResolveNames == nil || *opts.ResolveNames
	for ip, n := range neighbours {
		if resolve && ctx.Err() == nil {
			c, cancelLookup := context.WithTimeout(ctx, 500*time.Millisecond)
			if names, err := net.DefaultResolver.LookupAddr(c, ip); err == nil && len(names) > 0 {
				n.Hostname = strings.TrimSuffix(names[0], ".")
			}
			cancelLookup()
		}
		result.Neighbors = append(result.Neighbors, n)
		neighbours[ip] = n
	}
	sort.Slice(result.Neighbors, func(i, j int) bool { return result.Neighbors[i].IP < result.Neighbors[j].IP })
	return result, nil
}

func readNeighbours(procRoot string) []TopologyNeighbor {
	if IsMacOS {
		out, err := exec.Command("arp", "-an").Output()
		if err != nil {
			return nil
		}
		return ParseBSDARP(string(out))
	}
	data, err := os.ReadFile(filepath.Join(procRoot, "net", "arp"))
	if err != nil {
		return nil
	}
	return ParseLinuxARP(string(data))
}

func defaultGateway(procRoot string) string {
	if IsMacOS {
		out, err := exec.Command("route", "-n", "get", "default").Output()
		if err != nil {
			return ""
		}
		for _, line := range strings.Split(string(out), "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "gateway:" {
				return f[1]
			}
		}
		return ""
	}
	data, err := os.ReadFile(filepath.Join(procRoot, "net", "route"))
	if err != nil {
		return ""
	}
	return ParseLinuxGateway(string(data))
}

// DiscoverContext runs the network.discover command.
func (a *Agent) DiscoverContext(ctx context.Context, raw string) (map[string]interface{}, error) {
	var opts DiscoverOptions
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &opts); err != nil {
			return nil, err
		}
	}
	result, err := a.Discover(ctx, opts)
	if err != nil {
		return nil, err
	}
	data, _ := json.Marshal(result)
	var out map[string]interface{}
	_ = json.Unmarshal(data, &out)
	return map[string]interface{}{"topology": out}, nil
}
