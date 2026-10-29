package fleet

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func buildQuery(id uint16, name string, qtype uint16) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], id)
	msg[2] = 0x01 // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	return binary.BigEndian.AppendUint16(msg, 1)
}

// answerA builds a reply with one A record (TTL 120) for a query.
func answerA(query []byte, ip net.IP) []byte {
	q, _ := ParseDNSQuestion(query)
	out := append(header(query, 0, 1), query[12:q.End]...)
	rr := []byte{0xC0, 0x0C}
	rr = binary.BigEndian.AppendUint16(rr, dnsTypeA)
	rr = binary.BigEndian.AppendUint16(rr, 1)
	rr = binary.BigEndian.AppendUint32(rr, 120)
	rr = binary.BigEndian.AppendUint16(rr, 4)
	return append(append(out, rr...), ip.To4()...)
}

func answerIP(t *testing.T, reply []byte) (net.IP, byte) {
	t.Helper()
	if len(reply) < 12 {
		t.Fatalf("short reply %x", reply)
	}
	rcode := reply[3] & 0x0F
	if binary.BigEndian.Uint16(reply[6:8]) == 0 {
		return nil, rcode
	}
	end, _ := parseReplyQuestionEnd(reply)
	nameEnd, _ := skipName(reply, end)
	rdlen := int(binary.BigEndian.Uint16(reply[nameEnd+8 : nameEnd+10]))
	return net.IP(reply[nameEnd+10 : nameEnd+10+rdlen]), rcode
}

type fakeDoH struct {
	mu      sync.Mutex
	queries []string
	down    bool
}

func (f *fakeDoH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	down := f.down
	f.mu.Unlock()
	if down {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	body, _ := io.ReadAll(r.Body)
	q, err := ParseDNSQuestion(body)
	if err != nil || r.Header.Get("Content-Type") != "application/dns-message" {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.queries = append(f.queries, q.Name)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/dns-message")
	if strings.HasSuffix(q.Name, "evil.test.") {
		w.Header().Set("X-Fenrir-Dns-Action", "block")
		w.Header().Set("X-Fenrir-Dns-Reason", "blocklist hagezi-tif-mini")
		_, _ = w.Write(SinkholeAnswer(body, q, net.IPv4zero))
		return
	}
	w.Header().Set("X-Fenrir-Dns-Action", "allow")
	_, _ = w.Write(answerA(body, net.IPv4(93, 184, 216, 34)))
}

func (f *fakeDoH) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queries)
}

func exchange(t *testing.T, addr string, query []byte) []byte {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func TestDNSProxyBlocksCachesAndSurvivesCloudOutage(t *testing.T) {
	doh := &fakeDoH{}
	server := httptest.NewServer(doh)
	defer server.Close()
	var blocks []string
	var mu sync.Mutex
	proxy := &DNSProxy{Listen: "127.0.0.1:0", DoHURL: server.URL + "/dns/tok/dns-query", Sinkhole: net.ParseIP("127.77.0.1"),
		OnBlock: func(domain, reason string, cached bool) {
			mu.Lock()
			blocks = append(blocks, domain+"|"+reason+"|"+map[bool]string{true: "cached", false: "cloud"}[cached])
			mu.Unlock()
		}}
	if err := proxy.Start(); err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	ip, rcode := answerIP(t, exchange(t, proxy.Listen, buildQuery(1, "c2.evil.test", dnsTypeA)))
	if rcode != 0 || !ip.Equal(net.ParseIP("127.77.0.1")) {
		t.Fatalf("blocked name should resolve to the loopback sinkhole, got %v rcode %d", ip, rcode)
	}
	reply := exchange(t, proxy.Listen, buildQuery(2, "example.test", dnsTypeA))
	if binary.BigEndian.Uint16(reply[0:2]) != 2 {
		t.Fatal("reply must carry the query ID")
	}
	if ip, _ := answerIP(t, reply); !ip.Equal(net.IPv4(93, 184, 216, 34)) {
		t.Fatalf("allowed name: %v", ip)
	}
	before := doh.count()
	exchange(t, proxy.Listen, buildQuery(3, "example.test", dnsTypeA))
	if doh.count() != before {
		t.Fatal("a cached answer should not go back to the cloud")
	}

	// The cloud goes away: the cached block still applies (offline protection) ...
	doh.mu.Lock()
	doh.down = true
	doh.mu.Unlock()
	if ip, _ := answerIP(t, exchange(t, proxy.Listen, buildQuery(4, "c2.evil.test", dnsTypeA))); !ip.Equal(net.ParseIP("127.77.0.1")) {
		t.Fatalf("cached block lost while offline: %v", ip)
	}
	mu.Lock()
	if len(blocks) != 2 || blocks[0] != "c2.evil.test|blocklist hagezi-tif-mini|cloud" || !strings.HasSuffix(blocks[1], "|cached") {
		t.Fatalf("block notifications: %v", blocks)
	}
	mu.Unlock()

	// ... unknown names fail closed when configured ...
	proxy.FailClosed = true
	if _, rcode := answerIP(t, exchange(t, proxy.Listen, buildQuery(5, "unknown.test", dnsTypeA))); rcode != 5 {
		t.Fatalf("fail-closed should REFUSE, rcode %d", rcode)
	}
	// ... and otherwise use the previous system resolver.
	fallback, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fallback.Close()
	go func() {
		buf := make([]byte, 512)
		n, addr, err := fallback.ReadFrom(buf)
		if err == nil {
			_, _ = fallback.WriteTo(answerA(buf[:n], net.IPv4(10, 0, 0, 9)), addr)
		}
	}()
	proxy.FailClosed = false
	proxy.Fallback = []string{fallback.LocalAddr().String()}
	if ip, _ := answerIP(t, exchange(t, proxy.Listen, buildQuery(6, "intranet.test", dnsTypeA))); !ip.Equal(net.IPv4(10, 0, 0, 9)) {
		t.Fatalf("fail-open fallback: %v", ip)
	}
}

func TestDNSProxyRejectsMalformedQueries(t *testing.T) {
	proxy := &DNSProxy{}
	if reply := proxy.Resolve([]byte{1, 2, 3}); reply != nil {
		t.Fatal("a fragment shorter than a header gets no reply")
	}
	bad := buildQuery(9, "x.test", dnsTypeA)
	bad[12] = 0xC0 // compression pointer in a question is not accepted
	if reply := proxy.Resolve(bad); reply == nil || reply[3]&0x0F != 1 {
		t.Fatalf("expected FORMERR, got %x", reply)
	}
}

func TestSinkholeRecordsHostSNIAndProcess(t *testing.T) {
	var mu sync.Mutex
	var seen []SinkholeConnection
	s := &Sinkhole{Addr: "127.0.0.1", ProcRoot: "/proc", HTTPPort: freePort(t), TLSPort: freePort(t),
		OnConnection: func(c SinkholeConnection) { mu.Lock(); seen = append(seen, c); mu.Unlock() }}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	httpPort, tlsPort := s.BoundPorts()

	req, _ := http.NewRequest("GET", "http://127.0.0.1:"+itoa(httpPort)+"/payload.exe", nil)
	req.Host = "c2.evil.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(page), "c2.evil.test") {
		t.Fatalf("block page: %d %s", resp.StatusCode, page)
	}
	conn, err := tls.Dial("tcp", "127.0.0.1:"+itoa(tlsPort), &tls.Config{ServerName: "login.evil.test", InsecureSkipVerify: true})
	if err == nil {
		conn.Close()
		t.Fatal("the sinkhole must never complete a TLS handshake")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("connections: %+v", seen)
	}
	hosts := map[string]SinkholeConnection{}
	for _, c := range seen {
		hosts[c.Protocol] = c
	}
	if hosts["http"].Host != "c2.evil.test" || hosts["tls"].Host != "login.evil.test" {
		t.Fatalf("hosts: %+v", hosts)
	}
	if _, err := os.Stat("/proc/self/net/tcp"); err == nil && hosts["http"].PID != os.Getpid() {
		t.Fatalf("connection should be attributed to this test process (%d), got %d", os.Getpid(), hosts["http"].PID)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestResolverChangeIsRestored(t *testing.T) {
	if IsMacOS {
		t.Skip("macOS uses networksetup")
	}
	dir := t.TempDir()
	oldConf, oldDropIn, oldUpstream := resolvConfPath, resolvedDropInDir, resolvedUpstreamPath
	defer func() { resolvConfPath, resolvedDropInDir, resolvedUpstreamPath = oldConf, oldDropIn, oldUpstream }()
	resolvConfPath = filepath.Join(dir, "resolv.conf")
	resolvedDropInDir = filepath.Join(dir, "resolved.conf.d")
	resolvedUpstreamPath = filepath.Join(dir, "no-resolved")
	original := "nameserver 192.0.2.53\nnameserver 127.77.0.53\nsearch corp.example\n"
	if err := os.WriteFile(resolvConfPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := systemResolvers("127.77.0.53"); len(got) != 1 || got[0] != "192.0.2.53:53" {
		t.Fatalf("fallback resolvers should exclude the proxy: %v", got)
	}
	state := t.TempDir()
	change, err := pointResolverAt(state, "127.77.0.53")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(resolvConfPath)
	if !strings.Contains(string(data), "nameserver 127.77.0.53") || strings.Contains(string(data), "192.0.2.53") {
		t.Fatalf("resolv.conf: %s", data)
	}
	// A crash leaves the marker; the next start restores the original file.
	_ = change
	restoreStaleResolver(state)
	data, _ = os.ReadFile(resolvConfPath)
	if string(data) != original {
		t.Fatalf("restored resolv.conf: %q", data)
	}
	if _, err := os.Stat(filepath.Join(state, resolverMarker)); !os.IsNotExist(err) {
		t.Fatal("marker should be removed after restoring")
	}

	// systemd-resolved: a drop-in plus a restart, both undone.
	var commands []string
	oldRun := runResolverCommand
	defer func() { runResolverCommand = oldRun }()
	runResolverCommand = func(name string, args ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	resolvedUpstreamPath = filepath.Join(dir, "upstream.conf")
	_ = os.WriteFile(resolvedUpstreamPath, []byte("nameserver 198.51.100.1\n"), 0o644)
	_ = os.Remove(resolvConfPath)
	_ = os.Symlink("../run/systemd/resolve/stub-resolv.conf", resolvConfPath)
	if got := systemResolvers("127.77.0.53"); len(got) != 1 || got[0] != "198.51.100.1:53" {
		t.Fatalf("resolved upstreams: %v", got)
	}
	change, err = pointResolverAt(state, "127.77.0.53")
	if err != nil || change.Mode != "resolved" {
		t.Fatalf("resolved mode: %+v %v", change, err)
	}
	if dropIn, _ := os.ReadFile(filepath.Join(resolvedDropInDir, "90-fenrir-dns-proxy.conf")); !strings.Contains(string(dropIn), "DNS=127.77.0.53") {
		t.Fatalf("drop-in: %s", dropIn)
	}
	if err := change.Restore(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(resolvedDropInDir, "90-fenrir-dns-proxy.conf")); !os.IsNotExist(err) {
		t.Fatal("drop-in should be removed")
	}
	if len(commands) != 2 || commands[0] != "systemctl restart systemd-resolved" {
		t.Fatalf("commands: %v", commands)
	}
}
