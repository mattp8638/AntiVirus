package fleet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AntiVirus/agent/linux/pkg/reputation"
)

// Local loopback DNS proxy (policy dns.localProxy).
//
// The system resolver points at a loopback address. Each query is forwarded to the device's private
// DoH URL on Fenrir Cloud, which applies policy, threat intel and blocklists and reports its decision
// in X-Fenrir-Dns-Action. Verdicts are cached locally (reputation.DNSLookupCache), so a domain the
// cloud blocked stays blocked while the device is offline. Blocked names resolve to a loopback
// sinkhole (sinkhole.go) that records which process tried to connect.

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
	maxDNSMsg   = 4096
)

// DNSProxy answers DNS over UDP and TCP on one loopback address.
type DNSProxy struct {
	Listen     string        // e.g. 127.77.0.53:53
	DoHURL     string        // the device's /dns/<token>/dns-query URL
	APIKey     string        // sent as X-Device-Api-Key so the cloud can attribute queries
	Fallback   []string      // previous system resolvers ("ip:53"), used when the cloud is unreachable
	FailClosed bool          // refuse uncached names while the cloud is unreachable
	Sinkhole   net.IP        // IPv4 answer for blocked names (loopback sinkhole or 0.0.0.0)
	VerdictTTL time.Duration // how long a cloud verdict is trusted locally
	OnBlock    func(domain, reason string, cached bool)

	Verdicts *reputation.DNSLookupCache
	client   *http.Client
	answers  sync.Map // "qname|qtype" -> cachedAnswer
	udp      net.PacketConn
	tcp      net.Listener
	wg       sync.WaitGroup
	closed   chan struct{}
}

type cachedAnswer struct {
	wire    []byte
	expires time.Time
}

// Start binds the listeners. Returns an error if the address is in use.
func (p *DNSProxy) Start() error {
	if p.Verdicts == nil {
		p.Verdicts = reputation.NewDNSLookupCache()
	}
	if p.client == nil {
		p.client = &http.Client{Timeout: 4 * time.Second, Transport: p.transport()}
	}
	if p.VerdictTTL <= 0 {
		p.VerdictTTL = 30 * time.Minute
	}
	udp, err := net.ListenPacket("udp", p.Listen)
	if err != nil {
		return fmt.Errorf("dns proxy udp %s: %w", p.Listen, err)
	}
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		return fmt.Errorf("dns proxy tcp %s: %w", p.Listen, err)
	}
	p.udp, p.tcp, p.closed = udp, tcp, make(chan struct{})
	p.Listen = udp.LocalAddr().String()
	p.wg.Add(2)
	go p.serveUDP()
	go p.serveTCP()
	return nil
}

// transport dials the DoH host without the system resolver: once the system resolver points at this
// proxy, resolving the cloud's own name through it would loop. Addresses are pinned at start (before the
// resolver changes) and re-resolved through the previous system resolvers if all of them fail.
func (p *DNSProxy) transport() *http.Transport {
	dohHost := ""
	if u, err := url.Parse(p.DoHURL); err == nil {
		dohHost = u.Hostname()
	}
	var (
		pinnedMu sync.Mutex
		pinned   []string
	)
	if dohHost != "" && net.ParseIP(dohHost) == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		pinned, _ = net.DefaultResolver.LookupHost(ctx, dohHost)
		cancel()
	}
	fallbackResolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		for _, server := range p.Fallback {
			if conn, err := d.DialContext(ctx, network, server); err == nil {
				return conn, nil
			}
		}
		return nil, errors.New("no fallback resolver reachable")
	}}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || host != dohHost || net.ParseIP(host) != nil {
			return dialer.DialContext(ctx, network, addr)
		}
		pinnedMu.Lock()
		current := append([]string(nil), pinned...)
		pinnedMu.Unlock()
		for _, ip := range current {
			if conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port)); err == nil {
				return conn, nil
			}
		}
		if fresh, err := fallbackResolver.LookupHost(ctx, host); err == nil {
			pinnedMu.Lock()
			pinned = fresh
			pinnedMu.Unlock()
			for _, ip := range fresh {
				if conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port)); err == nil {
					return conn, nil
				}
			}
		}
		return nil, fmt.Errorf("cannot reach %s", host)
	}
	return base
}

func (p *DNSProxy) Close() {
	if p.closed == nil {
		return
	}
	select {
	case <-p.closed:
		return
	default:
	}
	close(p.closed)
	p.udp.Close()
	p.tcp.Close()
	p.wg.Wait()
}

func (p *DNSProxy) serveUDP() {
	defer p.wg.Done()
	buf := make([]byte, maxDNSMsg)
	for {
		n, addr, err := p.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		go func() {
			if reply := p.Resolve(query); reply != nil {
				_, _ = p.udp.WriteTo(reply, addr)
			}
		}()
	}
}

func (p *DNSProxy) serveTCP() {
	defer p.wg.Done()
	for {
		conn, err := p.tcp.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			for {
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				var size uint16
				if binary.Read(c, binary.BigEndian, &size) != nil || size == 0 {
					return
				}
				query := make([]byte, size)
				if _, err := io.ReadFull(c, query); err != nil {
					return
				}
				reply := p.Resolve(query)
				if reply == nil {
					return
				}
				out := make([]byte, 2+len(reply))
				binary.BigEndian.PutUint16(out, uint16(len(reply)))
				copy(out[2:], reply)
				if _, err := c.Write(out); err != nil {
					return
				}
			}
		}(conn)
	}
}

// Resolve answers one wire-format query.
func (p *DNSProxy) Resolve(query []byte) []byte {
	q, err := ParseDNSQuestion(query)
	if err != nil {
		return dnsError(query, 1) // FORMERR
	}
	domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if v, ok := p.Verdicts.Get(domain); ok && v.Verdict == "block" {
		p.notifyBlock(domain, v.Reason, true)
		return SinkholeAnswer(query, q, p.Sinkhole)
	}
	key := fmt.Sprintf("%s|%d", domain, q.Type)
	if cached, ok := p.answers.Load(key); ok {
		if c := cached.(cachedAnswer); time.Now().Before(c.expires) {
			return withID(c.wire, query)
		}
		p.answers.Delete(key)
	}
	reply, action, reason, err := p.forwardDoH(query)
	if err == nil {
		if action == "block" {
			p.Verdicts.Put(domain, "block", "", reason, int(p.VerdictTTL.Seconds()))
			p.notifyBlock(domain, reason, false)
			return SinkholeAnswer(query, q, p.Sinkhole)
		}
		p.Verdicts.Put(domain, "allow", "", "", int(p.VerdictTTL.Seconds()))
		if ttl := minAnswerTTL(reply); ttl > 0 {
			p.answers.Store(key, cachedAnswer{wire: append([]byte(nil), reply...), expires: time.Now().Add(ttl)})
		}
		return withID(reply, query)
	}
	// The cloud is unreachable. Known-blocked names were answered above; the rest depend on the fail mode.
	if p.FailClosed {
		return dnsError(query, 5) // REFUSED
	}
	for _, server := range p.Fallback {
		if reply, err := exchangeUDP(server, query); err == nil {
			return reply
		}
	}
	return dnsError(query, 2) // SERVFAIL
}

func (p *DNSProxy) notifyBlock(domain, reason string, cached bool) {
	if p.OnBlock != nil {
		p.OnBlock(domain, reason, cached)
	}
}

func (p *DNSProxy) forwardDoH(query []byte) ([]byte, string, string, error) {
	if p.DoHURL == "" {
		return nil, "", "", errors.New("no DoH URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.DoHURL, bytes.NewReader(query))
	if err != nil {
		return nil, "", "", err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	if p.APIKey != "" {
		req.Header.Set("X-Device-Api-Key", p.APIKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", "", fmt.Errorf("doh status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil || len(body) < 12 {
		return nil, "", "", fmt.Errorf("short doh reply")
	}
	return body, resp.Header.Get("X-Fenrir-Dns-Action"), resp.Header.Get("X-Fenrir-Dns-Reason"), nil
}

func exchangeUDP(server string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", server, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, maxDNSMsg)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < 12 || buf[0] != query[0] || buf[1] != query[1] {
		return nil, errors.New("mismatched reply")
	}
	return buf[:n], nil
}

// ---------------------------------------------------------------------------
// Minimal DNS wire handling: one question in, one synthetic answer out.
// ---------------------------------------------------------------------------

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
	End   int // offset just after the question section
}

func ParseDNSQuestion(msg []byte) (DNSQuestion, error) {
	if len(msg) < 12 {
		return DNSQuestion{}, errors.New("short message")
	}
	if msg[2]&0x80 != 0 || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return DNSQuestion{}, errors.New("not a single-question query")
	}
	var labels []string
	i := 12
	for {
		if i >= len(msg) {
			return DNSQuestion{}, errors.New("truncated name")
		}
		l := int(msg[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 != 0 || l > 63 || i+1+l > len(msg) {
			return DNSQuestion{}, errors.New("bad label")
		}
		labels = append(labels, string(msg[i+1:i+1+l]))
		i += 1 + l
	}
	if i+4 > len(msg) || len(labels) == 0 {
		return DNSQuestion{}, errors.New("truncated question")
	}
	return DNSQuestion{Name: strings.Join(labels, ".") + ".", Type: binary.BigEndian.Uint16(msg[i : i+2]),
		Class: binary.BigEndian.Uint16(msg[i+2 : i+4]), End: i + 4}, nil
}

func header(query []byte, rcode byte, answers uint16) []byte {
	h := make([]byte, 12)
	copy(h[0:2], query[0:2])
	h[2] = 0x80 | (query[2] & 0x01) // QR, keep RD
	h[3] = 0x80 | rcode             // RA
	binary.BigEndian.PutUint16(h[4:6], 1)
	binary.BigEndian.PutUint16(h[6:8], answers)
	return h
}

// SinkholeAnswer: A -> sinkhole IPv4, AAAA -> ::1 when the sinkhole is loopback (else ::), others empty.
func SinkholeAnswer(query []byte, q DNSQuestion, sinkhole net.IP) []byte {
	var rdata []byte
	switch q.Type {
	case dnsTypeA:
		if v4 := sinkhole.To4(); v4 != nil {
			rdata = v4
		} else {
			rdata = net.IPv4zero.To4()
		}
	case dnsTypeAAAA:
		rdata = net.IPv6unspecified
		if sinkhole != nil && sinkhole.IsLoopback() {
			rdata = net.IPv6loopback
		}
	}
	count := uint16(0)
	if rdata != nil {
		count = 1
	}
	out := append(header(query, 0, count), query[12:q.End]...)
	if rdata != nil {
		rr := []byte{0xC0, 0x0C}
		rr = binary.BigEndian.AppendUint16(rr, q.Type)
		rr = binary.BigEndian.AppendUint16(rr, 1)
		rr = binary.BigEndian.AppendUint32(rr, 60)
		rr = binary.BigEndian.AppendUint16(rr, uint16(len(rdata)))
		out = append(append(out, rr...), rdata...)
	}
	return out
}

func dnsError(query []byte, rcode byte) []byte {
	if len(query) < 12 {
		return nil
	}
	q, err := ParseDNSQuestion(query)
	if err != nil {
		h := header(query, rcode, 0)
		binary.BigEndian.PutUint16(h[4:6], 0)
		return h
	}
	return append(header(query, rcode, 0), query[12:q.End]...)
}

func withID(reply, query []byte) []byte {
	out := append([]byte(nil), reply...)
	copy(out[0:2], query[0:2])
	return out
}

// minAnswerTTL returns the smallest answer TTL (capped at 5 minutes), or 0 if it cannot be read.
func minAnswerTTL(msg []byte) time.Duration {
	q, err := parseReplyQuestionEnd(msg)
	if err != nil {
		return 0
	}
	answers := int(binary.BigEndian.Uint16(msg[6:8]))
	if answers == 0 || msg[3]&0x0F != 0 {
		return 0
	}
	i, minTTL := q, uint32(300)
	for n := 0; n < answers; n++ {
		end, err := skipName(msg, i)
		if err != nil || end+10 > len(msg) {
			return 0
		}
		ttl := binary.BigEndian.Uint32(msg[end+4 : end+8])
		rdlen := int(binary.BigEndian.Uint16(msg[end+8 : end+10]))
		if ttl < minTTL {
			minTTL = ttl
		}
		i = end + 10 + rdlen
		if i > len(msg) {
			return 0
		}
	}
	return time.Duration(minTTL) * time.Second
}

func parseReplyQuestionEnd(msg []byte) (int, error) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return 0, errors.New("unexpected reply")
	}
	end, err := skipName(msg, 12)
	if err != nil || end+4 > len(msg) {
		return 0, errors.New("bad question")
	}
	return end + 4, nil
}

func skipName(msg []byte, i int) (int, error) {
	for i < len(msg) {
		l := int(msg[i])
		switch {
		case l == 0:
			return i + 1, nil
		case l&0xC0 == 0xC0:
			return i + 2, nil
		default:
			i += 1 + l
		}
	}
	return 0, errors.New("truncated name")
}

// ---------------------------------------------------------------------------
// Agent integration
// ---------------------------------------------------------------------------

type dnsProxyState struct {
	proxy    *DNSProxy
	sinkhole *Sinkhole
	resolver *resolverChange
	config   string
}

// DNS proxy addresses. Linux routes all of 127.0.0.0/8 to loopback; macOS needs lo0 aliases (resolver.go).
var (
	dnsProxyAddr = "127.77.0.53"
	sinkholeAddr = "127.77.0.1"
)

// applyDNSProxy starts, reconfigures or stops the proxy to match policy, and points the system resolver at it.
func (a *Agent) applyDNSProxy() {
	p := a.state.Policy
	enabled := p.ModuleBool("dns", "enabled", true) && p.ModuleBool("dns", "localProxy", false) && a.state.DNSURL != ""
	failClosed := p.ModuleString("dns", "localProxyFailMode", "open") == "closed"
	intercept := p.ModuleBool("dns", "sinkholeInterception", true)
	ttl := time.Duration(maxInt(1, p.ModuleInt("dns", "localCacheMinutes", 30))) * time.Minute
	config := fmt.Sprintf("%v|%v|%v|%v|%s", enabled, failClosed, intercept, ttl, a.state.DNSURL)
	if a.dns != nil && a.dns.config == config {
		return
	}
	a.stopDNSProxy()
	if !enabled {
		return
	}
	if err := ensureLoopbackAliases(dnsProxyAddr, sinkholeAddr); err != nil {
		log.Printf("dns proxy: %v", err)
	}
	state := &dnsProxyState{config: config}
	sinkholeIP := net.IPv4zero
	if intercept {
		sinkhole := &Sinkhole{Addr: sinkholeAddr, ProcRoot: a.cfg.ProcRoot, OnConnection: func(c SinkholeConnection) {
			a.emit("network.sinkhole.connection", "dns-proxy", fmt.Sprintf("%s tried to reach blocked %s", c.ProcessName(), c.Host),
				c.Payload())
		}}
		if err := sinkhole.Start(); err != nil {
			log.Printf("dns sinkhole interception unavailable: %v", err)
		} else {
			state.sinkhole = sinkhole
			sinkholeIP = net.ParseIP(sinkholeAddr)
		}
	}
	proxy := &DNSProxy{Listen: dnsProxyAddr + ":53", DoHURL: a.state.DNSURL, APIKey: a.state.APIKey,
		Fallback:   systemResolvers(dnsProxyAddr),
		FailClosed: failClosed, Sinkhole: sinkholeIP, VerdictTTL: ttl,
		OnBlock: func(domain, reason string, cached bool) {
			a.emit("dns.blocked", "dns-proxy", "Blocked DNS lookup "+domain,
				map[string]interface{}{"queryName": domain, "reason": reason, "verdict": "block", "offline": cached})
		}}
	if startErr := proxy.Start(); startErr != nil {
		log.Printf("%v", startErr)
		if state.sinkhole != nil {
			state.sinkhole.Close()
		}
		a.emit("dns.proxy.failed", "dns-proxy", "Local DNS proxy could not start", map[string]interface{}{"error": startErr.Error()})
		return
	}
	// Only now that the proxy answers is the system resolver pointed at it.
	change, err := pointResolverAt(a.cfg.StateDir, dnsProxyAddr)
	if err != nil {
		log.Printf("dns proxy: system resolver not changed: %v", err)
	}
	state.proxy, state.resolver = proxy, change
	a.dns = state
	a.emit("dns.proxy.started", "dns-proxy", "Local DNS proxy on "+proxy.Listen,
		map[string]interface{}{"listen": proxy.Listen, "failMode": map[bool]string{true: "closed", false: "open"}[failClosed],
			"interception": state.sinkhole != nil, "resolverManaged": change != nil})
}

func (a *Agent) stopDNSProxy() {
	if a.dns == nil {
		restoreStaleResolver(a.cfg.StateDir)
		return
	}
	if a.dns.resolver != nil {
		if err := a.dns.resolver.Restore(); err != nil {
			log.Printf("dns proxy: restoring the system resolver failed: %v", err)
		}
	}
	if a.dns.proxy != nil {
		a.dns.proxy.Close()
	}
	if a.dns.sinkhole != nil {
		a.dns.sinkhole.Close()
	}
	a.dns = nil
}
