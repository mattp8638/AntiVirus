package fleet

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Loopback sinkhole for domains the DNS proxy blocked (policy dns.sinkholeInterception).
//
// Blocked names resolve to a loopback address where this listener accepts the connection the program
// then makes. HTTP gets a block page; TLS is read only as far as the ClientHello's server name and then
// closed (no certificate is presented, so nothing is intercepted or decrypted). Each connection is
// reported with the process that made it, which turns "a DNS lookup was blocked" into "this program
// tried to reach this blocked site".

type SinkholeConnection struct {
	Host     string
	Port     int
	Protocol string // http | tls
	PID      int
	Exe      string
	Cmdline  string
}

func (c SinkholeConnection) ProcessName() string {
	if c.Exe == "" {
		return "A program"
	}
	return filepath.Base(c.Exe)
}

func (c SinkholeConnection) Payload() map[string]interface{} {
	return map[string]interface{}{"destinationHostname": c.Host, "destinationPort": c.Port, "protocol": c.Protocol,
		"pid": c.PID, "processImagePath": c.Exe, "commandLine": c.Cmdline, "verdict": "blocked", "category": "dns-sinkhole"}
}

type Sinkhole struct {
	Addr         string
	ProcRoot     string
	OnConnection func(SinkholeConnection)
	listeners    []net.Listener
	wg           sync.WaitGroup
	once         sync.Once
	// Ports, overridable in tests (binding 80/443 needs root).
	HTTPPort, TLSPort int
}

func (s *Sinkhole) Start() error {
	if s.HTTPPort == 0 {
		s.HTTPPort = 80
	}
	if s.TLSPort == 0 {
		s.TLSPort = 443
	}
	for _, spec := range []struct {
		port  int
		proto string
	}{{s.HTTPPort, "http"}, {s.TLSPort, "tls"}} {
		ln, err := net.Listen("tcp", net.JoinHostPort(s.Addr, strconv.Itoa(spec.port)))
		if err != nil {
			s.Close()
			return err
		}
		s.listeners = append(s.listeners, ln)
		s.wg.Add(1)
		go s.serve(ln, spec.proto)
	}
	return nil
}

// Ports actually bound (useful when tests ask for port 0).
func (s *Sinkhole) BoundPorts() (int, int) {
	if len(s.listeners) < 2 {
		return 0, 0
	}
	return s.listeners[0].Addr().(*net.TCPAddr).Port, s.listeners[1].Addr().(*net.TCPAddr).Port
}

func (s *Sinkhole) Close() {
	s.once.Do(func() {
		for _, ln := range s.listeners {
			ln.Close()
		}
	})
	s.wg.Wait()
}

func (s *Sinkhole) serve(ln net.Listener, proto string) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn, proto)
	}
}

const blockPage = `<!doctype html><html><head><meta charset="utf-8"><title>Blocked by Fenrir</title></head>
<body style="font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;color:#222">
<h1>This site was blocked</h1><p><b>%s</b> is blocked by your organisation's DNS protection because it is
known to be malicious or is in a blocked category.</p><p>If you need it for work, contact your IT support team.</p></body></html>`

func (s *Sinkhole) handle(conn net.Conn, proto string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	record := SinkholeConnection{Protocol: proto}
	if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		record.Port = addr.Port
	}
	if peer, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		record.PID = pidForLocalTCP(s.ProcRoot, peer.IP, peer.Port)
		if record.PID > 0 {
			if info, err := readProc(s.ProcRoot, record.PID); err == nil {
				record.Exe, record.Cmdline = info.Exe, info.Cmdline
			}
		}
	}
	reader := bufio.NewReader(conn)
	if proto == "http" {
		if req, err := http.ReadRequest(reader); err == nil {
			record.Host = strings.ToLower(strings.Split(req.Host, ":")[0])
		}
		body := fmt.Sprintf(blockPage, html.EscapeString(record.Host))
		fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n%s",
			len(body), body)
	} else if hello, err := readClientHello(reader); err == nil {
		record.Host = strings.ToLower(ServerNameFromClientHello(hello))
	}
	if s.OnConnection != nil {
		s.OnConnection(record)
	}
}

func readClientHello(r io.Reader) ([]byte, error) {
	head := make([]byte, 5)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	if head[0] != 0x16 { // handshake record
		return nil, errors.New("not TLS")
	}
	size := int(binary.BigEndian.Uint16(head[3:5]))
	if size > 16384 {
		return nil, errors.New("record too large")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// ServerNameFromClientHello extracts the SNI host name from a ClientHello handshake message.
func ServerNameFromClientHello(msg []byte) string {
	if len(msg) < 4 || msg[0] != 0x01 {
		return ""
	}
	p := 4 + 2 + 32 // handshake header, legacy version, random
	if p >= len(msg) {
		return ""
	}
	p += 1 + int(msg[p]) // session id
	if p+2 > len(msg) {
		return ""
	}
	p += 2 + int(binary.BigEndian.Uint16(msg[p:])) // cipher suites
	if p >= len(msg) {
		return ""
	}
	p += 1 + int(msg[p]) // compression methods
	if p+2 > len(msg) {
		return ""
	}
	end := p + 2 + int(binary.BigEndian.Uint16(msg[p:]))
	p += 2
	for p+4 <= end && end <= len(msg) {
		extType, extLen := binary.BigEndian.Uint16(msg[p:]), int(binary.BigEndian.Uint16(msg[p+2:]))
		p += 4
		if p+extLen > len(msg) {
			return ""
		}
		if extType == 0 && extLen >= 5 { // server_name: list length, type (0 = host), name length, name
			nameLen := int(binary.BigEndian.Uint16(msg[p+3:]))
			if msg[p+2] == 0 && p+5+nameLen <= len(msg) {
				return string(msg[p+5 : p+5+nameLen])
			}
		}
		p += extLen
	}
	return ""
}

// pidForLocalTCP finds the process owning the TCP socket whose local end is ip:port (Linux procfs).
func pidForLocalTCP(procRoot string, ip net.IP, port int) int {
	if IsMacOS || procRoot == "" {
		return 0
	}
	inode := socketInode(filepath.Join(procRoot, "net", "tcp"), ip, port)
	if inode == "" {
		inode = socketInode(filepath.Join(procRoot, "net", "tcp6"), ip, port)
	}
	if inode == "" {
		return 0
	}
	target := "socket:[" + inode + "]"
	for _, pid := range listPIDs(procRoot) {
		fds, err := os.ReadDir(filepath.Join(procRoot, strconv.Itoa(pid), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if link, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "fd", fd.Name())); err == nil && link == target {
				return pid
			}
		}
	}
	return 0
}

func socketInode(path string, ip net.IP, port int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	want := procNetAddress(ip, port)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 10 && strings.EqualFold(fields[1], want) {
			return fields[9]
		}
	}
	return ""
}

// procNetAddress renders ip:port the way /proc/net/tcp does (IPv4 as one little-endian word).
func procNetAddress(ip net.IP, port int) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%02X%02X%02X%02X:%04X", v4[3], v4[2], v4[1], v4[0], port)
	}
	v6 := ip.To16()
	var b strings.Builder
	for i := 0; i < 16; i += 4 {
		b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{v6[i+3], v6[i+2], v6[i+1], v6[i]})))
	}
	return fmt.Sprintf("%s:%04X", b.String(), port)
}
