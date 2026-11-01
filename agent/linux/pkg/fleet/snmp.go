package fleet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Switch-port topology over SNMP (network.discover with "snmp": true; cloud: topology.py).
//
// The probe agent reads, from each switch or router it is given: its name and description, its bridge MAC, its
// port names, the bridge forwarding table (which MAC address was learned on which port, VLAN-aware where the
// switch supports Q-BRIDGE-MIB), its LLDP neighbours (which switch/AP is on the far end of a port) and its ARP
// table (which IP belongs to which MAC). The cloud turns that into "device X is on switch Y port Z".
//
// Credentials are never in the command payload: the agent fetches them for this one command from the cloud.
// Only private IPv4 addresses are queried, read-only, with GET/GETBULK.

const (
	oidSysDescr        = ".1.3.6.1.2.1.1.1.0"
	oidSysName         = ".1.3.6.1.2.1.1.5.0"
	oidBridgeAddress   = ".1.3.6.1.2.1.17.1.1.0"
	oidIfName          = ".1.3.6.1.2.1.31.1.1.1.1"
	oidIfDescr         = ".1.3.6.1.2.1.2.2.1.2"
	oidBasePortIfIndex = ".1.3.6.1.2.1.17.1.4.1.2"
	oidTpFdbPort       = ".1.3.6.1.2.1.17.4.3.1.2"
	oidQTpFdbPort      = ".1.3.6.1.2.1.17.7.1.2.2.1.2"
	oidLldpLocPortID   = ".1.0.8802.1.1.2.1.3.7.1.3"
	oidLldpLocPortDesc = ".1.0.8802.1.1.2.1.3.7.1.4"
	oidLldpRemChassis  = ".1.0.8802.1.1.2.1.4.1.1.5"
	oidLldpRemPortID   = ".1.0.8802.1.1.2.1.4.1.1.7"
	oidLldpRemPortDesc = ".1.0.8802.1.1.2.1.4.1.1.8"
	oidLldpRemSysName  = ".1.0.8802.1.1.2.1.4.1.1.9"
	oidIPNetToMedia    = ".1.3.6.1.2.1.4.22.1.2"

	maxSnmpHosts   = 64
	maxWalkEntries = 20000
)

// SnmpCredential is what the cloud releases for one discovery command.
type SnmpCredential struct {
	CredentialID string   `json:"credentialId"`
	Version      string   `json:"version"` // "2c" or "3"
	Community    string   `json:"community,omitempty"`
	Username     string   `json:"username,omitempty"`
	AuthProtocol string   `json:"authProtocol,omitempty"` // SHA, SHA256, SHA512, MD5
	AuthPassword string   `json:"authPassword,omitempty"`
	PrivProtocol string   `json:"privProtocol,omitempty"` // AES, AES256, DES
	PrivPassword string   `json:"privPassword,omitempty"`
	Hosts        []string `json:"hosts"`
}

type FdbEntry struct {
	MAC        string `json:"mac"`
	BridgePort string `json:"bridgePort"`
	VLAN       int    `json:"vlan,omitempty"`
}

type LldpNeighbor struct {
	LocalPort      string `json:"localPort"` // LLDP local port number
	LocalPortName  string `json:"localPortName,omitempty"`
	RemoteChassis  string `json:"remoteChassis,omitempty"`
	RemoteSysName  string `json:"remoteSysName,omitempty"`
	RemotePort     string `json:"remotePort,omitempty"`
	RemotePortDesc string `json:"remotePortDesc,omitempty"`
}

type ArpEntry struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

// SwitchReport is one queried switch or router.
type SwitchReport struct {
	Host         string            `json:"host"`
	CredentialID string            `json:"credentialId,omitempty"`
	SysName      string            `json:"sysName,omitempty"`
	SysDescr     string            `json:"sysDescr,omitempty"`
	BridgeMAC    string            `json:"bridgeMac,omitempty"`
	Ports        map[string]string `json:"ports,omitempty"`       // ifIndex -> port name
	BridgePorts  map[string]string `json:"bridgePorts,omitempty"` // bridge port -> ifIndex
	FDB          []FdbEntry        `json:"fdb,omitempty"`
	LLDP         []LldpNeighbor    `json:"lldp,omitempty"`
	ARP          []ArpEntry        `json:"arp,omitempty"`
	Truncated    bool              `json:"truncated,omitempty"`
	Error        string            `json:"error,omitempty"`
}

// snmpSession is the part of gosnmp the walker uses (a fake in tests).
type snmpSession interface {
	Get(oids []string) (*gosnmp.SnmpPacket, error)
	BulkWalkAll(rootOid string) ([]gosnmp.SnmpPDU, error)
}

func newSnmpSession(host string, cred SnmpCredential, timeout time.Duration) (*gosnmp.GoSNMP, error) {
	ip := net.ParseIP(host)
	if ip == nil || !IsPrivateIPv4(ip) {
		return nil, fmt.Errorf("%s is not a private IPv4 address", host)
	}
	g := &gosnmp.GoSNMP{Target: host, Port: 161, Timeout: timeout, Retries: 1, MaxRepetitions: 25, ExponentialTimeout: false}
	switch cred.Version {
	case "2c", "":
		if cred.Community == "" {
			return nil, errors.New("SNMP v2c needs a community")
		}
		g.Version, g.Community = gosnmp.Version2c, cred.Community
	case "3":
		if cred.Username == "" {
			return nil, errors.New("SNMP v3 needs a username")
		}
		usm := &gosnmp.UsmSecurityParameters{UserName: cred.Username}
		level := gosnmp.NoAuthNoPriv
		if cred.AuthPassword != "" {
			level = gosnmp.AuthNoPriv
			usm.AuthenticationPassphrase = cred.AuthPassword
			switch strings.ToUpper(cred.AuthProtocol) {
			case "MD5":
				usm.AuthenticationProtocol = gosnmp.MD5
			case "SHA256":
				usm.AuthenticationProtocol = gosnmp.SHA256
			case "SHA512":
				usm.AuthenticationProtocol = gosnmp.SHA512
			default:
				usm.AuthenticationProtocol = gosnmp.SHA
			}
			if cred.PrivPassword != "" {
				level = gosnmp.AuthPriv
				usm.PrivacyPassphrase = cred.PrivPassword
				switch strings.ToUpper(cred.PrivProtocol) {
				case "DES":
					usm.PrivacyProtocol = gosnmp.DES
				case "AES256":
					usm.PrivacyProtocol = gosnmp.AES256
				default:
					usm.PrivacyProtocol = gosnmp.AES
				}
			}
		}
		g.Version, g.SecurityModel, g.MsgFlags, g.SecurityParameters = gosnmp.Version3, gosnmp.UserSecurityModel, level, usm
	default:
		return nil, fmt.Errorf("unsupported SNMP version %q", cred.Version)
	}
	return g, nil
}

// QuerySwitches reads every host of every credential, sequentially, within the context's deadline.
func QuerySwitches(ctx context.Context, creds []SnmpCredential, timeout time.Duration) []SwitchReport {
	var out []SwitchReport
	seen := map[string]bool{}
	for _, cred := range creds {
		for _, host := range cred.Hosts {
			if len(seen) >= maxSnmpHosts || ctx.Err() != nil {
				return out
			}
			if seen[host] {
				continue
			}
			seen[host] = true
			report := SwitchReport{Host: host, CredentialID: cred.CredentialID}
			g, err := newSnmpSession(host, cred, timeout)
			if err == nil {
				err = g.Connect()
			}
			if err != nil {
				report.Error = err.Error()
				out = append(out, report)
				continue
			}
			report = ReadSwitch(g, host)
			report.CredentialID = cred.CredentialID
			_ = g.Conn.Close()
			out = append(out, report)
		}
	}
	return out
}

// ReadSwitch reads one device's identity, ports, forwarding table, LLDP neighbours and ARP table.
func ReadSwitch(s snmpSession, host string) SwitchReport {
	r := SwitchReport{Host: host, Ports: map[string]string{}, BridgePorts: map[string]string{}}
	packet, err := s.Get([]string{oidSysName, oidSysDescr, oidBridgeAddress})
	if err != nil {
		r.Error = "no SNMP answer: " + err.Error()
		return r
	}
	for _, v := range packet.Variables {
		switch v.Name {
		case oidSysName:
			r.SysName = pduString(v)
		case oidSysDescr:
			r.SysDescr = truncate(pduString(v), 300)
		case oidBridgeAddress:
			r.BridgeMAC = pduMAC(v)
		}
	}
	walk := func(oid string) []gosnmp.SnmpPDU {
		pdus, err := s.BulkWalkAll(oid)
		if err != nil {
			return nil
		}
		if len(pdus) > maxWalkEntries {
			r.Truncated = true
			pdus = pdus[:maxWalkEntries]
		}
		return pdus
	}
	for _, v := range walk(oidIfName) {
		r.Ports[suffix(v.Name, oidIfName)] = pduString(v)
	}
	if len(r.Ports) == 0 {
		for _, v := range walk(oidIfDescr) {
			r.Ports[suffix(v.Name, oidIfDescr)] = pduString(v)
		}
	}
	for _, v := range walk(oidBasePortIfIndex) {
		r.BridgePorts[suffix(v.Name, oidBasePortIfIndex)] = strconv.Itoa(pduInt(v))
	}
	r.FDB = ParseQBridgeFDB(walk(oidQTpFdbPort))
	if len(r.FDB) == 0 {
		r.FDB = ParseBridgeFDB(walk(oidTpFdbPort))
	}
	r.LLDP = ParseLLDP(walk(oidLldpRemChassis), walk(oidLldpRemPortID), walk(oidLldpRemPortDesc), walk(oidLldpRemSysName),
		walk(oidLldpLocPortID), walk(oidLldpLocPortDesc))
	r.ARP = ParseARP(walk(oidIPNetToMedia))
	return r
}

// ParseBridgeFDB: dot1dTpFdbPort, index = 6 MAC octets, value = bridge port.
func ParseBridgeFDB(pdus []gosnmp.SnmpPDU) []FdbEntry {
	var out []FdbEntry
	for _, v := range pdus {
		parts := strings.Split(suffix(v.Name, oidTpFdbPort), ".")
		if mac := macFromOctets(parts); mac != "" && pduInt(v) > 0 {
			out = append(out, FdbEntry{MAC: mac, BridgePort: strconv.Itoa(pduInt(v))})
		}
	}
	return out
}

// ParseQBridgeFDB: dot1qTpFdbPort, index = FDB id (usually the VLAN) then 6 MAC octets.
func ParseQBridgeFDB(pdus []gosnmp.SnmpPDU) []FdbEntry {
	var out []FdbEntry
	for _, v := range pdus {
		parts := strings.Split(suffix(v.Name, oidQTpFdbPort), ".")
		if len(parts) != 7 || pduInt(v) <= 0 {
			continue
		}
		vlan, _ := strconv.Atoi(parts[0])
		if mac := macFromOctets(parts[1:]); mac != "" {
			out = append(out, FdbEntry{MAC: mac, BridgePort: strconv.Itoa(pduInt(v)), VLAN: vlan})
		}
	}
	return out
}

// ParseLLDP joins the remote table (index timeMark.localPort.remIndex) with local port ids.
func ParseLLDP(chassis, portID, portDesc, sysName, locPortID, locPortDesc []gosnmp.SnmpPDU) []LldpNeighbor {
	type key struct{ local, rem string }
	rows := map[key]*LldpNeighbor{}
	var order []key
	get := func(oid, root string) (key, bool) {
		parts := strings.Split(suffix(oid, root), ".")
		if len(parts) < 3 {
			return key{}, false
		}
		k := key{parts[len(parts)-2], parts[len(parts)-1]}
		if rows[k] == nil {
			rows[k] = &LldpNeighbor{LocalPort: k.local}
			order = append(order, k)
		}
		return k, true
	}
	for _, v := range chassis {
		if k, ok := get(v.Name, oidLldpRemChassis); ok {
			rows[k].RemoteChassis = pduIdentifier(v)
		}
	}
	for _, v := range portID {
		if k, ok := get(v.Name, oidLldpRemPortID); ok {
			rows[k].RemotePort = pduIdentifier(v)
		}
	}
	for _, v := range portDesc {
		if k, ok := get(v.Name, oidLldpRemPortDesc); ok {
			rows[k].RemotePortDesc = pduString(v)
		}
	}
	for _, v := range sysName {
		if k, ok := get(v.Name, oidLldpRemSysName); ok {
			rows[k].RemoteSysName = pduString(v)
		}
	}
	local := map[string]string{}
	for _, v := range locPortDesc {
		local[suffix(v.Name, oidLldpLocPortDesc)] = pduString(v)
	}
	for _, v := range locPortID {
		if n := suffix(v.Name, oidLldpLocPortID); local[n] == "" {
			local[n] = pduString(v)
		}
	}
	out := make([]LldpNeighbor, 0, len(order))
	for _, k := range order {
		row := rows[k]
		row.LocalPortName = local[row.LocalPort]
		out = append(out, *row)
	}
	return out
}

// ParseARP: ipNetToMediaPhysAddress, index = ifIndex then 4 IPv4 octets.
func ParseARP(pdus []gosnmp.SnmpPDU) []ArpEntry {
	var out []ArpEntry
	for _, v := range pdus {
		parts := strings.Split(suffix(v.Name, oidIPNetToMedia), ".")
		if len(parts) != 5 {
			continue
		}
		ip := net.ParseIP(strings.Join(parts[1:], "."))
		if mac := pduMAC(v); ip != nil && mac != "" && IsPrivateIPv4(ip) {
			out = append(out, ArpEntry{IP: ip.String(), MAC: mac})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func suffix(name, root string) string {
	return strings.TrimPrefix(strings.TrimPrefix(name, root), ".")
}

func macFromOctets(parts []string) string {
	if len(parts) != 6 {
		return ""
	}
	b := make([]string, 6)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return ""
		}
		b[i] = fmt.Sprintf("%02x", n)
	}
	mac := strings.Join(b, ":")
	if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
		return ""
	}
	return mac
}

func pduBytes(v gosnmp.SnmpPDU) []byte {
	switch b := v.Value.(type) {
	case []byte:
		return b
	case string:
		return []byte(b)
	}
	return nil
}

func pduString(v gosnmp.SnmpPDU) string {
	return strings.TrimSpace(strings.ToValidUTF8(string(pduBytes(v)), ""))
}

func pduMAC(v gosnmp.SnmpPDU) string {
	b := pduBytes(v)
	if len(b) != 6 {
		return ""
	}
	parts := make([]string, 6)
	for i, x := range b {
		parts[i] = strconv.Itoa(int(x))
	}
	return macFromOctets(parts)
}

// pduIdentifier renders an LLDP chassis/port id: a MAC when it is 6 bytes, else text.
func pduIdentifier(v gosnmp.SnmpPDU) string {
	if mac := pduMAC(v); mac != "" {
		return mac
	}
	return pduString(v)
}

func pduInt(v gosnmp.SnmpPDU) int {
	n := gosnmp.ToBigInt(v.Value)
	if n == nil || !n.IsInt64() {
		return 0
	}
	return int(n.Int64())
}

// FetchSnmpCredentials releases the switch credentials for one network.discover command (once, to this device).
func (c *Client) FetchSnmpCredentials(commandID string) ([]SnmpCredential, error) {
	var out struct {
		Credentials []SnmpCredential `json:"credentials"`
	}
	if err := c.do("POST", "/api/v1/devices/"+c.DeviceID+"/commands/"+commandID+"/snmp-credentials", map[string]string{}, &out, nil); err != nil {
		return nil, err
	}
	return out.Credentials, nil
}
