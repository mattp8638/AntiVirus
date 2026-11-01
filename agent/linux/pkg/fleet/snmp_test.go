package fleet

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

type fakeSwitch struct {
	get   []gosnmp.SnmpPDU
	walks map[string][]gosnmp.SnmpPDU
}

func (f fakeSwitch) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	if f.get == nil {
		return nil, errors.New("timeout")
	}
	return &gosnmp.SnmpPacket{Variables: f.get}, nil
}

func (f fakeSwitch) BulkWalkAll(root string) ([]gosnmp.SnmpPDU, error) { return f.walks[root], nil }

func snmpStr(oid, v string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: []byte(v)}
}
func snmpNum(oid string, v int) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Integer, Value: v}
}
func snmpRaw(oid string, b ...byte) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: b}
}

// A 24-port access switch: a PC on Gi1/0/5 (VLAN 10), an uplink on Gi1/0/24 to the core with LLDP, ARP for the PC.
func accessSwitch() fakeSwitch {
	return fakeSwitch{
		get: []gosnmp.SnmpPDU{snmpStr(oidSysName, "SW-ACCESS-1"), snmpStr(oidSysDescr, "Cisco IOS Software, C2960X"),
			snmpRaw(oidBridgeAddress, 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e)},
		walks: map[string][]gosnmp.SnmpPDU{
			oidIfName:          {snmpStr(oidIfName+".10005", "Gi1/0/5"), snmpStr(oidIfName+".10024", "Gi1/0/24")},
			oidBasePortIfIndex: {snmpNum(oidBasePortIfIndex+".5", 10005), snmpNum(oidBasePortIfIndex+".24", 10024)},
			oidQTpFdbPort: {snmpNum(oidQTpFdbPort+".10.170.187.204.0.0.1", 5), snmpNum(oidQTpFdbPort+".1.0.80.86.1.2.3", 24),
				snmpNum(oidQTpFdbPort+".1.255.255.255.255.255.255", 24)},
			oidLldpRemChassis: {snmpRaw(oidLldpRemChassis+".0.24.1", 0x00, 0x99, 0x88, 0x77, 0x66, 0x55)},
			oidLldpRemPortID:  {snmpStr(oidLldpRemPortID+".0.24.1", "Te1/0/1")},
			oidLldpRemSysName: {snmpStr(oidLldpRemSysName+".0.24.1", "SW-CORE")},
			oidLldpLocPortID:  {snmpStr(oidLldpLocPortID+".24", "Gi1/0/24")},
			oidIPNetToMedia:   {snmpRaw(oidIPNetToMedia+".1.192.168.10.50", 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01), snmpRaw(oidIPNetToMedia+".1.8.8.8.8", 1, 2, 3, 4, 5, 6)},
		},
	}
}

func TestReadSwitchParsesIdentityFDBLLDPAndARP(t *testing.T) {
	r := ReadSwitch(accessSwitch(), "192.168.10.2")
	if r.Error != "" || r.SysName != "SW-ACCESS-1" || r.BridgeMAC != "00:1a:2b:3c:4d:5e" {
		t.Fatalf("identity: %+v", r)
	}
	if r.Ports["10005"] != "Gi1/0/5" || r.BridgePorts["5"] != "10005" {
		t.Fatalf("ports: %v %v", r.Ports, r.BridgePorts)
	}
	if len(r.FDB) != 2 || r.FDB[0] != (FdbEntry{MAC: "aa:bb:cc:00:00:01", BridgePort: "5", VLAN: 10}) {
		t.Fatalf("fdb (broadcast must be dropped): %+v", r.FDB)
	}
	if len(r.LLDP) != 1 || r.LLDP[0].RemoteSysName != "SW-CORE" || r.LLDP[0].RemoteChassis != "00:99:88:77:66:55" ||
		r.LLDP[0].RemotePort != "Te1/0/1" || r.LLDP[0].LocalPortName != "Gi1/0/24" {
		t.Fatalf("lldp: %+v", r.LLDP)
	}
	if len(r.ARP) != 1 || r.ARP[0] != (ArpEntry{IP: "192.168.10.50", MAC: "aa:bb:cc:00:00:01"}) {
		t.Fatalf("arp (public addresses dropped): %+v", r.ARP)
	}
}

func TestReadSwitchFallsBackToClassicBridgeTableAndReportsSilence(t *testing.T) {
	sw := accessSwitch()
	delete(sw.walks, oidQTpFdbPort)
	sw.walks[oidTpFdbPort] = []gosnmp.SnmpPDU{snmpNum(oidTpFdbPort+".170.187.204.0.0.2", 5)}
	if r := ReadSwitch(sw, "10.0.0.2"); len(r.FDB) != 1 || r.FDB[0].MAC != "aa:bb:cc:00:00:02" || r.FDB[0].VLAN != 0 {
		t.Fatalf("classic fdb: %+v", r.FDB)
	}
	if r := ReadSwitch(fakeSwitch{}, "10.0.0.3"); !strings.Contains(r.Error, "no SNMP answer") {
		t.Fatalf("silent switch: %+v", r)
	}
}

func TestSnmpOnlyQueriesPrivateAddressesWithValidCredentials(t *testing.T) {
	for _, c := range []struct {
		host string
		cred SnmpCredential
		want string
	}{
		{"8.8.8.8", SnmpCredential{Version: "2c", Community: "public"}, "not a private"},
		{"10.0.0.1", SnmpCredential{Version: "2c"}, "community"},
		{"10.0.0.1", SnmpCredential{Version: "3"}, "username"},
		{"10.0.0.1", SnmpCredential{Version: "1"}, "unsupported"},
	} {
		if _, err := newSnmpSession(c.host, c.cred, time.Second); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %+v: want %q, got %v", c.host, c.cred, c.want, err)
		}
	}
	g, err := newSnmpSession("10.0.0.1", SnmpCredential{Version: "3", Username: "fenrir", AuthProtocol: "SHA256", AuthPassword: "a-long-auth",
		PrivProtocol: "AES", PrivPassword: "a-long-priv"}, time.Second)
	if err != nil || g.MsgFlags != gosnmp.AuthPriv || g.Version != gosnmp.Version3 {
		t.Fatalf("v3 authPriv: %v %+v", err, g)
	}
	reports := QuerySwitches(context.Background(), []SnmpCredential{{CredentialID: "c1", Version: "2c", Community: "x", Hosts: []string{"1.1.1.1"}}}, time.Second)
	if len(reports) != 1 || !strings.Contains(reports[0].Error, "not a private") || reports[0].CredentialID != "c1" {
		t.Fatalf("public host must be refused, not queried: %+v", reports)
	}
}
