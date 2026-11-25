"""VULN-13: firewall configuration assessment from an uploaded export."""
import base64

from fenrir_cloud import db as database
from fenrir_cloud.models import AuditLog, FirewallAssessment

URL = "/api/console/firewall-assessments"

WEAK_PFSENSE = b"""<?xml version="1.0"?>
<pfsense>
  <version>23.3</version>
  <system>
    <webgui><protocol>http</protocol><nohttpreferercheck/></webgui>
    <ssh><enable>enabled</enable></ssh>
    <user><name>admin</name><bcrypt-hash>$2y$10$secrethash</bcrypt-hash></user>
  </system>
  <filter>
    <rule><type>pass</type><interface>wan</interface><source><any/></source><destination><any/></destination><descr>temp allow</descr></rule>
    <rule><type>pass</type><interface>wan</interface><source><any/></source><destination><network>(self)</network><port>443</port></destination><descr>GUI</descr></rule>
    <rule><type>pass</type><interface>lan</interface><source><any/></source><destination><any/></destination></rule>
    <rule><type>pass</type><interface>wan</interface><disabled/><source><any/></source><destination><any/></destination></rule>
  </filter>
  <snmpd><enable/><rocommunity>public</rocommunity></snmpd>
  <syslog></syslog>
  <installedpackages><miniupnpd><config><enable>on</enable></config></miniupnpd></installedpackages>
  <ipsec><phase1><descr>Branch</descr><encryption><item><encryption-algorithm><name>3des</name></encryption-algorithm>
    <hash-algorithm>sha1</hash-algorithm><dhgroup>2</dhgroup></item></encryption>
    <authentication_method>pre_shared_key</authentication_method><pre-shared-key>tinykey9</pre-shared-key></phase1></ipsec>
  <openvpn><openvpn-server><description>Remote</description><crypto>BF-CBC</crypto></openvpn-server></openvpn>
</pfsense>"""

GOOD_OPNSENSE = b"""<?xml version="1.0"?>
<opnsense>
  <system><webgui><protocol>https</protocol></webgui><ssh><enabled>enabled</enabled><passwordauth>0</passwordauth></ssh></system>
  <filter><rule><type>block</type><interface>wan</interface><source><any/></source><destination><any/></destination></rule></filter>
  <syslog><destinations><destination><hostname>10.0.0.5</hostname></destination></destinations></syslog>
</opnsense>"""


def upload(client, admin, tenant, data, **extra):
    return client.post(URL, headers=admin, json={"tenantId": tenant["id"], "label": "HQ firewall",
                                                 "contentBase64": base64.b64encode(data).decode(), **extra})


def test_weak_pfsense_configuration(client, admin, tenant):
    r = upload(client, admin, tenant, WEAK_PFSENSE, firmware="2.6.0", minimumFirmware="2.7.2")
    assert r.status_code == 200, r.text
    out = r.json()
    checks = [f["check"] for f in out["findings"]]
    assert out["vendor"] == "pfsense" and out["findings"][0]["severity"] == "critical" and checks[0] == "wan-any-any"
    for c in ("wan-management", "gui-http", "ssh-passwords", "snmp-community", "remote-logging", "upnp", "ipsec-crypto", "openvpn-crypto",
              "disabled-rules", "firmware"):
        assert c in checks, c
    ipsec = next(f for f in out["findings"] if f["check"] == "ipsec-crypto" and "weak" in f["title"])
    assert "3des" in ipsec["title"] and "sha1" in ipsec["title"] and "DH group 2" in ipsec["title"]
    assert sum(1 for f in out["findings"] if f["check"] == "wan-any-any") == 1  # the LAN and disabled rules are not WAN findings
    assert out["firmware"] == {"version": "2.6.0", "minimum": "2.7.2", "status": "checked"}
    assert len(out["fileSha256"]) == 64
    with database.session_factory()() as db:
        row = db.get(FirewallAssessment, out["id"])
        stored = str(row.findings) + str(row.summary) + str([a.details for a in db.query(AuditLog).all()])
        assert "secrethash" not in stored and "tinykey9" not in stored  # the file's secrets are never kept


def test_sound_opnsense_configuration_and_untested_scope(client, admin, tenant):
    out = upload(client, admin, tenant, GOOD_OPNSENSE).json()
    assert out["vendor"] == "opnsense" and out["findings"] == []
    assert {u["check"] for u in out["untested"]} == {"firmware", "passwords", "live state"}
    assert out["firmware"]["status"] == "not checked"
    listed = client.get(URL, headers=admin, params={"tenantId": tenant["id"]}).json()
    assert listed[0]["id"] == out["id"]


def test_unsupported_and_hostile_files_are_refused(client, admin, tenant):
    r = upload(client, admin, tenant, b"config system global\n set hostname FGT\nend\n")
    assert r.status_code == 400 and "FortiGate" in r.json()["detail"]
    bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><pfsense>&a;</pfsense>'
    r = upload(client, admin, tenant, bomb)
    assert r.status_code == 400 and "DOCTYPE" in r.json()["detail"]
    r = client.post(URL, headers=admin, json={"tenantId": tenant["id"], "contentBase64": "not base64!!"})
    assert r.status_code == 400
    caps = client.get(URL + "/capabilities", headers=admin).json()
    assert set(caps["vendors"]) == {"pfsense", "opnsense"} and "SonicWall" in caps["unsupported"]
