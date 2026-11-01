"""Switch-port topology over SNMP (topology.ingest_switches): which device is on which switch port, which switch
uplinks to which, and safe handling of the switch credentials."""

import json

from conftest import enroll, login
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import Device
from test_documentation_vault import stepup
from test_topology import REPORT, complete, poll

CORE_MAC, ACCESS_MAC = "00:99:88:77:66:55", "00:1a:2b:3c:4d:5e"
PC_MAC, PRINTER_MAC, PHONE_MAC, CAM_MAC = "aa:bb:cc:00:00:60", "aa:bb:cc:00:00:30", "aa:bb:cc:00:00:31", "aa:bb:cc:00:00:32"


def switches(pc_port="5"):
    """An access switch with the PC on Gi1/0/<pc_port>, a desk switch (printer + phone) on Gi1/0/8 and an LLDP uplink
    on Gi1/0/24 to the core. The core sees everything through its Te1/0/1 (facing the access switch) and has a
    camera directly on Gi1/0/3."""
    access = {
        "host": "192.168.10.3", "credentialId": "", "sysName": "SW-ACCESS-1.acme.lan", "sysDescr": "Cisco IOS Software, C2960X",
        "bridgeMac": ACCESS_MAC,
        "ports": {"10005": "Gi1/0/5", "10007": "Gi1/0/7", "10008": "Gi1/0/8", "10024": "Gi1/0/24"},
        "bridgePorts": {"5": "10005", "7": "10007", "8": "10008", "24": "10024"},
        "fdb": [{"mac": PC_MAC, "bridgePort": pc_port, "vlan": 10}, {"mac": PRINTER_MAC, "bridgePort": "8"}, {"mac": PHONE_MAC, "bridgePort": "8"},
                {"mac": CORE_MAC, "bridgePort": "24"}, {"mac": CAM_MAC, "bridgePort": "24"}],
        "lldp": [{"localPort": "24", "localPortName": "Gi1/0/24", "remoteChassis": CORE_MAC, "remoteSysName": "SW-CORE", "remotePort": "Te1/0/1"}],
    }
    core = {
        "host": "192.168.10.2", "credentialId": "", "sysName": "SW-CORE", "sysDescr": "Aruba 6300", "bridgeMac": CORE_MAC,
        "ports": {"1": "Te1/0/1", "3": "Gi1/0/3"}, "bridgePorts": {"1": "1", "3": "3"},
        "fdb": [{"mac": PC_MAC, "bridgePort": "1"}, {"mac": PRINTER_MAC, "bridgePort": "1"}, {"mac": PHONE_MAC, "bridgePort": "1"},
                {"mac": ACCESS_MAC, "bridgePort": "1"}, {"mac": CAM_MAC, "bridgePort": "3"}],
        "lldp": [], "arp": [{"ip": "192.168.10.70", "mac": CAM_MAC}],
    }
    return [access, core]


def setup_probe(client, admin, tenant, platform_os="Ubuntu 22.04", serial="P1"):
    probe = enroll(client, admin, tenant, hostname="ACME-PROBE", os_version=platform_os, serial=serial)
    reply = client.put("/api/console/network/topology/settings", headers=admin,
                       json={"tenantId": tenant["id"], "probeDeviceIds": [probe["deviceId"]], "intervalHours": 24})
    assert reply.status_code == 200, reply.text
    return probe


def add_credential(client, admin, tenant, **extra):
    body = {"tenantId": tenant["id"], "name": "Switches", "version": "2c", "community": "s3cret-ro", "hosts": ["192.168.10.2", "192.168.10.3"], **extra}
    return client.post("/api/console/network/snmp-credentials", headers=stepup(client, admin), json=body)


def discover(client, admin, probe):
    assert client.post("/api/console/network/discover", json={"deviceId": probe["deviceId"]}, headers=admin).json()["queued"] == 1
    return next(c for c in poll(client, probe) if c["type"] == "network.discover")


def test_switch_tables_map_devices_to_ports_and_uplinks(client, admin, tenant):
    probe = setup_probe(client, admin, tenant)
    managed = enroll(client, admin, tenant, hostname="ACME-WS-60", serial="T2")
    with session_factory()() as db:
        db.get(Device, managed["deviceId"]).inventory = {"macAddresses": [PC_MAC], "ipAddresses": ["192.168.10.60"]}
        db.commit()
    cred = add_credential(client, admin, tenant)
    assert cred.status_code == 200, cred.text
    command = discover(client, admin, probe)
    assert json.loads(command["payloadJson"])["snmp"] is True and "s3cret" not in command["payloadJson"]  # never in the payload
    released = client.post(f"/api/v1/devices/{probe['deviceId']}/commands/{command['id']}/snmp-credentials", headers=probe["headers"]).json()
    assert released["credentials"][0]["community"] == "s3cret-ro" and released["credentials"][0]["hosts"] == ["192.168.10.2", "192.168.10.3"]
    report = switches()
    for r in report:
        r["credentialId"] = cred.json()["id"]
    complete(client, probe, command["id"], {"topology": {**REPORT, "switches": report}})

    graph = client.get("/api/console/network/topology", params={"tenant_id": tenant["id"]}, headers=admin).json()
    nodes = {n["id"]: n for n in graph["nodes"] if n["type"] == "node"}
    by_mac = {n["mac"]: n for n in nodes.values() if n.get("mac")}
    access, core = by_mac[ACCESS_MAC], by_mac[CORE_MAC]
    assert access["label"] == "SW-ACCESS-1.acme.lan" and access["kind"] == "network" and core["kind"] == "network"
    pc = by_mac[PC_MAC]
    assert pc["managed"] and pc["connection"] == {"switchId": access["id"], "switch": access["label"], "port": "Gi1/0/5", "kind": "access", "vlan": 10}
    # Printer and phone share Gi1/0/8 (a desk switch): placed there, not on the core's uplink port.
    assert by_mac[PRINTER_MAC]["connection"]["port"] == "Gi1/0/8" and by_mac[PRINTER_MAC]["connection"]["kind"] == "shared"
    assert by_mac[PHONE_MAC]["connection"]["switch"] == access["label"]
    # The camera is on the core directly; its IP comes from the core's ARP table.
    assert by_mac[CAM_MAC]["connection"]["switch"] == "SW-CORE" and by_mac[CAM_MAC]["connection"]["port"] == "Gi1/0/3"
    assert by_mac[CAM_MAC]["ip"] == "192.168.10.70"
    uplinks = [e for e in graph["edges"] if e["kind"] == "uplink"]
    assert {"from": access["id"], "to": core["id"], "kind": "uplink", "port": "Gi1/0/24", "peerPort": "Te1/0/1", "vlan": None} in uplinks
    assert any(e["from"] == core["id"] and e["to"] == access["id"] and e["port"] == "Te1/0/1" for e in uplinks)  # learned MAC
    assert graph["summary"]["switches"] == 2 and graph["summary"]["connected"] >= 4
    access_view = next(s for s in graph["switches"] if s["id"] == access["id"])
    assert access_view["ports"] == ["Gi1/0/5", "Gi1/0/8"] and access_view["uplinks"][0]["toLabel"] == "SW-CORE"
    listed = client.get("/api/console/network/snmp-credentials", params={"tenant_id": tenant["id"]}, headers=admin).json()
    assert listed[0]["lastResult"]["192.168.10.3"]["ok"] is True and "community" not in json.dumps(listed)

    # The PC moves to Gi1/0/7: the old link goes, nothing is duplicated.
    command = discover(client, admin, probe)
    client.post(f"/api/v1/devices/{probe['deviceId']}/commands/{command['id']}/snmp-credentials", headers=probe["headers"])
    complete(client, probe, command["id"], {"topology": {**REPORT, "switches": switches(pc_port="7")}})
    graph = client.get("/api/console/network/topology", params={"tenant_id": tenant["id"]}, headers=admin).json()
    pcs = [n for n in graph["nodes"] if n.get("mac") == PC_MAC]
    assert len(pcs) == 1 and pcs[0]["connection"]["port"] == "Gi1/0/7"
    assert len([e for e in graph["edges"] if e["to"] == pcs[0]["id"] and e["kind"] in ("access", "shared")]) == 1


def test_switch_credentials_are_released_once_to_the_probe_only(client, admin, tenant):
    probe = setup_probe(client, admin, tenant)
    other = enroll(client, admin, tenant, hostname="ACME-OTHER", os_version="Ubuntu 22.04", serial="P2")
    add_credential(client, admin, tenant)
    command = discover(client, admin, probe)
    route = f"/api/v1/devices/{{}}/commands/{command['id']}/snmp-credentials"
    assert client.post(route.format(other["deviceId"]), headers=other["headers"]).status_code == 404  # not its command
    assert client.post(route.format(probe["deviceId"]), headers=probe["headers"]).status_code == 200
    assert client.post(route.format(probe["deviceId"]), headers=probe["headers"]).status_code == 404  # once
    # A device that is not a probe does not query switches, and a Windows probe never gets SNMP.
    client.post("/api/console/network/discover", json={"deviceId": other["deviceId"]}, headers=admin)
    assert json.loads(next(c for c in poll(client, other) if c["type"] == "network.discover")["payloadJson"])["snmp"] is False
    win = setup_probe(client, admin, tenant, platform_os="Windows Server 2022", serial="W1")
    client.post("/api/console/network/discover", json={"deviceId": win["deviceId"]}, headers=admin)
    script = next(c for c in poll(client, win) if c["type"] == "script.run")
    assert "snmp" not in json.loads(script["payloadJson"])


def test_credential_validation_reauth_and_scope(client, admin, tenant):
    assert client.post("/api/console/network/snmp-credentials", headers=admin,
                       json={"tenantId": tenant["id"], "version": "2c", "community": "x", "hosts": ["192.168.1.2"]}).json()["detail"] == "reauth_required"
    assert add_credential(client, admin, tenant, hosts=["8.8.8.8"]).status_code == 422  # not a private address
    assert add_credential(client, admin, tenant, community=None).status_code == 400
    assert add_credential(client, admin, tenant, version="3", community=None).status_code == 400  # no username
    v3 = add_credential(client, admin, tenant, version="3", community=None, username="fenrir", authProtocol="SHA256", authPassword="long-auth-pass",
                        privProtocol="AES", privPassword="long-priv-pass")
    assert v3.status_code == 200 and v3.json()["username"] == "fenrir" and v3.json()["hasSecret"]
    # Updating without resending a secret keeps it.
    kept = client.put(f"/api/console/network/snmp-credentials/{v3.json()['id']}", headers=stepup(client, admin),
                      json={"tenantId": tenant["id"], "version": "3", "username": "fenrir", "authProtocol": "SHA256", "privProtocol": "AES",
                            "hosts": ["192.168.10.9"]})
    assert kept.status_code == 200 and kept.json()["hosts"] == ["192.168.10.9"]
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Co", "template": "balanced"}).json()
    client.post("/api/console/users", headers=admin, json={"tenantId": other["id"], "email": "boss@other.example",
                                                           "password": "other-password-123", "role": "tenant_admin"})
    outsider = login(client, "boss@other.example", "other-password-123")
    assert client.get("/api/console/network/snmp-credentials", params={"tenant_id": tenant["id"]}, headers=outsider).status_code == 404
    assert client.delete(f"/api/console/network/snmp-credentials/{v3.json()['id']}", headers=outsider).status_code == 404
    assert client.delete(f"/api/console/network/snmp-credentials/{v3.json()['id']}", headers=admin).status_code == 200


def test_switch_that_does_not_answer_is_reported_not_guessed(client, admin, tenant):
    probe = setup_probe(client, admin, tenant)
    cred = add_credential(client, admin, tenant).json()
    command = discover(client, admin, probe)
    client.post(f"/api/v1/devices/{probe['deviceId']}/commands/{command['id']}/snmp-credentials", headers=probe["headers"])
    complete(client, probe, command["id"], {"topology": {**REPORT, "switches": [
        {"host": "192.168.10.2", "credentialId": cred["id"], "error": "no SNMP answer: request timeout"}]}})
    graph = client.get("/api/console/network/topology", params={"tenant_id": tenant["id"]}, headers=admin).json()
    assert graph["summary"]["switches"] == 0 and not any(n.get("connection") for n in graph["nodes"])
    listed = client.get("/api/console/network/snmp-credentials", params={"tenant_id": tenant["id"]}, headers=admin).json()
    assert listed[0]["lastResult"]["192.168.10.2"] == {**listed[0]["lastResult"]["192.168.10.2"], "ok": False}
    assert "timeout" in listed[0]["lastResult"]["192.168.10.2"]["error"]
