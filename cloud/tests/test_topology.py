"""Network topology discovery (topology.py): ingestion, matching managed devices, classification, graph."""

import json

from conftest import enroll, login
from fenrir_cloud import topology
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import Device, NetworkNode


def poll(client, device):
    return client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]


def complete(client, device, command_id, result, status="completed"):
    response = client.post(f"/api/v1/devices/{device['deviceId']}/commands/{command_id}/complete",
                           json={"status": status, "resultJson": json.dumps(result)}, headers=device["headers"])
    assert response.status_code == 200, response.text


REPORT = {
    "interfaces": [{"name": "eth0", "mac": "aa:aa:aa:00:00:01", "addresses": ["192.168.10.20/24", "fe80::1/64"]}],
    "gateway": "192.168.10.1",
    "neighbors": [
        {"ip": "192.168.10.1", "mac": "AA-BB-CC-00-00-01", "openPorts": [53, 80, 443], "source": "arp"},
        {"ip": "192.168.10.30", "mac": "aa:bb:cc:00:00:30", "openPorts": [9100, 80], "hostname": "printer-1.acme.lan", "source": "arp"},
        {"ip": "192.168.10.40", "mac": "00:15:5d:00:00:40", "openPorts": [22], "source": "arp"},
        {"ip": "192.168.10.50", "mac": "aa:bb:cc:00:00:50", "openPorts": [135, 445, 3389], "hostname": "acme-srv-02", "source": "sweep"},
        {"ip": "192.168.10.60", "mac": "aa:bb:cc:00:00:60", "source": "arp"},
        {"ip": "8.8.8.8", "mac": "aa:bb:cc:00:00:99", "source": "arp"},  # never recorded: not a private address
    ],
    "swept": ["192.168.10.0/24"],
}


def test_linux_discovery_builds_topology_and_links_managed_devices(client, admin, tenant):
    probe = enroll(client, admin, tenant, hostname="ACME-LNX", os_version="Ubuntu 22.04", serial="T1")
    managed = enroll(client, admin, tenant, hostname="ACME-WS-60", serial="T2")
    with session_factory()() as db:
        db.get(Device, managed["deviceId"]).inventory = {"macAddresses": ["AA:BB:CC:00:00:60"], "ipAddresses": ["192.168.10.60"]}
        db.commit()
    assert client.post("/api/console/network/discover", json={"deviceId": probe["deviceId"]}, headers=admin).json()["queued"] == 1
    command = next(c for c in poll(client, probe) if c["type"] == "network.discover")
    assert json.loads(command["payloadJson"])["sweep"] is True
    complete(client, probe, command["id"], {"topology": REPORT})

    graph = client.get("/api/console/network/topology", params={"tenant_id": tenant["id"]}, headers=admin).json()
    nodes = {n["ip"]: n for n in graph["nodes"] if n["type"] == "node"}
    assert "8.8.8.8" not in nodes
    assert nodes["192.168.10.1"]["kind"] == "gateway"
    assert nodes["192.168.10.30"]["kind"] == "printer" and nodes["192.168.10.30"]["label"] == "printer-1.acme.lan"
    assert nodes["192.168.10.40"]["kind"] == "virtual" and nodes["192.168.10.40"]["vendor"] == "Microsoft Hyper-V"
    assert nodes["192.168.10.50"]["kind"] == "server" and not nodes["192.168.10.50"]["managed"]
    assert nodes["192.168.10.60"]["managed"] and nodes["192.168.10.60"]["deviceId"] == managed["deviceId"]
    assert nodes["192.168.10.20"]["managed"] and nodes["192.168.10.20"]["deviceId"] == probe["deviceId"]  # the probe itself
    assert {"from": nodes["192.168.10.1"]["id"], "to": "subnet:192.168.10.0/24", "kind": "gateway"} in graph["edges"]
    assert graph["summary"]["deployable"] == 1  # the unmanaged Windows server

    # A second report updates nodes in place (keyed by MAC), never duplicating them.
    again = client.post("/api/console/network/discover", json={"deviceId": probe["deviceId"]}, headers=admin)
    command = next(c for c in poll(client, probe) if c["type"] == "network.discover")
    complete(client, probe, command["id"], {"topology": REPORT})
    with session_factory()() as db:
        assert db.query(NetworkNode).filter(NetworkNode.tenant_id == tenant["id"]).count() == 6


def test_windows_discovery_via_script_and_node_actions(client, admin, tenant):
    probe = enroll(client, admin, tenant, hostname="ACME-WIN", serial="T3")
    client.post("/api/console/network/discover", json={"deviceId": probe["deviceId"]}, headers=admin)
    command = next(c for c in poll(client, probe) if c["type"] == "script.run")
    assert topology.MARKER in json.loads(command["payloadJson"])["body"]
    complete(client, probe, command["id"], {"exitCode": 0, "stdout": "x\n" + topology.MARKER + json.dumps(REPORT)})
    graph = client.get("/api/console/network/topology", params={"tenant_id": tenant["id"]}, headers=admin).json()
    printer = next(n for n in graph["nodes"] if n.get("kind") == "printer")
    monitor = client.post(f"/api/console/network/nodes/{printer['id']}/monitor", json={}, headers=admin).json()
    assert monitor["address"] == "192.168.10.30" and monitor["port"] == 80 and monitor["probeDeviceId"] == probe["deviceId"]
    assert client.patch(f"/api/console/network/nodes/{printer['id']}", json={"ignored": True}, headers=admin).json()["ignored"] is True
    graph = client.get("/api/console/network/topology", params={"tenant_id": tenant["id"]}, headers=admin).json()
    assert graph["summary"]["unmanaged"] == 4  # gateway, Hyper-V guest, server, .60 (printer ignored)


def test_topology_scope_and_schedule(client, admin, tenant):
    probe = enroll(client, admin, tenant, hostname="ACME-LNX2", os_version="Debian 12", serial="T4")
    saved = client.put("/api/console/network/topology/settings", json={"tenantId": tenant["id"], "probeDeviceIds": [probe["deviceId"]]},
                       headers=admin)
    assert saved.status_code == 200
    with session_factory()() as db:
        assert topology.tick(db) == 1
        db.commit()
        assert topology.tick(db) == 0  # once per interval
    other = client.post("/api/console/tenants", json={"name": "Other Co", "template": "balanced"}, headers=admin).json()
    client.post("/api/console/users", json={"email": "ta@other.test", "name": "T", "role": "tenant_admin", "tenantId": other["id"],
                                            "password": "a-long-enough-password-1"}, headers=admin)
    outsider = login(client, "ta@other.test", "a-long-enough-password-1")
    assert client.get("/api/console/network/topology", params={"tenant_id": tenant["id"]}, headers=outsider).status_code == 404
    assert client.post("/api/console/network/discover", json={"deviceId": probe["deviceId"]}, headers=outsider).status_code == 404
