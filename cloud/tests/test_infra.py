"""RMM-14: hypervisor monitoring from provider APIs with dependency-aware alerts."""
import json

import httpx
import pytest

from conftest import enroll
from test_documentation_vault import stepup
from fenrir_cloud import db as database, infra
from fenrir_cloud.models import Alert, AuditLog, Command, InfraAsset, InfraSource

REAL = httpx.Client
URL = "/api/console/infrastructure"


@pytest.fixture
def vcenter(monkeypatch):
    state = {"hosts": [{"host": "host-1", "name": "esx1", "connection_state": "CONNECTED", "power_state": "POWERED_ON"},
                       {"host": "host-2", "name": "esx2", "connection_state": "CONNECTED", "power_state": "POWERED_ON"}],
             "vms": {"vm-1": ("dc01", "POWERED_ON", "host-1"), "vm-2": ("sql01", "POWERED_ON", "host-2"), "vm-3": ("test", "POWERED_OFF", "host-2")},
             "datastores": [{"datastore": "ds-1", "name": "SAN", "capacity": 1000, "free_space": 50}], "auth": True}

    def handler(request: httpx.Request):
        path = request.url.path
        if path == "/api/session":
            if request.method == "DELETE":
                return httpx.Response(204)
            return httpx.Response(201, json="sess-1") if state["auth"] else httpx.Response(401)
        assert request.headers.get("vmware-api-session-id") == "sess-1"
        if path == "/api/vcenter/host":
            return httpx.Response(200, json=state["hosts"])
        if path == "/api/vcenter/vm":
            host = request.url.params.get("hosts")
            return httpx.Response(200, json=[{"vm": k, "name": n, "power_state": p} for k, (n, p, h) in state["vms"].items() if not host or h == host])
        if path == "/api/vcenter/datastore":
            return httpx.Response(200, json=state["datastores"])
        return httpx.Response(404)

    monkeypatch.setattr(infra, "_client", lambda source: REAL(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(infra.netguard, "resolve_public", lambda host: ["1.1.1.1"])
    return state


def add(client, admin, tenant, **extra):
    body = {"tenantId": tenant["id"], "name": "Main vCenter", "provider": "vsphere", "baseUrl": "https://vc.example.com",
            "route": "direct", "credentials": {"username": "fenrir-ro@vsphere.local", "password": "secret-pw"}, **extra}
    r = client.post(f"{URL}/sources", headers=stepup(client, admin), json=body)
    assert r.status_code == 200, r.text
    return r.json()


def alerts():
    with database.session_factory()() as db:
        return {a.details["key"].split(":", 2)[-1]: a for a in db.query(Alert).filter_by(rule_id=infra.ALERT_RULE, status="new").all()}


def test_vcenter_relationships_and_dependency_aware_alerts(client, admin, tenant, vcenter):
    src = add(client, admin, tenant)
    assert "secret-pw" not in json.dumps(src)
    out = client.post(f"{URL}/sources/{src['id']}/poll", headers=admin).json()
    assert out["status"] == "ok" and out["assets"] == 6
    rows = {a["name"]: a for a in client.get(f"{URL}/sources/{src['id']}/assets", headers=admin).json()}
    assert rows["sql01"]["parentExternalId"] == "host-2" and rows["dc01"]["expectedState"] == "running" and rows["test"]["expectedState"] == ""
    assert rows["SAN"]["health"] == "alert" and "95% full" in rows["SAN"]["reason"]
    assert set(alerts()) == {"storage:ds-1"}

    # esx2 stops responding: one host alert, its VMs suppressed rather than alerted.
    vcenter["hosts"][1]["connection_state"] = "NOT_RESPONDING"
    vcenter["vms"]["vm-2"] = ("sql01", "POWERED_OFF", "host-2")
    client.post(f"{URL}/sources/{src['id']}/poll", headers=admin)
    rows = {a["name"]: a for a in client.get(f"{URL}/sources/{src['id']}/assets", headers=admin).json()}
    assert rows["esx2"]["health"] == "alert" and rows["sql01"]["health"] == "suppressed" and "esx2" in rows["sql01"]["reason"]
    assert set(alerts()) == {"storage:ds-1", "host:host-2"} and alerts()["host:host-2"].severity == "critical"

    # The host comes back but sql01 stays off: now sql01 alerts and the host alert resolves.
    vcenter["hosts"][1]["connection_state"] = "CONNECTED"
    client.post(f"{URL}/sources/{src['id']}/poll", headers=admin)
    assert set(alerts()) == {"storage:ds-1", "vm:vm-2"}
    # An operator marks sql01 as expected to be off: the alert resolves on the next poll.
    asset_id = next(a["id"] for a in client.get(f"{URL}/sources/{src['id']}/assets", headers=admin).json() if a["name"] == "sql01")
    client.put(f"{URL}/assets/{asset_id}/expected", headers=admin, json={"expectedState": "stopped"})
    client.post(f"{URL}/sources/{src['id']}/poll", headers=admin)
    assert set(alerts()) == {"storage:ds-1"}

    # The credential stops working: one source alert, assets unknown (not alerted).
    vcenter["auth"] = False
    out = client.post(f"{URL}/sources/{src['id']}/poll", headers=admin).json()
    assert out["status"] == "auth_failed"
    rows = client.get(f"{URL}/sources/{src['id']}/assets", headers=admin).json()
    assert {a["health"] for a in rows} == {"unknown"} and f"source:{src['id']}" in {a.details["key"] for a in alerts().values()}


def test_proxmox_parse():
    raw = [{"name": "nodes", "status": 200, "body": json.dumps({"data": [{"node": "pve1", "status": "online"}, {"node": "pve2", "status": "offline"}]})},
           {"name": "vms", "status": 200, "body": json.dumps({"data": [
               {"id": "qemu/100", "vmid": 100, "name": "web", "node": "pve1", "status": "running", "type": "qemu"},
               {"id": "lxc/200", "vmid": 200, "name": "db", "node": "pve2", "status": "stopped", "type": "lxc"},
               {"id": "qemu/9000", "vmid": 9000, "name": "tpl", "node": "pve1", "status": "stopped", "template": 1}]})},
           {"name": "storage", "status": 200, "body": json.dumps({"data": [{"id": "storage/pve1/local", "storage": "local", "node": "pve1",
                                                                             "status": "available", "disk": 10, "maxdisk": 100}]})}]
    status, _, assets = infra.parse("proxmox", raw)
    by = {a["name"]: a for a in assets}
    assert status == "ok" and "tpl" not in by and by["db"]["parent"] == "pve2" and by["pve2"]["state"] == "offline"
    assert by["local"]["metrics"]["usedFraction"] == 0.1
    assert infra.parse("proxmox", [{"name": "nodes", "status": 401, "body": ""}])[0] == "auth_failed"


def test_agent_route_releases_credential_once(client, admin, tenant, vcenter):
    probe = enroll(client, admin, tenant, hostname="probe-01", os_version="Ubuntu 24.04")
    with database.session_factory()() as db:
        from fenrir_cloud.models import Device
        db.get(Device, probe["deviceId"]).platform = "linux"
        db.commit()
    src = add(client, admin, tenant, provider="proxmox", baseUrl="https://pve.lan:8006", route="agent", probeDeviceId=probe["deviceId"],
              credentials={"tokenId": "fenrir@pve!ro", "secret": "tok-secret"}, tlsInsecure=True)
    out = client.post(f"{URL}/sources/{src['id']}/poll", headers=admin).json()
    assert out["status"] == "queued"
    with database.session_factory()() as db:
        cmd = db.get(Command, out["commandId"])
        assert cmd.type == "infra.poll" and "tok-secret" not in json.dumps(cmd.payload)
    url = f"/api/v1/devices/{probe['deviceId']}/commands/{out['commandId']}/infra-credential"
    cred = client.post(url, headers=probe["headers"]).json()
    assert cred == {"provider": "proxmox", "baseUrl": "https://pve.lan:8006", "tlsInsecure": True, "tokenId": "fenrir@pve!ro", "secret": "tok-secret"}
    assert client.post(url, headers=probe["headers"]).status_code == 404  # released once
    with database.session_factory()() as db:
        cmd = db.get(Command, out["commandId"])
        cmd.status, cmd.result = "completed", {"responses": [
            {"name": "nodes", "status": 200, "body": json.dumps({"data": [{"node": "pve1", "status": "online"}]})},
            {"name": "vms", "status": 200, "body": json.dumps({"data": [{"id": "qemu/100", "name": "web", "node": "pve1", "status": "running"}]})},
            {"name": "storage", "status": 200, "body": json.dumps({"data": []})}]}
        device = db.get(__import__("fenrir_cloud.models", fromlist=["Device"]).Device, probe["deviceId"])
        infra.on_command_complete(db, device, cmd)
        db.commit()
        assert db.get(InfraSource, src["id"]).status == "ok"
        assert db.query(InfraAsset).filter_by(source_id=src["id"], kind="vm").one().expected_state == "running"
        assert db.query(AuditLog).filter_by(action="infra.credential.released").count() == 1


def test_private_direct_endpoint_is_refused(client, admin, tenant, monkeypatch):
    src = add(client, admin, tenant, baseUrl="https://10.0.0.5")
    monkeypatch.setattr(infra.netguard, "resolve_public", lambda host: (_ for _ in ()).throw(infra.netguard.Blocked("10.0.0.5 is private")))
    out = client.post(f"{URL}/sources/{src['id']}/poll", headers=admin).json()
    assert out["status"] == "unreachable" and "probe device" in out["error"]
