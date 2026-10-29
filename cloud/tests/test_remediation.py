"""EPSS-driven priority and silent remediation (remediation.py, the Cyber Heal endpoints)."""

import json

import pytest

from conftest import enroll, login
from fenrir_cloud import remediation, vulnmgmt
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import Device, DevicePatch, Vulnerability


def add_vuln(device_id, tenant_id, **values):
    with session_factory()() as db:
        row = Vulnerability(tenant_id=tenant_id, device_id=device_id, **{"vuln_id": "CVE-2024-0001", "package": "openssl",
                                                                         "severity": "high", **values})
        db.add(row)
        db.commit()
        return row.id


def poll(client, device):
    return client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]


def complete(client, device, command_id, result, status="completed"):
    response = client.post(f"/api/v1/devices/{device['deviceId']}/commands/{command_id}/complete",
                           json={"status": status, "resultJson": json.dumps(result)}, headers=device["headers"])
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("values,elevated,expected", [
    ({"known_exploited": True, "severity": "low"}, False, "P1"),
    ({"epss": 0.6, "severity": "medium"}, False, "P1"),
    ({"epss": 0.15, "severity": "critical"}, False, "P1"),
    ({"epss": 0.15, "severity": "medium"}, False, "P2"),
    ({"epss": None, "severity": "critical"}, False, "P2"),
    ({"epss": 0.0002, "severity": "critical"}, False, "P3"),  # critical but very unlikely to be exploited
    ({"epss": 0.02, "severity": "low"}, False, "P3"),
    ({"epss": 0.0001, "severity": "medium"}, False, "P4"),
    ({"epss": 0.0001, "severity": "medium"}, True, "P3"),  # sensitive data on the device raises one level
    ({"known_exploited": True}, True, "P1"),
])
def test_priority_is_driven_by_exploit_likelihood(values, elevated, expected):
    vuln = Vulnerability(vuln_id="CVE-1", package="x", **{"severity": "medium", "known_exploited": False, **values})
    assert vulnmgmt.priority(vuln, elevated) == expected


def test_linux_package_update_queues_safe_command_and_tracks_result(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="ACME-LNX", os_version="Ubuntu 22.04.4 LTS", serial="L1")
    vid = add_vuln(device["deviceId"], tenant["id"], evidence={"ecosystem": "Ubuntu:22.04"}, fixed_version="3.0.2-0ubuntu1.14")
    plan = client.get(f"/api/console/vulnerabilities/{vid}/remediation", headers=admin).json()
    assert plan["available"] and plan["commandType"] == "software.install" and "apt" in plan["description"]

    queued = client.post(f"/api/console/vulnerabilities/{vid}/cyber-heal", headers=admin)
    assert queued.status_code == 200, queued.text
    command = next(c for c in poll(client, device) if c["id"] == queued.json()["commandId"])
    payload = json.loads(command["payloadJson"])
    # The package name travels as data for the agent's own package-manager call; there is no script body.
    assert payload == {"installer": "apt", "identifier": "openssl", "action": "upgrade", "vulnerabilityIds": [vid]}
    assert "body" not in payload

    complete(client, device, command["id"], {"output": "openssl upgraded"})
    with session_factory()() as db:
        row = db.get(Vulnerability, vid)
        assert row.status == "patching"  # still needs a clean rescan to be "fixed"
        assert row.remediation["status"] == "completed" and row.remediation["awaitingVerification"]


def test_failed_remediation_reopens_and_bad_names_are_refused(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="ACME-LNX2", os_version="Debian GNU/Linux 12", serial="L2")
    vid = add_vuln(device["deviceId"], tenant["id"])
    command_id = client.post(f"/api/console/vulnerabilities/{vid}/remediate", json={"mode": "update"}, headers=admin).json()["commandId"]
    complete(client, device, command_id, {"error": "dpkg lock"}, status="failed")
    with session_factory()() as db:
        row = db.get(Vulnerability, vid)
        assert row.status == "open" and row.remediation["status"] == "failed"

    evil = add_vuln(device["deviceId"], tenant["id"], vuln_id="CVE-2024-0002", package="openssl'; rm -rf / #")
    refused = client.post(f"/api/console/vulnerabilities/{evil}/remediate", json={"mode": "update"}, headers=admin)
    assert refused.status_code == 409 and "not a valid apt package name" in refused.json()["detail"]


def test_windows_uses_reported_patch_or_winget_id_and_never_guesses(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="ACME-WIN", serial="W1")
    no_id = add_vuln(device["deviceId"], tenant["id"], package="Mozilla Firefox", source="nvd-cpe")
    plan = client.get(f"/api/console/vulnerabilities/{no_id}/remediation", headers=admin).json()
    assert not plan["available"] and "patch scan" in plan["reason"]

    with session_factory()() as db:
        db.add(DevicePatch(device_id=device["deviceId"], tenant_id=tenant["id"], patch_key="winget:Mozilla.Firefox", title="Mozilla Firefox 131",
                           source="winget", product="Mozilla Firefox", status="missing"))
        db.commit()
    queued = client.post(f"/api/console/vulnerabilities/{no_id}/remediate", json={"mode": "update"}, headers=admin).json()
    command = next(c for c in poll(client, device) if c["id"] == queued["commandId"])
    assert command["type"] == "patch.install"
    assert json.loads(command["payloadJson"])["patchIds"] == ["winget:Mozilla.Firefox"]

    winget = add_vuln(device["deviceId"], tenant["id"], vuln_id="CVE-2024-0003", package="7-Zip", fix={"winget": "7zip.7zip"})
    uninstall = client.post(f"/api/console/vulnerabilities/{winget}/remediate", json={"mode": "uninstall"}, headers=admin)
    assert uninstall.status_code == 200, uninstall.text
    uninstall = uninstall.json()
    command = next(c for c in poll(client, device) if c["id"] == uninstall["commandId"])
    assert command["type"] == "software.uninstall"
    assert json.loads(command["payloadJson"])["identifier"] == "7zip.7zip"


def test_remediation_permissions_and_scope(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="ACME-LNX3", os_version="Ubuntu 24.04", serial="L3")
    vid = add_vuln(device["deviceId"], tenant["id"])
    other = client.post("/api/console/tenants", json={"name": "Other Co", "template": "balanced"}, headers=admin).json()
    client.post("/api/console/users", json={"email": "ta@other.test", "name": "T", "role": "tenant_admin", "tenantId": other["id"],
                                            "password": "a-long-enough-password-1"}, headers=admin)
    outsider = login(client, "ta@other.test", "a-long-enough-password-1")
    for path in (f"vulnerabilities/{vid}/remediate", f"vulnerabilities/{vid}/cyber-heal"):
        assert client.post(f"/api/console/{path}", json={"mode": "update"}, headers=outsider).status_code == 404
    client.post("/api/console/users", json={"email": "view@acme.test", "name": "V", "role": "viewer", "tenantId": tenant["id"],
                                            "password": "a-long-enough-password-1"}, headers=admin)
    viewer = login(client, "view@acme.test", "a-long-enough-password-1")
    assert client.post(f"/api/console/vulnerabilities/{vid}/remediate", json={"mode": "update"}, headers=viewer).status_code == 403


def test_automatic_remediation_follows_customer_settings(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="ACME-LNX4", os_version="Ubuntu 22.04", serial="L4")
    kev = add_vuln(device["deviceId"], tenant["id"], vuln_id="CVE-2024-1111", known_exploited=True)
    low = add_vuln(device["deviceId"], tenant["id"], vuln_id="CVE-2024-2222", package="zlib1g", severity="low", epss=0.0001)
    with session_factory()() as db:
        assert remediation.tick(db) == 0  # off by default
    bad = client.put("/api/console/vulnerabilities/auto-remediation", json={"tenantId": tenant["id"], "enabled": True, "priorities": []},
                     headers=admin)
    assert bad.status_code == 422
    saved = client.put("/api/console/vulnerabilities/auto-remediation", json={"tenantId": tenant["id"], "enabled": True, "priorities": ["P1"]},
                       headers=admin)
    assert saved.status_code == 200
    assert client.get("/api/console/vulnerabilities/auto-remediation", params={"tenant_id": tenant["id"]},
                      headers=admin).json()["candidates"] == 1
    with session_factory()() as db:
        assert remediation.tick(db) == 1
        db.commit()
        assert remediation.tick(db) == 0  # not retried within 24 hours
        db.commit()
        assert db.get(Vulnerability, kev).remediation["automatic"] is True
        assert db.get(Vulnerability, low).remediation is None


def test_pii_on_device_raises_priority_in_the_list(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="ACME-HR", os_version="Ubuntu 22.04", serial="L5")
    add_vuln(device["deviceId"], tenant["id"], vuln_id="CVE-2024-3333", severity="medium", epss=0.0001)
    first = client.get(f"/api/console/vulnerabilities?tenant_id={tenant['id']}", headers=admin).json()[0]
    assert first["priority"] == "P4"
    with session_factory()() as db:
        db.get(Device, device["deviceId"]).exposure_flags = ["pii-high"]
        db.commit()
    entry = client.get(f"/api/console/vulnerabilities?tenant_id={tenant['id']}", headers=admin).json()[0]
    assert entry["priority"] == "P3" and entry["devices"][0]["exposure"] == ["pii-high"]
    detail = client.get(f"/api/console/vulnerabilities/cve/CVE-2024-3333", params={"tenant_id": tenant["id"]}, headers=admin).json()
    assert any("personal data" in reason for reason in detail["affected"][0]["reasons"])
