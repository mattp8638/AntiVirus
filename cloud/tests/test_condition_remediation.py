"""Condition-based background remediation: detect -> remediate -> verify through script.run."""

import json

from conftest import enroll, login
from fenrir_cloud import condition_remediation
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import ConditionResult, Ticket


def poll(client, device):
    return client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]


def complete(client, device, command_id, exit_code, stdout=""):
    status = "completed" if exit_code == 0 else "failed"
    response = client.post(f"/api/v1/devices/{device['deviceId']}/commands/{command_id}/complete",
                           json={"status": status, "resultJson": json.dumps({"exitCode": exit_code, "stdout": stdout})},
                           headers=device["headers"])
    assert response.status_code == 200, response.text


def phase_of(command):
    return json.loads(command["payloadJson"])["phase"]


def enable(client, admin, tenant, key, **extra):
    templates = client.get("/api/console/rmm/remediation-packages", headers=admin).json()
    template = next(p for p in templates if p["builtinKey"] == key and p["template"])
    response = client.post(f"/api/console/rmm/remediation-packages/{template['id']}/enable", json={"tenantId": tenant["id"], **extra},
                           headers=admin)
    assert response.status_code == 200, response.text
    return response.json()


def test_detect_remediate_verify_cycle(client, admin, tenant, device):
    package = enable(client, admin, tenant, "win-spooler")
    assert package["enabled"] and package["detectionScript"].startswith("$s = Get-Service")
    with session_factory()() as db:
        assert condition_remediation.tick(db) == 1
        db.commit()
        assert condition_remediation.tick(db) == 0  # the device has not answered yet
    detect = next(c for c in poll(client, device) if c["type"] == "script.run")
    assert phase_of(detect) == "detect"
    complete(client, device, detect["id"], 1, "Print Spooler is Stopped")
    remediate = next(c for c in poll(client, device) if c["type"] == "script.run" and phase_of(c) == "remediate")
    complete(client, device, remediate["id"], 0, "Print Spooler started")
    verify = next(c for c in poll(client, device) if c["type"] == "script.run" and phase_of(c) == "verify")
    complete(client, device, verify["id"], 0, "Print Spooler is running")
    results = client.get(f"/api/console/rmm/remediation-packages/{package['id']}/results", headers=admin).json()
    assert results[0]["status"] == "remediated" and results[0]["attempts"] == 1 and "running" in results[0]["detectOutput"]
    listed = next(p for p in client.get("/api/console/rmm/remediation-packages", headers=admin).json() if p["id"] == package["id"])
    assert listed["results"] == {"remediated": 1}


def test_failed_verification_opens_one_ticket_and_report_only_mode(client, admin, tenant, device):
    package = enable(client, admin, tenant, "win-firewall")
    client.post(f"/api/console/rmm/remediation-packages/{package['id']}/run", json={}, headers=admin)
    detect = next(c for c in poll(client, device) if c["type"] == "script.run")
    complete(client, device, detect["id"], 1, "Firewall off for: Public")
    remediate = next(c for c in poll(client, device) if phase_of(c) == "remediate")
    complete(client, device, remediate["id"], 0)
    verify = next(c for c in poll(client, device) if phase_of(c) == "verify")
    complete(client, device, verify["id"], 1, "Firewall off for: Public")
    with session_factory()() as db:
        row = db.query(ConditionResult).filter_by(package_id=package["id"]).one()
        assert row.status == "failed" and row.ticket_id
        assert db.query(Ticket).filter(Ticket.source == "condition-remediation").count() == 1

    report_only = enable(client, admin, tenant, "win-wuauserv", autoRemediate=False)
    client.post(f"/api/console/rmm/remediation-packages/{report_only['id']}/run", json={}, headers=admin)
    detect = next(c for c in poll(client, device) if c["type"] == "script.run" and "wuauserv" in json.loads(c["payloadJson"])["body"])
    complete(client, device, detect["id"], 1)
    assert not [c for c in poll(client, device) if phase_of(c) == "remediate"]
    results = client.get(f"/api/console/rmm/remediation-packages/{report_only['id']}/results", headers=admin).json()
    assert results[0]["status"] == "noncompliant"


def test_custom_packages_validate_and_stay_in_scope(client, admin, tenant, device):
    bad = client.post("/api/console/rmm/remediation-packages",
                      json={"tenantId": tenant["id"], "name": "x", "language": "bash", "platforms": ["windows"], "detectionScript": "exit 0"},
                      headers=admin)
    assert bad.status_code == 422
    linux = enroll(client, admin, tenant, hostname="ACME-LNX", os_version="Ubuntu 22.04", serial="C2")
    created = client.post("/api/console/rmm/remediation-packages",
                          json={"tenantId": tenant["id"], "name": "Custom check", "language": "bash", "platforms": ["linux"],
                                "detectionScript": "exit 2", "remediationScript": "true"}, headers=admin).json()
    assert client.post(f"/api/console/rmm/remediation-packages/{created['id']}/run", json={}, headers=admin).json()["queued"] == 1
    assert not [c for c in poll(client, device) if c["type"] == "script.run"]  # the Windows device is not targeted
    detect = next(c for c in poll(client, linux) if c["type"] == "script.run")
    complete(client, linux, detect["id"], 2, "cannot tell")
    assert client.get(f"/api/console/rmm/remediation-packages/{created['id']}/results", headers=admin).json()[0]["status"] == "error"

    other = client.post("/api/console/tenants", json={"name": "Other Co", "template": "balanced"}, headers=admin).json()
    client.post("/api/console/users", json={"email": "ta@other.test", "name": "T", "role": "tenant_admin", "tenantId": other["id"],
                                            "password": "a-long-enough-password-1"}, headers=admin)
    outsider = login(client, "ta@other.test", "a-long-enough-password-1")
    assert client.patch(f"/api/console/rmm/remediation-packages/{created['id']}", json={"enabled": False}, headers=outsider).status_code == 404
    assert all(p["template"] for p in client.get("/api/console/rmm/remediation-packages", headers=outsider).json())
