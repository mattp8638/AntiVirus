"""AV-15: sandbox submissions with approval, confidential-data controls and asynchronous verdicts (mocked provider)."""
import hashlib

import httpx
import pytest

from conftest import enroll, login
from test_documentation_vault import stepup
from fenrir_cloud import db as database, sandbox
from fenrir_cloud.models import (Alert, AuditLog, Command, DataDiscoveryScan, Device, DeviceArtifact, Incident, SandboxSubmission, utcnow)

REAL = httpx.Client
URL = "/api/console/sandbox"
SAMPLE = b"MZ fake malware body"
SHA = hashlib.sha256(SAMPLE).hexdigest()


@pytest.fixture
def cape(monkeypatch, tmp_path):
    state = {"known": {}, "tasks": {}, "uploads": [], "ready": False}

    def handler(request: httpx.Request):
        assert request.headers["Authorization"] == "Token cape-key"
        path = request.url.path
        if path.startswith("/apiv2/tasks/search/sha256/"):
            sha = path.rstrip("/").rsplit("/", 1)[1]
            return httpx.Response(200, json={"data": [{"id": state["known"][sha], "status": "reported"}] if sha in state["known"] else []})
        if path == "/apiv2/tasks/create/file/":
            state["uploads"].append(request.content)
            return httpx.Response(200, json={"error": False, "data": {"task_ids": [42]}})
        if path.startswith("/apiv2/tasks/status/"):
            return httpx.Response(200, json={"data": "reported" if state["ready"] else "running"})
        if path.startswith("/apiv2/tasks/get/report/"):
            return httpx.Response(200, json={"malscore": 8.5, "signatures": [{"name": "injection_rwx", "severity": 3}],
                                             "network": {"domains": [{"domain": "c2.bad.example"}], "hosts": ["203.0.113.9"]}})
        return httpx.Response(404)

    monkeypatch.setattr(sandbox, "_client", lambda: REAL(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(sandbox.netguard, "guard_url_host", lambda host: None)
    from fenrir_cloud.routers import artifacts
    monkeypatch.setattr(artifacts, "artifact_dir", lambda: tmp_path)
    return state


def setup(client, admin, tenant, **policy):
    client.post(f"{URL}/providers", headers=stepup(client, admin),
                json={"tenantId": tenant["id"], "name": "CAPE", "baseUrl": "https://cape.example.net", "apiKey": "cape-key"})
    client.put(f"{URL}/policy/{tenant['id']}", headers=admin, json={"enabled": True, "mode": "file", **policy})
    dev = enroll(client, admin, tenant, hostname="ws-01")
    with database.session_factory()() as db:
        db.get(Device, dev["deviceId"]).platform = "linux"
        incident = Incident(tenant_id=tenant["id"], title="Malware on ws-01")
        db.add(incident)
        db.flush()
        alert = Alert(tenant_id=tenant["id"], device_id=dev["deviceId"], rule_id="av.detection", title="Malware", severity="medium",
                      incident_id=incident.id, details={"sha256": SHA, "path": "/home/sam/Downloads/invoice.exe", "recordId": "q-1-abc"})
        db.add(alert)
        db.commit()
        return dev, alert.id, incident.id


def run_tick():
    with database.session_factory()() as db:
        sandbox.tick(db)


def test_executable_auto_approved_collected_submitted_and_verdict_on_incident(client, admin, tenant, cape, tmp_path):
    dev, alert_id, incident_id = setup(client, admin, tenant, autoApproveExecutables=True)
    sub = client.post(f"{URL}/submissions", headers=admin, json={"alertId": alert_id}).json()
    assert sub["status"] == "approved" and sub["mode"] == "file" and sub["incidentId"] == incident_id
    run_tick()  # unknown to the sandbox: ask the agent for the sample
    with database.session_factory()() as db:
        row = db.get(SandboxSubmission, sub["id"])
        from fenrir_cloud.models import SandboxProvider
        assert row.status == "collecting", (row.reason, [p.last_error for p in db.query(SandboxProvider).all()])
        cmd = db.get(Command, row.command_id)
        assert cmd.type == "sample.collect" and cmd.payload == {"recordId": "q-1-abc", "sha256": SHA}
    # The agent uploads the sample through the artifact endpoint.
    up = client.post(f"/api/v1/devices/{dev['deviceId']}/commands/{row.command_id}/artifact", headers=dev["headers"],
                     params={"filename": f"{SHA}.sample", "sha256": SHA}, content=SAMPLE)
    assert up.status_code == 200, up.text
    run_tick()
    assert cape["uploads"] and SAMPLE in cape["uploads"][0]
    run_tick()  # still running at the sandbox
    cape["ready"] = True
    run_tick()
    with database.session_factory()() as db:
        row = db.get(SandboxSubmission, sub["id"])
        assert row.status == "completed" and row.verdict == "malicious" and row.report["network"]["domains"] == ["c2.bad.example"]
        assert db.get(Alert, alert_id).severity == "high"
        assert db.get(Incident, incident_id).timeline[-1]["kind"] == "sandbox"
        assert {a.action for a in db.query(AuditLog).filter(AuditLog.action.like("sandbox.%")).all()} >= {"sandbox.requested", "sandbox.submitted", "sandbox.verdict"}


def test_documents_need_a_second_person_and_confidential_paths_are_refused(client, admin, tenant, cape):
    dev, alert_id, _ = setup(client, admin, tenant, neverSubmit=["/HR/"])
    doc = client.post(f"{URL}/submissions", headers=admin, json={"tenantId": tenant["id"], "sha256": SHA, "filename": "contract.docx",
                                                              "deviceId": dev["deviceId"], "quarantineRecord": "q-2"}).json()
    assert doc["status"] == "awaiting_approval" and "second person" in doc["reason"]
    r = client.post(f"{URL}/submissions/{doc['id']}/review", headers=admin, json={"approve": True})
    assert r.status_code == 409
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "analyst@acme.example",
                                                           "password": "analyst-pass-1234", "role": "tenant_admin"})
    analyst = login(client, "analyst@acme.example", "analyst-pass-1234")
    assert client.post(f"{URL}/submissions/{doc['id']}/review", headers=analyst, json={"approve": True}).json()["status"] == "approved"

    hr = client.post(f"{URL}/submissions", headers=admin, json={"tenantId": tenant["id"], "sha256": SHA, "path": "/srv/HR/salaries.xlsx"}).json()
    assert hr["status"] == "refused" and "never-submit" in hr["reason"]
    with database.session_factory()() as db:
        db.add(DataDiscoveryScan(tenant_id=tenant["id"], device_id=dev["deviceId"], status="completed",
                                 files=[{"path": "/home/sam/customers.csv", "types": {"email": 40}}]))
        db.commit()
    pii = client.post(f"{URL}/submissions", headers=admin, json={"tenantId": tenant["id"], "sha256": SHA, "path": "/home/sam/customers.csv",
                                                              "deviceId": dev["deviceId"]}).json()
    assert pii["status"] == "refused" and "personal data" in pii["reason"]


def test_hash_only_mode_never_uploads_and_no_provider_is_explicit(client, admin, tenant, cape, second_tenant=None):
    dev, alert_id, _ = setup(client, admin, tenant, mode="hash", autoApproveExecutables=True)
    sub = client.post(f"{URL}/submissions", headers=admin, json={"alertId": alert_id}).json()
    run_tick()
    with database.session_factory()() as db:
        row = db.get(SandboxSubmission, sub["id"])
        assert row.status == "completed" and row.verdict == "unknown" and "not sent" in row.reason
        assert db.query(Command).filter_by(type="sample.collect").count() == 0
    assert cape["uploads"] == []
    other = client.post("/api/console/tenants", json={"name": "No sandbox", "template": "balanced"}, headers=admin).json()
    with database.session_factory()() as db:
        from fenrir_cloud.models import SandboxProvider
        db.query(SandboxProvider).delete()
        db.commit()
    client.put(f"{URL}/policy/{other['id']}", headers=admin, json={"enabled": True})
    r = client.post(f"{URL}/submissions", headers=admin, json={"tenantId": other["id"], "sha256": SHA, "filename": "a.exe"}).json()
    assert r["status"] == "refused" and "licensed sandbox" in r["reason"]


def test_windows_device_falls_back_to_hash_lookup(client, admin, tenant, cape):
    dev, alert_id, _ = setup(client, admin, tenant, autoApproveExecutables=True)
    with database.session_factory()() as db:
        db.get(Device, dev["deviceId"]).platform = "windows"
        db.commit()
    sub = client.post(f"{URL}/submissions", headers=admin, json={"alertId": alert_id}).json()
    run_tick()
    with database.session_factory()() as db:
        row = db.get(SandboxSubmission, sub["id"])
        assert row.status == "completed" and "Windows agents" in row.reason and cape["uploads"] == []
    cape["known"][SHA] = "7"
    cape["ready"] = True
    sub2 = client.post(f"{URL}/submissions", headers=admin, json={"alertId": alert_id}).json()
    run_tick()
    run_tick()
    with database.session_factory()() as db:
        assert db.get(SandboxSubmission, sub2["id"]).verdict == "malicious"  # known hash: the earlier analysis is used
