import hashlib
from datetime import datetime, timedelta, timezone
import httpx
import pytest
from conftest import ADMIN_PASSWORD, login
from test_documentation_vault import stepup
from fenrir_cloud import db as database, m365, network
from fenrir_cloud.models import Alert, Device, Event, Incident, M365Connection, NetworkMonitor

def post(client, admin, path, body):
    response = client.post("/api/console/" + path, headers=admin, json=body)
    assert response.status_code == 200, response.text
    return response.json()

def connection(client, admin, tenant):
    return post(client, stepup(client, admin), "m365/connections", {"tenantId":tenant["id"],"name":"Customer M365",
        "directoryId":"00000000-0000-0000-0000-000000000001","clientId":"00000000-0000-0000-0000-000000000002","clientSecret":"private-client-secret"})

def test_m365_sync_pagination_and_failure_retains_snapshot(client, admin, tenant, monkeypatch):
    row = connection(client, admin, tenant)
    assert "private-client-secret" not in str(row) and "credentialsEnvelope" not in row
    seen = []
    def handle(request):
        seen.append(str(request.url))
        if request.url.host == "login.microsoftonline.com":
            assert b"private-client-secret" in request.content
            return httpx.Response(200, json={"access_token":"token"})
        assert request.headers["Authorization"] == "Bearer token"
        if request.url.path.endswith("/users"):
            if request.url.params.get("page") == "2":
                return httpx.Response(200, json={"value":[{"id":"u2"}]})
            return httpx.Response(200, json={"value":[{"id":"u1"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/users?page=2"})
        return httpx.Response(200, json={"value":[]})
    real_client = httpx.Client
    monkeypatch.setattr(m365.httpx, "Client", lambda **kwargs: real_client(transport=httpx.MockTransport(handle)))
    synced = post(client, admin, "m365/connections/"+row["id"]+"/sync", {})
    assert len(synced["snapshot"]["users"]) == 2 and synced["status"] == "synced"
    monkeypatch.setattr(m365, "synchronize", lambda row: (_ for _ in ()).throw(httpx.ConnectError("private-client-secret")))
    failed = client.post("/api/console/m365/connections/"+row["id"]+"/sync",headers=admin)
    assert failed.status_code == 502 and "private-client-secret" not in failed.text
    saved = client.get("/api/console/m365/connections",headers=admin).json()[0]
    assert saved["status"] == "failed" and len(saved["snapshot"]["users"]) == 2

def test_graph_pagination_cannot_exfiltrate_bearer():
    seen = []
    def handle(request):
        seen.append(str(request.url))
        return httpx.Response(200,json={"value":[],"@odata.nextLink":"https://attacker.test/steal"})
    with httpx.Client(transport=httpx.MockTransport(handle)) as transport:
        with pytest.raises(ValueError, match="pagination"):
            m365.collect(transport,"https://graph.microsoft.com/v1.0/users","secret-token")
    assert len(seen) == 1

@pytest.mark.parametrize("address", ["127.0.0.1","169.254.169.254","::1","::ffff:127.0.0.1","224.0.0.1","not-an-ip"])
def test_monitor_rejects_local_metadata_and_non_ip_targets(address):
    with pytest.raises(ValueError):
        network.validate_address(address)

def test_network_failed_service_alert_and_recovery(client, admin, tenant, monkeypatch):
    row = post(client,admin,"network/monitors",{"tenantId":tenant["id"],"name":"HTTPS","address":"10.0.0.10","port":443})
    monkeypatch.setattr(network,"probe",lambda address,port:(False,None))
    for _ in range(3):
        row = post(client,admin,"network/monitors/"+row["id"]+"/check",{})
    assert row["state"] == "down" and row["failures"] == 3
    with database.session_factory()() as db:
        alerts = db.query(Alert).filter_by(rule_id="network:"+row["id"]).all()
        assert len(alerts) == 1 and alerts[0].status == "new"
    monkeypatch.setattr(network,"probe",lambda address,port:(True,2.5))
    row = post(client,admin,"network/monitors/"+row["id"]+"/check",{})
    assert row["state"] == "up" and row["failures"] == 0 and len(row["samples"]) == 4
    with database.session_factory()() as db:
        assert db.query(Alert).filter_by(rule_id="network:"+row["id"]).one().status == "resolved"

def test_grc_review_requires_stepup_and_future_review(client,admin,tenant):
    row = post(client,admin,"grc/records",{"tenantId":tenant["id"],"kind":"risk","title":"Restore failure","likelihood":3,"impact":5})
    assert row["riskScore"] == 15
    url = "/api/console/grc/records/"+row["id"]+"/review"
    assert client.patch(url,headers=admin,json={"status":"accepted"}).status_code == 403
    proof = stepup(client,admin)
    assert client.patch(url,headers=proof,json={"status":"accepted"}).status_code == 400
    accepted = client.patch(url,headers=proof,json={"status":"accepted","reviewDue":(datetime.now(timezone.utc)+timedelta(days=30)).isoformat()})
    assert accepted.status_code == 200 and accepted.json()["approvedBy"] == "admin@fenrir.local"

def test_backup_idempotent_runs_health_and_recovery_transitions(client,admin,tenant):
    plan = post(client,admin,"backup/plans",{"tenantId":tenant["id"],"name":"SQL service","provider":"Existing provider","rpoHours":24,"rtoMinutes":60})
    body = {"externalId":"job-1","status":"success","completedAt":datetime.now(timezone.utc).isoformat(),"bytesProtected":5000000000,"evidence":"provider report 1"}
    first = post(client,admin,"backup/plans/"+plan["id"]+"/runs",body)
    assert post(client,admin,"backup/plans/"+plan["id"]+"/runs",body)["id"] == first["id"]
    assert client.post("/api/console/backup/plans/"+plan["id"]+"/runs",headers=admin,json={**body,"status":"failed"}).status_code == 409
    assert client.get("/api/console/backup/plans",headers=admin).json()[0]["health"] == "protected"
    proof = stepup(client,admin)
    exercise = post(client,proof,"backup/plans/"+plan["id"]+"/exercises",{"target":"Isolated recovery VM"})
    url = "/api/console/backup/exercises/"+exercise["id"]
    assert client.patch(url,headers=proof,json={"status":"completed","evidence":"ok","durationMinutes":30}).status_code == 409
    assert client.patch(url,headers=proof,json={"status":"approved"}).status_code == 200
    assert client.patch(url,headers=proof,json={"status":"completed"}).status_code == 400
    complete = client.patch(url,headers=proof,json={"status":"completed","evidence":"Boot and application checks passed","durationMinutes":30})
    assert complete.status_code == 200 and complete.json()["rtoMet"] is True
    assert client.patch(url,headers=proof,json={"status":"approved"}).status_code == 409

def test_external_siem_events_deduplicate_without_changing_device_state(client,admin,device):
    body = {"deviceId":device["deviceId"],"source":"customer-shipper","events":[{"eventId":"external-1","eventType":"device.isolated","summary":"third-party observation"}]}
    result = post(client,admin,"soc/ingest",body)
    assert result["accepted"] == 1
    assert post(client,admin,"soc/ingest",body)["duplicates"] == 1
    with database.session_factory()() as db:
        assert db.get(Device,device["deviceId"]).isolated is False
        row = db.query(Event).filter_by(device_id=device["deviceId"]).one()
        assert row.source == "external:customer-shipper"

def test_incident_evidence_hash_and_scope(client,admin,tenant):
    with database.session_factory()() as db:
        incident = Incident(tenant_id=tenant["id"],title="Investigation")
        db.add(incident); db.commit()
        ident = incident.id
    evidence = post(client,admin,"soc/incidents/"+ident+"/evidence",{"name":"Investigation notes","content":"Collected evidence"})
    assert evidence["sha256"] == hashlib.sha256(b"Collected evidence").hexdigest()
    assert client.get("/api/console/soc/incidents/"+ident+"/evidence",headers=admin).json()[0]["content"] == "Collected evidence"

def test_module_cross_tenant_boundaries(client,admin,tenant):
    conn = connection(client,admin,tenant)
    monitor = post(client,admin,"network/monitors",{"tenantId":tenant["id"],"name":"HTTPS","address":"10.0.0.1","port":443})
    risk = post(client,admin,"grc/records",{"tenantId":tenant["id"],"kind":"risk","title":"Private risk"})
    plan = post(client,admin,"backup/plans",{"tenantId":tenant["id"],"name":"Private backup","provider":"vendor"})
    other = post(client,admin,"tenants",{"name":"Unrelated"})
    post(client,admin,"users",{"tenantId":other["id"],"email":"outsider@test.com","password":ADMIN_PASSWORD,"role":"tenant_admin"})
    outsider = login(client,"outsider@test.com")
    for collection in ["m365/connections","network/monitors","grc/records","backup/plans","backup/exercises","soc/suppressions"]:
        assert client.get("/api/console/"+collection,headers=outsider).json() == []
    assert client.post("/api/console/m365/connections/"+conn["id"]+"/sync",headers=outsider).status_code == 404
    assert client.post("/api/console/network/monitors/"+monitor["id"]+"/check",headers=outsider).status_code == 404
    assert client.patch("/api/console/grc/records/"+risk["id"]+"/review",headers=outsider,json={"status":"closed"}).status_code == 404
    assert client.get("/api/console/backup/plans/"+plan["id"]+"/runs",headers=outsider).status_code == 404

def test_suppression_expires_and_alerting_resumes(client, admin, device):
    from fenrir_cloud import detection
    from fenrir_cloud.models import AlertSuppression, DetectionRule, utcnow
    with database.session_factory()() as db:
        managed = db.get(Device, device["deviceId"])
        tenant_id = managed.tenant_id
        db.add(DetectionRule(id="test-maintenance", title="Maintenance", source="", tenant_id=tenant_id))
        db.commit()
    row = post(client, admin, "soc/suppressions", {"tenantId":tenant_id, "ruleId":"test-maintenance",
        "reason":"Planned maintenance", "expiresAt":(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()})
    with database.session_factory()() as db:
        managed = db.get(Device, device["deviceId"])
        event = Event(tenant_id=tenant_id, device_id=managed.id, event_id="maintenance", event_type="process.start")
        db.add(event); db.flush()
        assert detection._raise_alert(db, managed, "test-maintenance", "Maintenance", "high", [], event, {}) is None
        assert db.get(Event, event.id) is not None
        db.get(AlertSuppression, row["id"]).expires_at = utcnow() - timedelta(seconds=1)
        db.flush()
        assert detection._raise_alert(db, managed, "test-maintenance", "Maintenance", "high", [], event, {}) is not None
        db.commit()
    assert client.get("/api/console/soc/suppressions", headers=admin).json() == []

def test_graph_sync_stops_at_total_deadline(monkeypatch):
    monkeypatch.setattr(m365, "monotonic", lambda: 121)
    with httpx.Client(transport=httpx.MockTransport(lambda request: pytest.fail("Request after deadline"))) as transport:
        with pytest.raises(ValueError, match="time budget"):
            m365.collect(transport, "https://graph.microsoft.com/v1.0/users", "token", deadline=120)

def test_backup_stale_and_future_completion(client, admin, tenant):
    plan = post(client, admin, "backup/plans", {"tenantId":tenant["id"],"name":"Archive","provider":"Provider","rpoHours":1})
    body = {"externalId":"old", "status":"success", "completedAt":(datetime.now(timezone.utc)-timedelta(hours=2)).isoformat()}
    post(client, admin, "backup/plans/"+plan["id"]+"/runs", body)
    assert client.get("/api/console/backup/plans", headers=admin).json()[0]["health"] == "stale"
    body.update(externalId="future", completedAt=(datetime.now(timezone.utc)+timedelta(hours=2)).isoformat())
    assert client.post("/api/console/backup/plans/"+plan["id"]+"/runs",headers=admin,json=body).status_code == 400


def test_grc_controls_combine_automatic_checks_and_register_evidence(client, admin, tenant):
    library = client.get(f"/api/console/grc/controls?tenant_id={tenant['id']}", headers=admin).json()["frameworks"]
    ce = next(f for f in library if f["framework"] == "cyber-essentials")
    access = next(c for c in ce["controls"] if c["id"] == "CE-3")
    assert access["status"] in ("met", "gap") and access["records"] == []
    gap = next(c for c in ce["controls"] if c["status"] == "gap")
    record = post(client, admin, "grc/records", {"tenantId": tenant["id"], "kind": "evidence", "title": "Signed access policy",
                                                 "framework": "Cyber Essentials", "control": f"{gap['id']} {gap['title']}"})
    library = client.get(f"/api/console/grc/controls?tenant_id={tenant['id']}", headers=admin).json()["frameworks"]
    linked = next(c for f in library if f["framework"] == "cyber-essentials" for c in f["controls"] if c["id"] == gap["id"])
    assert [r["id"] for r in linked["records"]] == [record["id"]] and linked["status"] == "gap"  # draft is not evidence yet
    # Unenforced policy switches never count as passing evidence.
    nist = next(f for f in library if f["framework"] == "nist-csf-2")
    recovery = next(c for c in nist["controls"] if c["id"] == "RC.RP")
    assert not recovery["passed"] and "not enforced" in recovery["evidence"][0]
