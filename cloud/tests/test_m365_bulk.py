"""M365-30: cross-tenant bulk and scheduled actions."""
from contextlib import contextmanager
from datetime import timedelta

import pytest

from conftest import login
from test_documentation_vault import stepup
from test_msp_modules import connection
from fenrir_cloud import db as database, m365_admin as provider, m365_bulk, m365_standards
from fenrir_cloud.models import AuditLog, M365BulkItem, M365BulkJob, M365Connection, User, utcnow

USERS = ["00000000-0000-0000-0000-0000000000a1", "00000000-0000-0000-0000-0000000000b1", "00000000-0000-0000-0000-0000000000c1"]
URL = "/api/console/m365/bulk-jobs"


def customer(client, admin, name):
    t = client.post("/api/console/tenants", json={"name": name, "template": "balanced"}, headers=admin).json()
    return t, connection(client, admin, t)


@pytest.fixture
def three(client, admin):
    return [customer(client, admin, n) for n in ("Alpha Ltd", "Bravo Ltd", "Charlie Ltd")]


def targets(three):
    return [{"connectionId": conn["id"], "targetId": USERS[i], "label": f"user{i}"} for i, (_, conn) in enumerate(three)]


def create(client, headers, body, status=200):
    r = client.post(URL, headers=headers, json=body)
    assert r.status_code == status, r.text
    return r.json()


def test_bulk_job_snapshot_throttling_partial_results_and_audit(client, admin, three, monkeypatch):
    calls = []
    throttled = {"done": False}

    def execute(conn, op, target, params):
        calls.append((conn.tenant_id, target))
        with database.session_factory()() as db:  # checkpoint: the claim is committed before the provider call
            assert db.query(M365BulkItem).filter_by(target_id=target).one().status == "running"
        if target == USERS[1] and not throttled["done"]:
            throttled["done"] = True
            raise provider.ProviderError("Microsoft throttled the action.", retry_after=120)
        if target == USERS[2]:
            raise provider.ProviderError("Microsoft's result is unknown.", uncertain=True)
        return "succeeded", {"user": {"id": target, "accountEnabled": False, "displayName": "kept out"}}

    monkeypatch.setattr(provider, "execute", execute)
    body = {"operation": "user.signin", "parameters": {"accountEnabled": False}, "name": "Block leavers",
            "targets": targets(three) + [{"connectionId": "m365_nope", "targetId": USERS[0]},
                                         {"connectionId": three[0][1]["id"], "targetId": "not-a-guid"}]}
    preview = client.post(URL + "/preview", headers=admin, json={k: body[k] for k in ("operation", "parameters", "targets")}).json()
    assert len(preview["eligible"]) == 3 and len(preview["excluded"]) == 2
    assert {e["reason"] for e in preview["excluded"]} == {"No such Microsoft 365 connection in a customer you manage", "Not a Microsoft user ID"}

    assert client.post(URL, headers=admin, json={**body, "confirmCount": 3}).status_code == 403  # writes need step-up
    proof = stepup(client, admin)
    create(client, proof, {**body, "confirmCount": 5}, status=409)  # typed count must match the eligible targets
    job = create(client, proof, {**body, "confirmCount": 3})
    assert job["status"] == "queued" and len(job["targets"]) == 3 and len(job["excluded"]) == 2
    assert len(job["targetsHash"]) == 64 and job["summary"]["verified"] is True

    out = client.post(f"{URL}/{job['id']}/run", headers=admin).json()
    items = {i["targetId"]: i for i in out["job"]["items"]}
    assert items[USERS[0]]["status"] == "succeeded"
    assert items[USERS[1]]["status"] == "pending" and items[USERS[1]]["result"]["throttled"] and items[USERS[1]]["notBefore"]
    assert items[USERS[2]]["status"] == "unknown"  # never replayed
    assert out["more"] is False and out["waitingUntil"] and out["job"]["status"] == "running"
    assert "displayName" not in items[USERS[0]]["result"]["user"]

    # Retry-After has passed: only the throttled tenant's item runs again.
    with database.session_factory()() as db:
        db.query(M365BulkItem).filter_by(target_id=USERS[1]).update({"not_before": utcnow() - timedelta(seconds=1)})
        db.commit()
    out = client.post(f"{URL}/{job['id']}/run", headers=admin).json()
    assert out["job"]["status"] == "partial"
    counts = out["job"]["summary"]["counts"]
    assert counts == {"succeeded": 2, "unknown": 1}
    tenants = out["job"]["summary"]["tenants"]
    assert tenants[three[2][0]["id"]]["counts"] == {"unknown": 1} and tenants[three[0][0]["id"]]["counts"] == {"succeeded": 1}
    assert [c[1] for c in calls] == [USERS[0], USERS[1], USERS[2], USERS[1]]

    # The unknown item: reconcile reads the user and settles it.
    @contextmanager
    def session(conn):
        yield None, {}

    monkeypatch.setattr(provider, "session", session)
    monkeypatch.setattr(provider, "user", lambda client_, headers, ident: {"id": ident, "accountEnabled": False})
    rec = client.post(f"{URL}/{job['id']}/reconcile", headers=admin).json()
    assert rec["settled"] == 1 and rec["job"]["status"] == "completed"
    with database.session_factory()() as db:
        assert db.query(AuditLog).filter_by(action="m365.bulk_created").count() == 1
        per_tenant = db.query(AuditLog).filter_by(action="m365.bulk_tenant_result").all()
        assert {a.tenant_id for a in per_tenant} == {t["id"] for t, _ in three}


def test_cancel_stops_new_items(client, admin, three, monkeypatch):
    monkeypatch.setattr(provider, "execute", lambda *a: pytest.fail("cancelled job ran"))
    proof = stepup(client, admin)
    job = create(client, proof, {"operation": "user.revoke_sessions", "parameters": {}, "targets": targets(three), "confirmCount": 3})
    out = client.post(f"{URL}/{job['id']}/cancel", headers=admin).json()
    assert out["status"] == "cancelled" and out["summary"]["counts"] == {"cancelled": 3}
    assert client.post(f"{URL}/{job['id']}/cancel", headers=admin).status_code == 409
    assert client.post(f"{URL}/{job['id']}/run", headers=admin).json()["status"] == "cancelled"


def test_crashed_item_becomes_unknown_and_can_be_resolved(client, admin, three, monkeypatch):
    monkeypatch.setattr(provider, "execute", lambda conn, op, target, params: ("succeeded", {}))
    proof = stepup(client, admin)
    job = create(client, proof, {"operation": "user.revoke_sessions", "parameters": {}, "targets": targets(three)[:1], "confirmCount": 1})
    with database.session_factory()() as db:  # a worker claimed the item and died
        db.query(M365BulkItem).filter_by(job_id=job["id"]).update({"status": "running", "started_at": utcnow() - timedelta(hours=1)})
        db.commit()
    out = client.post(f"{URL}/{job['id']}/run", headers=admin).json()
    item = out["job"]["items"][0]
    assert item["status"] == "unknown" and out["job"]["status"] == "partial"
    # Revocation leaves no state to read, so reconciliation cannot settle it; a technician does.
    assert client.post(f"{URL}/{job['id']}/reconcile", headers=admin).json()["unresolved"] == 1
    url = f"{URL}/{job['id']}/items/{item['id']}/resolve"
    assert client.post(url, headers=admin, json={"outcome": "retry"}).status_code == 403  # a write retry needs step-up
    done = client.post(url, headers=admin, json={"outcome": "succeeded"}).json()
    assert done["status"] == "completed" and done["items"][0]["resolvedBy"]


def test_scheduled_job_starts_at_its_time(client, admin, three, monkeypatch):
    monkeypatch.setattr(m365_standards, "evaluate", lambda conn, standard, options=None: {"status": "drifted", "detail": "No policy"})
    when = (utcnow() + timedelta(hours=2)).isoformat() + "Z"
    targets_ = [{"connectionId": c["id"]} for _, c in three]
    job = create(client, admin, {"operation": "standard.evaluate", "parameters": {"standard": "mfa.admins"}, "targets": targets_,
                                 "confirmCount": 3, "scheduledFor": when})  # read-only: no step-up
    assert job["status"] == "scheduled"
    assert client.post(f"{URL}/{job['id']}/run", headers=admin).status_code == 409
    with database.session_factory()() as db:
        assert m365_bulk.tick(db) == 0
        db.query(M365BulkJob).filter_by(id=job["id"]).update({"scheduled_for": utcnow() - timedelta(minutes=1)})
        db.commit()
        m365_bulk.tick(db)
    out = client.get(f"{URL}/{job['id']}", headers=admin).json()
    assert out["status"] == "completed" and {i["result"]["compliance"] for i in out["items"]} == {"drifted"}


def test_deploy_skips_compliant_tenants_and_reports_failures_per_tenant(client, admin, three, monkeypatch):
    state = {three[0][1]["id"]: "compliant", three[1][1]["id"]: "drifted", three[2][1]["id"]: "drifted"}
    deployed = []
    monkeypatch.setattr(m365_standards, "evaluate", lambda conn, standard, options=None: {"status": state[conn.id], "detail": ""})

    def deploy(conn, standard, options=None):
        if conn.id == three[2][1]["id"]:
            raise m365_standards.StandardError("Licence missing for Conditional Access")
        deployed.append(conn.id)
        return {"detail": "Report-only policy created"}

    monkeypatch.setattr(m365_standards, "deploy", deploy)
    proof = stepup(client, admin)
    job = create(client, proof, {"operation": "standard.deploy", "parameters": {"standard": "mfa.admins"},
                                 "targets": [{"connectionId": c["id"]} for _, c in three], "confirmCount": 3})
    out = client.post(f"{URL}/{job['id']}/run", headers=admin).json()["job"]
    assert out["status"] == "partial" and deployed == [three[1][1]["id"]]
    by = {i["connectionId"]: i for i in out["items"]}
    assert by[three[0][1]["id"]]["status"] == "skipped" and by[three[2][1]["id"]]["result"]["message"].startswith("Licence missing")


def test_scope_and_runtime_authority(client, admin, tenant, three, monkeypatch):
    calls = []
    monkeypatch.setattr(provider, "execute", lambda conn, op, target, params: calls.append(target) or ("succeeded", {}))
    created = client.post("/api/console/users", headers=admin, json={"tenantId": three[0][0]["id"], "email": "tech@alpha.example",
                                                                    "password": "alpha-password-123", "role": "tenant_admin"})
    assert created.status_code == 200, created.text
    tech = login(client, "tech@alpha.example", "alpha-password-123")
    preview = client.post(URL + "/preview", headers=tech, json={"operation": "user.revoke_sessions", "parameters": {}, "targets": targets(three)})
    assert preview.status_code in (200, 403)
    if preview.status_code == 200:  # their own customer only; the others are left out with the reason
        assert len(preview.json()["eligible"]) == 1 and len(preview.json()["excluded"]) == 2

    proof = stepup(client, admin)
    job = create(client, proof, {"operation": "user.revoke_sessions", "parameters": {}, "targets": targets(three), "confirmCount": 3})
    assert client.get(f"{URL}/{job['id']}", headers=tech).status_code in (403, 404)
    # The creator loses access before the job runs: every item is skipped with the reason, nothing is sent.
    with database.session_factory()() as db:
        row = db.get(M365BulkJob, job["id"])
        db.query(User).filter_by(id=row.created_by_user_id).update({"role": "viewer"})
        db.commit()
        m365_bulk.run(db, row, "system:test")
        assert calls == [] and row.status == "failed"
        items = m365_bulk.items(db, row)
        assert {i.status for i in items} == {"skipped"} and "no longer has" in items[0].result["message"]


def test_tampered_snapshot_is_refused(client, admin, three, monkeypatch):
    monkeypatch.setattr(provider, "execute", lambda *a: pytest.fail("tampered job ran"))
    proof = stepup(client, admin)
    job = create(client, proof, {"operation": "user.revoke_sessions", "parameters": {}, "targets": targets(three), "confirmCount": 3})
    with database.session_factory()() as db:
        row = db.get(M365BulkJob, job["id"])
        row.targets = row.targets[:1]
        db.commit()
    out = client.post(f"{URL}/{job['id']}/run", headers=admin).json()
    assert out["status"] == "failed" and "does not match" in out["job"]["summary"]["error"]


def test_connection_without_permission_is_excluded(client, admin, three):
    with database.session_factory()() as db:
        conn = db.get(M365Connection, three[1][1]["id"])
        conn.snapshot = {"permissions": {"features": [{"key": "user.signin", "available": False}]}}
        db.commit()
    preview = client.post(URL + "/preview", headers=admin, json={"operation": "user.signin", "parameters": {"accountEnabled": False},
                                                               "targets": targets(three)}).json()
    assert [e["connectionId"] for e in preview["excluded"]] == [three[1][1]["id"]]
