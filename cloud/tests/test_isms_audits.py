"""Internal audit: programmes, audits, checklists from the customer's frameworks, results, findings, completion,
coverage and reproducible sampling."""

from datetime import datetime, timedelta, timezone

import pytest
from conftest import login
from test_isms_soa import HALCYON, PW, person, programme

A = "/api/console/isms"


@pytest.fixture()
def ctx(client, admin, tenant):
    h = programme(client, admin, tenant, HALCYON)
    tid = tenant["id"]
    aud = client.post("/api/console/users", headers=admin, json={"tenantId": tid, "email": "auditor@acme.test", "password": PW,
                                                                 "name": "Ada", "role": "tenant_analyst"}).json()
    expires = (datetime.now(timezone.utc) + timedelta(days=60)).isoformat()
    assert client.put("/api/console/isms/memberships", headers=admin, json={"tenantId": tid, "userId": aud["id"], "role": "auditor",
                                                                           "expiresAt": expires}).status_code == 200
    kim = person(client, admin, tid, "kim@acme.test", "control_owner")
    prog = client.post(f"{A}/audit-programmes", headers=h, json={"tenantId": tid, "title": "Audit programme 2027",
                                                                 "periodStart": "2027-01-01", "periodEnd": "2027-12-31"}).json()
    return h, login(client, "auditor@acme.test", PW), login(client, "kim@acme.test", PW), aud, kim, tid, prog


def plan(client, h, prog, aud, **extra):
    body = {"title": "Clauses and people controls", "frameworks": ["iso27001"], "plannedStart": "2027-03-01",
            "plannedEnd": "2027-03-03", "leadAuditorId": aud["id"], "independenceNote": "External consultant", **extra}
    return client.post(f"{A}/audit-programmes/{prog['id']}/audits", headers=h, json=body)


def test_programme_and_audit_validation(client, admin, ctx):
    h, ah, kh, aud, kim, tid, prog = ctx
    bad = lambda **b: client.post(f"{A}/audit-programmes", headers=h, json={"tenantId": tid, "title": "Other", "periodStart": "2027-01-01", "periodEnd": "2027-12-31", **b})  # noqa: E731
    assert bad(title="Audit programme 2027").json()["detail"] == "A programme with that title already exists."
    assert bad(periodEnd="2026-12-31").json()["detail"] == "The period must end after it starts."
    assert plan(client, h, prog, aud, plannedStart="2028-02-01", plannedEnd="2028-02-02").json()["detail"] == "Plan the audit inside the programme period."
    assert plan(client, h, prog, aud, frameworks=["soc2-2017"]).json()["detail"] == "Audit only frameworks in this customer's programme."
    assert plan(client, h, prog, aud, frameworks=[]).status_code == 400
    outsider = client.post("/api/console/users", headers=admin, json={"tenantId": tid, "email": "x@acme.test", "password": PW, "name": "X", "role": "tenant_analyst"}).json()
    assert plan(client, h, prog, aud, leadAuditorId=outsider["id"]).status_code == 400
    assert plan(client, ah, prog, aud).status_code == 403  # auditors do not plan
    a = plan(client, h, prog, aud).json()
    assert (a["ref"], a["status"], a["checks"]) == ("AUD-001", "planned", [])
    assert plan(client, h, prog, aud).json()["ref"] == "AUD-002"


def test_audit_from_checklist_to_completion(client, admin, ctx):
    h, ah, kh, aud, kim, tid, prog = ctx
    a = plan(client, h, prog, aud).json()
    url = f"{A}/audits/{a['id']}"
    assert client.post(f"{url}/start", headers=ah).json()["detail"] == "Generate the checklist before starting."
    a = client.post(f"{url}/checklist", headers=h, json={"groups": ["clause-9", "annex-a-6"]}).json()
    refs = [c["ref"] for c in a["checks"]]
    assert "9.2.1" in refs and "A.6.3" in refs and not any(r.startswith(("A.5", "A.8", "4.")) for r in refs)
    assert all(c["mandatory"] for c in a["checks"] if not c["ref"].startswith("A."))
    check = {c["ref"]: c for c in a["checks"]}
    assert client.put(f"{A}/audit-checks/{check['9.2.1']['id']}", headers=ah, json={"result": "conforms"}).json()["detail"] == "Start the audit to record results."
    a = client.post(f"{url}/start", headers=ah).json()
    assert a["status"] == "in_progress"
    assert client.put(f"{A}/audit-checks/{check['A.6.3']['id']}", headers=ah, json={"result": "minor"}).json()["detail"] == "Describe what was found."
    assert client.put(f"{A}/audit-checks/{check['A.6.3']['id']}", headers=kh, json={"result": "conforms"}).status_code == 403
    for ref, c in check.items():
        result = {"A.6.3": "minor", "9.3.1": "observation"}.get(ref, "conforms")
        r = client.put(f"{A}/audit-checks/{c['id']}", headers=ah, json={"result": result, "notes": "Two starters had no training record" if result != "conforms" else "", "evidenceSeen": "Training log"})
        assert r.status_code == 200, (ref, r.text)
    done = lambda s: client.post(f"{url}/complete", headers=ah, json={"summary": s})  # noqa: E731
    assert done("").json()["detail"] == "Write the audit summary."
    assert "A.6.3" in done("Good overall").json()["detail"]
    a = client.post(f"{A}/audit-checks/{check['A.6.3']['id']}/finding", headers=ah, json={"ownerId": kim["id"]}).json()
    f = next(c for c in a["checks"] if c["ref"] == "A.6.3")["findings"][0]
    assert f["ref"] == "NC-001"
    assert client.post(f"{A}/audit-checks/{check['A.6.3']['id']}/finding", headers=ah, json={}).json()["detail"] == "A finding has already been raised for this item."
    assert client.post(f"{A}/audit-checks/{check['9.2.1']['id']}/finding", headers=ah, json={}).status_code == 400
    ncs = client.get(f"{A}/nonconformities?tenant_id={tid}", headers=h).json()["nonconformities"]
    assert ncs[0]["source"] == "internal_audit" and ncs[0]["severity"] == "minor" and ncs[0]["ownerName"] == "Kim"
    a = done("Good overall; one minor finding on training records.").json()
    assert a["status"] == "completed" and a["counts"]["minor"] == 1 and a["counts"]["observation"] == 1
    # A completed audit is a record.
    assert client.put(f"{A}/audit-checks/{check['9.2.1']['id']}", headers=ah, json={"result": "major", "notes": "x"}).status_code == 400
    assert client.patch(url, headers=h, json={**a, "title": "Changed"}).json()["detail"] == "A completed audit cannot change."
    assert client.post(f"{url}/checklist", headers=h, json={}).status_code == 400
    assert client.delete(url, headers=h).status_code == 400
    p = client.get(f"{A}/audit-programmes?tenant_id={tid}", headers=h).json()["programmes"][0]
    assert p["audits"][0]["findings"] == 1
    assert 0 < p["coverage"]["covered"] < p["coverage"]["required"]
    actions = [e["action"] for e in client.get("/api/console/audit?limit=200", headers=admin).json()]
    for x in ("isms.audit_planned", "isms.audit_checklist_generated", "isms.audit_started", "isms.audit_check_recorded", "isms.audit_completed"):
        assert x in actions


def test_the_database_guard_freezes_completed_audits(client, admin, ctx):
    from fenrir_cloud import db as database
    from fenrir_cloud.isms.models import CompletedAudit, IsmsAudit, IsmsAuditCheck
    from sqlalchemy import select

    h, ah, kh, aud, kim, tid, prog = ctx
    a = plan(client, h, prog, aud).json()
    with database.session_factory()() as db:
        row = db.get(IsmsAudit, a["id"])
        row.status = "completed"
        db.add(IsmsAuditCheck(tenant_id=tid, audit_id=row.id, framework="iso27001", requirement_ref="9.2", requirement_title="Internal audit"))
        db.commit()
        row.summary = "rewritten"
        with pytest.raises(CompletedAudit):
            db.commit()
        db.rollback()
        c = db.execute(select(IsmsAuditCheck).where(IsmsAuditCheck.audit_id == row.id)).scalar_one()
        c.result = "major"
        with pytest.raises(CompletedAudit):
            db.commit()


def test_planned_audits_can_be_deleted_and_refreshed(client, admin, ctx):
    h, ah, kh, aud, kim, tid, prog = ctx
    a = plan(client, h, prog, aud).json()
    url = f"{A}/audits/{a['id']}"
    n = len(client.post(f"{url}/checklist", headers=h, json={"groups": ["clause-9"]}).json()["checks"])
    assert len(client.post(f"{url}/checklist", headers=h, json={"groups": ["clause-10"]}).json()["checks"]) != n
    assert client.delete(url, headers=h).json() == {"ok": True}
    assert client.get(url, headers=h).status_code == 404


def test_sampling_is_reproducible(client, admin, ctx):
    h, ah, kh, aud, kim, tid, prog = ctx
    pop = [f"Leaver {i}" for i in range(40)]
    one = client.post(f"{A}/audit-sample", headers=ah, json={"tenantId": tid, "population": pop, "seed": "AUD-001 A.6.5"}).json()
    two = client.post(f"{A}/audit-sample", headers=ah, json={"tenantId": tid, "population": list(reversed(pop)), "seed": "AUD-001 A.6.5"}).json()
    assert one["items"] == two["items"] and one["size"] == 10 == one["suggested"]
    assert client.post(f"{A}/audit-sample", headers=ah, json={"tenantId": tid, "population": pop, "seed": " "}).status_code == 400
    assert client.post(f"{A}/audit-sample", headers=kh, json={"tenantId": tid, "population": pop, "seed": "x"}).status_code == 403


def test_isolation(client, admin, ctx):
    h, ah, kh, aud, kim, tid, prog = ctx
    a = plan(client, h, prog, aud).json()
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", "isms_manager")
    g = login(client, "isms@globex.test", PW)
    assert client.get(f"{A}/audits/{a['id']}", headers=g).status_code == 404
    assert client.patch(f"{A}/audit-programmes/{prog['id']}", headers=g, json={"title": "x"}).status_code == 404
    assert client.get(f"{A}/audit-programmes?tenant_id={tid}", headers=g).status_code == 404
