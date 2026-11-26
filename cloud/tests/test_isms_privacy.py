"""Privacy: records of processing with gaps and DPIA screening, DPIAs frozen once approved, and data subject requests
with their legal deadlines."""

from datetime import date, timedelta

import pytest
from conftest import login
from test_isms_soa import HALCYON, PW, person, programme

A = "/api/console/isms/privacy"


@pytest.fixture()
def ctx(client, admin, tenant):
    h = programme(client, admin, tenant, HALCYON)
    return h, tenant["id"]


def test_records_of_processing_and_dpia(client, admin, ctx):
    from fenrir_cloud import db as database
    from fenrir_cloud.isms.models import ApprovedDpia, IsmsDpia
    from fenrir_cloud.models import Vendor
    h, tid = ctx
    with database.session_factory()() as db:
        v = Vendor(tenant_id=tid, name="Payroll Bureau")
        db.add(v)
        db.commit()
        vid = v.id
    add = lambda **b: client.post(f"{A}/processing", headers=h, json={"tenantId": tid, "name": "Payroll", **b})  # noqa: E731
    assert add(name="x").status_code == 400
    assert add(lawfulBasis="vibes").status_code == 400
    assert add(supplierIds=["vnd_nope"]).status_code == 400
    p = add(purpose="Pay staff", lawfulBasis="contract", supplierIds=[vid], screening={"profiling": True}).json()
    assert p["ref"] == "ROPA-001" and p["suppliers"] == [{"id": vid, "name": "Payroll Bureau"}]
    assert p["dpiaRequired"] is False  # one weak indicator is not enough
    assert set(p["gaps"]) == {"Record how long the data is kept.", "List the categories of people.",
                              "List the categories of personal data."}
    p = client.patch(f"{A}/processing/{p['id']}", headers=h, json={**p, "screening": {"vulnerable": True, "profiling": True},
                     "retention": "6 years after leaving", "dataSubjects": ["Staff"], "dataCategories": ["Bank details"],
                     "transfers": True}).json()
    assert p["dpiaRequired"] is True and set(p["gaps"]) == {"Record the safeguard for international transfers.",
                                                            "Complete and approve a DPIA."}
    d = client.post(f"{A}/processing/{p['id']}/dpia", headers=h).json()
    assert d["ref"] == "DPIA-001" and client.post(f"{A}/processing/{p['id']}/dpia", headers=h).status_code == 400
    url = f"{A}/dpias/{d['id']}"
    assert client.post(f"{url}/approve", headers=h).json()["detail"].startswith("Describe the processing.")
    assert client.put(url, headers=h, json={"title": d["title"], "risks": [{"description": "Bank details leak", "likelihood": "medium", "severity": "extreme", "residual": "low"}]}).status_code == 400
    d = client.put(url, headers=h, json={"title": d["title"], "description": "Monthly payroll", "necessity": "Needed to pay staff",
                   "dpoAdvice": "Proceed", "outcome": "proceed_with_measures",
                   "risks": [{"description": "Bank details leak", "likelihood": "high", "severity": "high", "measures": "Encryption", "residual": "high"}]}).json()
    assert d["priorConsultation"] is True and d["risks"][0]["level"] == "high" and d["blockers"] == []
    person(client, admin, tid, "kim@acme.test", "control_owner")
    assert client.post(f"{url}/approve", headers=login(client, "kim@acme.test", PW)).status_code == 403
    d = client.post(f"{url}/approve", headers=h).json()
    assert d["status"] == "approved" and d["reviewOn"]
    assert client.put(url, headers=h, json={"title": "Changed"}).status_code == 400
    with database.session_factory()() as db:
        db.get(IsmsDpia, d["id"]).title = "Rewritten"
        with pytest.raises(ApprovedDpia):
            db.commit()
    p = client.get(f"{A}?tenant_id={tid}", headers=h).json()["processing"][0]
    assert p["gaps"] == ["Record the safeguard for international transfers."]
    assert client.patch(f"{A}/processing/{p['id']}", headers=h, json={"status": "retired"}).json()["gaps"] == []


def test_data_subject_requests(client, admin, ctx):
    h, tid = ctx
    today = date.today()
    add = lambda **b: client.post(f"{A}/requests", headers=h, json={"tenantId": tid, "type": "access", "requester": "J Smith", "receivedOn": today.isoformat(), **b})  # noqa: E731
    assert add(type="gossip").status_code == 400
    assert add(receivedOn=(today + timedelta(days=1)).isoformat()).status_code == 400
    r = add(receivedOn="2026-01-31").json()
    assert r["ref"] == "DSR-001" and r["dueOn"] == "2026-02-28" and r["overdue"] is (today > date(2026, 2, 28))
    url = f"{A}/requests/{r['id']}"
    assert client.post(f"{url}/verify", headers=h, json={"on": "2026-01-01"}).status_code == 400
    r = client.post(f"{url}/verify", headers=h, json={"on": "2026-02-02"}).json()
    assert r["clockStartsOn"] == "2026-02-02" and r["dueOn"] == "2026-03-02"
    assert client.post(f"{url}/extend", headers=h, json={"months": 3, "reason": "x"}).status_code == 400
    assert client.post(f"{url}/extend", headers=h, json={"months": 2, "reason": ""}).status_code == 400
    r = client.post(f"{url}/extend", headers=h, json={"months": 2, "reason": "Several thousand emails"}).json()
    assert r["dueOn"] == "2026-05-02"
    assert client.post(f"{url}/close", headers=h, json={"status": "refused", "response": ""}).json()["detail"].startswith("Record the reason for refusing")
    r = client.post(f"{url}/close", headers=h, json={"status": "completed", "response": "Copy sent by secure link"}).json()
    assert r["status"] == "completed" and r["closedOn"] == today.isoformat()
    assert client.post(f"{url}/extend", headers=h, json={"months": 1, "reason": "x"}).json()["detail"] == "This request is closed."
    events = client.get("/api/console/audit?limit=50", headers=admin).json()
    assert any(e["action"] == "isms.dsr_received" for e in events) and "J Smith" not in str(events)
    tiles = client.put("/api/console/isms/dashboard/layout", headers=h, json={"tenantId": tid, "tiles": ["privacy"]}).json()["tiles"]
    assert tiles[0]["value"] == "0 open requests"


def test_isolation(client, admin, ctx):
    h, tid = ctx
    p = client.post(f"{A}/processing", headers=h, json={"tenantId": tid, "name": "Payroll"}).json()
    r = client.post(f"{A}/requests", headers=h, json={"tenantId": tid, "type": "access", "requester": "J Smith", "receivedOn": date.today().isoformat()}).json()
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", "isms_manager")
    g = login(client, "isms@globex.test", PW)
    assert client.patch(f"{A}/processing/{p['id']}", headers=g, json={"status": "retired"}).status_code == 404
    assert client.post(f"{A}/requests/{r['id']}/close", headers=g, json={"status": "completed", "response": "x"}).status_code == 404
    assert client.get(f"{A}?tenant_id={tid}", headers=g).status_code == 404
