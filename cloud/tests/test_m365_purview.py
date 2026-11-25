"""M365-27: Purview label inventory, template drift and two-person reviewed deployment."""
import json

import httpx
import pytest

from conftest import login
from test_documentation_vault import stepup
from test_msp_modules import connection
from fenrir_cloud import db as database, m365, m365_purview as pv
from fenrir_cloud.models import AuditLog

REAL = httpx.Client
URL = "/api/console/m365/purview"


@pytest.fixture
def purview(monkeypatch):
    state = {"labels": [{"id": "rl1", "displayName": "Finance 7 years", "retentionDuration": {"days": 2555},
                         "actionAfterRetentionPeriod": "delete", "behaviorDuringRetentionPeriod": "retain", "retentionTrigger": "dateLabeled"}],
             "deny_sensitivity": False, "posts": []}

    def handler(request: httpx.Request):
        if "/beta/security/informationProtection/sensitivityLabels" in str(request.url):
            if state["deny_sensitivity"]:
                return httpx.Response(403)
            return httpx.Response(200, json={"value": [{"id": "s1", "name": "Confidential", "sensitivity": 2, "isActive": True}]})
        if request.url.path == "/v1.0/security/labels/retentionLabels":
            if request.method == "POST":
                body = json.loads(request.content)
                state["posts"].append(body)
                label = {**body, "id": f"rl{len(state['labels']) + 1}"}
                state["labels"].append(label)
                return httpx.Response(201, json=label)
            return httpx.Response(200, json={"value": state["labels"]})
        return httpx.Response(404)

    monkeypatch.setattr(pv, "_client", lambda: REAL(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(m365, "access_token", lambda client, conn, *a, **k: "token")
    return state


def test_drift_and_second_person_review(client, admin, tenant, purview):
    conn = connection(client, admin, tenant)
    base = client.post(f"{URL}/baselines", headers=admin, json={"tenantId": tenant["id"], "name": "Standard", "retentionLabels": [
        {"displayName": "Finance 7 years", "retentionDurationDays": 2190, "actionAfterRetentionPeriod": "delete"},
        {"displayName": "HR records", "retentionDurationDays": 2190, "behaviorDuringRetentionPeriod": "retainAsRecord"}]}).json()
    inv = client.post(f"{URL}/connections/{conn['id']}/inventory", headers=admin).json()
    assert inv["data"]["sensitivityLabels"][0]["name"] == "Confidential" and "dlpPolicies" in inv["data"]["unavailable"]
    st = client.get(f"{URL}/connections/{conn['id']}", headers=admin, params={"baselineId": base["id"]}).json()
    items = {i["label"]: i for i in st["drift"]["items"]}
    assert st["drift"]["status"] == "drifted" and items["HR records"]["state"] == "missing"
    assert items["Finance 7 years"]["differences"] == [{"field": "retentionDurationDays", "template": 2190, "tenant": 2555}]

    change = client.post(f"{URL}/connections/{conn['id']}/changes", headers=admin, json={"baselineId": base["id"]}).json()
    assert [(p["label"], p["action"]) for p in change["plan"]] == [("Finance 7 years", "review"), ("HR records", "create")]
    proof = stepup(client, admin)
    r = client.post(f"{URL}/changes/{change['id']}/review", headers=proof, json={"approve": True})
    assert r.status_code == 409 and "second person" in r.json()["detail"] and purview["posts"] == []

    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "lead@acme.example",
                                                           "password": "lead-password-1234", "role": "tenant_admin"})
    lead = login(client, "lead@acme.example", "lead-password-1234")
    assert client.post(f"{URL}/changes/{change['id']}/review", headers=lead, json={"approve": True}).status_code == 403  # step-up
    lead_proof = client.post("/api/console/auth/reauth", headers=lead, json={"password": "lead-password-1234"}).json()["reauthToken"]
    done = client.post(f"{URL}/changes/{change['id']}/review", headers={**lead, "X-Fenrir-Reauth": lead_proof},
                       json={"approve": True, "note": "Matches the retention schedule"}).json()
    assert done["status"] == "completed" and done["reviewedBy"] == "lead@acme.example"
    assert {r["label"]: r["status"] for r in done["results"]} == {"Finance 7 years": "left for a person", "HR records": "created"}
    posted = purview["posts"][0]
    assert posted["retentionDuration"]["days"] == 2190 and posted["defaultRecordBehavior"] == "startLocked"
    assert client.post(f"{URL}/changes/{change['id']}/review", headers=admin, json={"approve": False}).status_code == 409
    with database.session_factory()() as db:
        assert db.query(AuditLog).filter_by(action="m365.purview_change_applied").count() == 1


def test_unreadable_items_are_unavailable_not_compliant(client, admin, tenant, purview):
    conn = connection(client, admin, tenant)
    purview["deny_sensitivity"] = True
    inv = client.post(f"{URL}/connections/{conn['id']}/inventory", headers=admin).json()
    assert inv["data"]["sensitivityLabels"] is None and "denied" in inv["data"]["unavailable"]["sensitivityLabels"]
    bad = client.post(f"{URL}/baselines", headers=admin, json={"tenantId": tenant["id"], "name": "x",
                                                              "retentionLabels": [{"displayName": "Bad", "retentionDurationDays": 0}]})
    assert bad.status_code == 400
