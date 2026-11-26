"""ISMS improvement (nonconformities, corrective actions), objectives and metrics, and the ISMS change log."""

from datetime import timedelta

import pytest
from conftest import login

PW = "a-long-password-123"


def person(client, admin, tenant_id, email, isms_role):
    user = client.post("/api/console/users", headers=admin, json={"tenantId": tenant_id, "email": email, "password": PW,
                                                                  "name": email.split("@")[0].title(),
                                                                  "role": "tenant_analyst"}).json()
    assert client.put("/api/console/isms/memberships", headers=admin,
                      json={"tenantId": tenant_id, "userId": user["id"], "role": isms_role}).status_code == 200
    return user


@pytest.fixture()
def ctx(client, admin, tenant):
    person(client, admin, tenant["id"], "isms@acme.test", "isms_manager")
    kim = person(client, admin, tenant["id"], "kim@acme.test", "control_owner")
    return login(client, "isms@acme.test", PW), login(client, "kim@acme.test", PW), kim, tenant["id"]


def test_nonconformity_workflow_to_an_effective_close(client, admin, ctx):
    h, kim_h, kim, tid = ctx
    raise_ = lambda **b: client.post("/api/console/isms/nonconformities", headers=h, json={"tenantId": tid, **b})  # noqa: E731
    assert raise_(title="x", source="internal_audit", severity="minor").status_code == 400
    assert raise_(title="Log reviews missed", source="internal_audit").status_code == 400  # needs a severity
    nc = raise_(title="Log reviews missed", source="internal_audit", severity="minor", requirementRef="A.8.15").json()
    assert (nc["ref"], nc["stage"]) == ("NC-001", "needs_root_cause")
    url = f"/api/console/isms/nonconformities/{nc['id']}"
    eff = lambda **b: client.post(f"{url}/effectiveness", headers=h, json=b)  # noqa: E731
    assert eff(effective=True, note="Checked").json()["detail"] == "Record the root cause. Plan at least one corrective action."
    client.patch(url, headers=h, json={"title": nc["title"], "source": "internal_audit", "severity": "minor",
                                       "rootCause": "No owner for the weekly review"})
    due = "2026-12-31"
    nc = client.post(f"{url}/actions", headers=h, json={"description": "Assign the weekly review to Kim", "ownerId": kim["id"], "dueOn": due}).json()
    assert nc["stage"] == "actions_in_progress"
    action = nc["actions"][0]["id"]
    assert client.post(f"/api/console/isms/corrective-actions/{action}/done", headers=kim_h, json={"note": "Done"}).status_code == 200
    assert eff(effective=False, note="Reviews still missed in week 2").json()["status"] == "open"
    closed = eff(effective=True, note="Four weeks of reviews on file").json()
    assert (closed["status"], closed["effective"]) == ("closed", True)
    assert client.patch(url, headers=h, json={"title": "x y z", "source": "other", "severity": "minor"}).status_code == 400
    assert client.post(f"{url}/close", headers=h, json={"outcome": "cancelled", "note": "x"}).status_code == 400


def test_opportunities_close_with_a_note(client, admin, ctx):
    h, kim_h, kim, tid = ctx
    ofi = client.post("/api/console/isms/nonconformities", headers=h, json={
        "tenantId": tid, "kind": "opportunity", "title": "Automate access reviews", "source": "management_review"}).json()
    assert ofi["ref"] == "OFI-001" and ofi["severity"] is None
    url = f"/api/console/isms/nonconformities/{ofi['id']}"
    assert client.post(f"{url}/actions", headers=h, json={"description": "x y", "dueOn": "2027-01-01"}).status_code == 400
    assert client.post(f"{url}/close", headers=h, json={"outcome": "closed", "note": "Done in Entra"}).json()["status"] == "closed"
    actions = [e["action"] for e in client.get("/api/console/audit?limit=50", headers=admin).json()]
    assert "isms.nonconformity_raised" in actions and "isms.nonconformity_closed" in actions


def test_objectives_and_measurements(client, admin, ctx):
    h, kim_h, kim, tid = ctx
    base = {"tenantId": tid, "title": "Patch critical updates quickly", "measure": "Median days to patch",
            "unit": "days", "direction": "at_most", "target": 14, "ownerId": kim["id"], "frequency": "monthly"}
    assert client.post("/api/console/isms/objectives", headers=h, json={**base, "direction": "sideways"}).status_code == 400
    assert client.post("/api/console/isms/objectives", headers=h, json={**base, "target": "lots"}).status_code == 400
    o = client.post("/api/console/isms/objectives", headers=h, json=base).json()
    assert (o["ref"], o["summary"]["health"]) == ("OBJ-001", "no_data")
    url = f"/api/console/isms/objectives/{o['id']}/values"
    from fenrir_cloud.models import utcnow
    today = utcnow().date()
    assert client.post(url, headers=kim_h, json={"measuredOn": (today + timedelta(days=2)).isoformat(), "value": 3}).status_code == 400
    client.post(url, headers=kim_h, json={"measuredOn": (today - timedelta(days=40)).isoformat(), "value": 20})
    o = client.post(url, headers=kim_h, json={"measuredOn": today.isoformat(), "value": 9}).json()
    assert o["summary"] == {"latest": {"measuredOn": today.isoformat(), "value": 9.0}, "health": "met", "trend": "improving",
                            "stale": False}
    assert client.patch(f"/api/console/isms/objectives/{o['id']}", headers=h, json={"status": "achieved"}).status_code == 400
    assert client.patch(f"/api/console/isms/objectives/{o['id']}", headers=h, json={"status": "achieved", "note": "Stable for a year"}).json()["status"] == "achieved"
    assert client.post(url, headers=kim_h, json={"measuredOn": today.isoformat(), "value": 5}).status_code == 400
    person(client, admin, tid, "sam@acme.test", "staff")
    assert client.get(f"/api/console/isms/objectives?tenant_id={tid}", headers=login(client, "sam@acme.test", PW)).status_code == 403


def test_change_log(client, admin, ctx):
    h, kim_h, kim, tid = ctx
    c = client.post("/api/console/isms/changes", headers=h, json={"tenantId": tid, "title": "Move to Intune",
                                                                  "purpose": "Manage every laptop centrally"}).json()
    assert (c["ref"], c["status"]) == ("CHG-001", "planned")
    url = f"/api/console/isms/changes/{c['id']}"
    assert client.patch(url, headers=h, json={**c, "status": "done"}).status_code == 400  # needs completion and outcome
    done = client.patch(url, headers=h, json={"title": c["title"], "purpose": c["purpose"], "status": "done",
                                              "completedOn": "2026-11-20", "outcome": "All 40 laptops enrolled"}).json()
    assert (done["status"], done["outcome"]) == ("done", "All 40 laptops enrolled")
    assert client.post("/api/console/isms/changes", headers=kim_h, json={"tenantId": tid, "title": "x y z", "purpose": "p"}).status_code == 403


def test_isolation(client, admin, ctx):
    h, kim_h, kim, tid = ctx
    nc = client.post("/api/console/isms/nonconformities", headers=h, json={"tenantId": tid, "title": "Missed review",
                                                                           "source": "other", "severity": "minor"}).json()
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", "isms_manager")
    g = login(client, "isms@globex.test", PW)
    assert client.patch(f"/api/console/isms/nonconformities/{nc['id']}", headers=g, json={"title": "x"}).status_code == 404
    assert client.get(f"/api/console/isms/nonconformities?tenant_id={tid}", headers=g).status_code == 404
