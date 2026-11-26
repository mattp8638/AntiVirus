"""Management review: the pack from live data, recording the meeting (which freezes it), actions that feed the next
review, and the minutes document."""

from datetime import date, timedelta

import pytest
from conftest import login
from test_isms_documents import PW, generate, person

A = "/api/console/isms"


@pytest.fixture()
def ctx(client, admin, tenant):
    tid = tenant["id"]
    person(client, admin, tid, "isms@acme.test", "isms_manager")
    kim = person(client, admin, tid, "kim@acme.test", "control_owner")
    h = login(client, "isms@acme.test", PW)
    client.put(f"{A}/programme/frameworks", headers=h, json={"tenantId": tid, "frameworks": {"iso27001": {}}})
    client.post(f"{A}/programme/apply", headers=h, json={"tenantId": tid, "answers": {"develops_software": False}})
    return h, login(client, "kim@acme.test", PW), kim, tid


def test_pack_meeting_and_actions(client, admin, ctx):
    from fenrir_cloud import db as database
    from fenrir_cloud.isms.models import HeldReview, IsmsManagementReview

    h, kh, kim, tid = ctx
    today = date.today()
    client.post(f"{A}/registers/context-issues", headers=h, json={"tenantId": tid, "kind": "external", "description": "New supplier rules"})
    client.post(f"{A}/nonconformities", headers=h, json={"tenantId": tid, "title": "Customer complaint about access",
                                                         "source": "complaint", "severity": "major"})
    client.post(f"{A}/nonconformities", headers=h, json={"tenantId": tid, "kind": "opportunity", "title": "Automate reviews", "source": "monitoring"})
    assert client.post(f"{A}/reviews", headers=h, json={"tenantId": tid, "title": "x", "plannedOn": today.isoformat()}).status_code == 400
    r = client.post(f"{A}/reviews", headers=h, json={"tenantId": tid, "title": "Annual review 2026", "plannedOn": today.isoformat()}).json()
    assert r["ref"] == "MR-001" and r["pack"] is None
    from fenrir_cloud.isms.domain.review import review_period_start
    assert r["periodStart"] == review_period_start(today.isoformat(), None)  # a year back when nothing was held
    url = f"{A}/reviews/{r['id']}"
    r = client.post(f"{url}/pack", headers=h, json={"feedback": "Board wants quarterly reports"}).json()
    inputs = r["pack"]["inputs"]
    assert r["missing"] == [] and inputs["party_feedback"]["notes"] == "Board wants quarterly reports"
    assert inputs["issue_changes"]["changes"][0] == {**inputs["issue_changes"]["changes"][0], "action": "added", "text": "New supplier rules"}
    assert inputs["nonconformities"]["majorOpen"] == 1 and inputs["party_feedback"]["complaints"][0]["title"] == "Customer complaint about access"
    assert inputs["opportunities"]["open"] == [{"ref": "OFI-001", "title": "Automate reviews"}]
    assert inputs["monitoring"]["readiness"][0]["framework"].startswith("ISO")
    held = lambda **b: client.post(f"{url}/held", headers=h, json={"heldOn": today.isoformat(), "attendees": "Kim, Sam", "minutes": "We met.", "decisions": "Fund MFA.", **b})  # noqa: E731
    assert held(heldOn=(today + timedelta(days=1)).isoformat()).status_code == 400
    assert held(minutes=" ").json()["detail"] == "Record the minutes."
    assert held(decisions="").status_code == 400
    assert client.post(f"{url}/held", headers=kh, json={}).status_code == 403
    r = held(chairId=kim["id"]).json()
    assert r["status"] == "held" and r["chairName"] == "Kim"
    assert client.post(f"{url}/pack", headers=h, json={}).json()["detail"] == "This review has been held and is frozen."
    assert client.delete(url, headers=h).status_code == 400
    r = client.post(f"{url}/actions", headers=h, json={"description": "Roll out MFA", "ownerId": kim["id"], "dueOn": (today + timedelta(days=30)).isoformat()}).json()
    action = r["actions"][0]
    person(client, admin, tid, "sam@acme.test", "control_owner")
    assert client.post(f"{A}/review-actions/{action['id']}/done", headers=login(client, "sam@acme.test", PW), json={}).status_code == 403
    assert client.post(f"{A}/review-actions/{action['id']}/done", headers=kh, json={"note": "Done for all staff"}).json()["actions"][0]["doneAt"]
    # The next review reports the action and starts its period at the held date.
    r2 = client.post(f"{A}/reviews", headers=h, json={"tenantId": tid, "title": "Next review", "plannedOn": (today + timedelta(days=90)).isoformat()}).json()
    assert r2["periodStart"] == today.isoformat()
    r2 = client.post(f"{A}/reviews/{r2['id']}/pack", headers=h, json={}).json()
    assert r2["pack"]["inputs"]["previous_actions"]["items"][0]["description"] == "Roll out MFA"
    assert client.delete(f"{A}/reviews/{r2['id']}", headers=h).json() == {"ok": True}
    # The minutes document uses the held review.
    g = generate(client, h, tid, "management-review-minutes")
    html = client.get(f"{A}/documents/{g['documentId']}", headers=h).json()["html"]
    assert "Fund MFA." in html and "Roll out MFA" in html
    with database.session_factory()() as db:
        row = db.get(IsmsManagementReview, r["id"])
        row.minutes = "rewritten"
        with pytest.raises(HeldReview):
            db.commit()
    actions = [e["action"] for e in client.get("/api/console/audit?limit=100", headers=admin).json()]
    for x in ("isms.review_planned", "isms.review_pack_built", "isms.review_held", "isms.review_action_done", "isms.review_deleted"):
        assert x in actions


def test_isolation(client, admin, ctx):
    h, kh, kim, tid = ctx
    r = client.post(f"{A}/reviews", headers=h, json={"tenantId": tid, "title": "Annual review", "plannedOn": date.today().isoformat()}).json()
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", "isms_manager")
    g = login(client, "isms@globex.test", PW)
    assert client.post(f"{A}/reviews/{r['id']}/pack", headers=g, json={}).status_code == 404
    assert client.get(f"{A}/reviews?tenant_id={tid}", headers=g).status_code == 404
