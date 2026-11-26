"""People and training: named ISMS roles, the RACI matrix, competence records and acknowledgement campaigns, with
portal accounts acknowledging in the client portal."""

from datetime import date, timedelta

import pytest
from conftest import login
from test_isms_documents import DOC, PW, act, generate, person

A = "/api/console/isms"


@pytest.fixture()
def ctx(client, admin, tenant):
    tid = tenant["id"]
    person(client, admin, tid, "isms@acme.test", "isms_manager")
    person(client, admin, tid, "boss@acme.test", "approver")
    kim = person(client, admin, tid, "kim@acme.test", "control_owner")
    h, boss = login(client, "isms@acme.test", PW), login(client, "boss@acme.test", PW)
    client.put(f"{A}/programme/frameworks", headers=h, json={"tenantId": tid, "frameworks": {"iso27001": {}}})
    client.post(f"{A}/programme/apply", headers=h, json={"tenantId": tid, "answers": {"develops_software": False}})
    return h, boss, kim, tid


def published(client, h, boss, tid):
    vid = generate(client, h, tid, DOC)["versionId"]
    act(client, h, vid, "submit")
    act(client, boss, vid, "approve")
    assert act(client, boss, vid, "publish").json()["state"] == "published"
    return vid


def test_roles_and_raci(client, admin, ctx):
    h, boss, kim, tid = ctx
    assert client.post(f"{A}/org-roles", headers=h, json={"tenantId": tid, "name": "x"}).status_code == 400
    roles = client.post(f"{A}/org-roles", headers=h, json={"tenantId": tid, "name": "Information security lead",
                                                           "responsibilities": "Runs the ISMS", "holderIds": [kim["id"]]}).json()["roles"]
    lead = roles[0]
    assert lead["holders"] == [{"id": kim["id"], "name": "Kim"}]
    assert client.post(f"{A}/org-roles", headers=h, json={"tenantId": tid, "name": "information security LEAD"}).json()["detail"] == "A role with that name already exists."
    outsider = client.post("/api/console/users", headers=admin, json={"tenantId": tid, "email": "o@acme.test", "password": PW, "name": "O", "role": "tenant_analyst"}).json()
    assert client.post(f"{A}/org-roles", headers=h, json={"tenantId": tid, "name": "Board", "holderIds": [outsider["id"]]}).status_code == 400
    board = client.post(f"{A}/org-roles", headers=h, json={"tenantId": tid, "name": "Board"}).json()["roles"][1]
    raci = client.post(f"{A}/raci/activities", headers=h, json={"tenantId": tid, "title": "Run the risk assessment"}).json()
    act_id = raci["activities"][0]["id"]
    assert {i["problem"] for i in raci["issues"]} == {"no_accountable", "no_responsible"}
    url = f"{A}/raci/activities/{act_id}"
    assert client.put(url, headers=h, json={"letters": {lead["id"]: "A", board["id"]: "A"}}).json()["detail"] == "Only one role can be accountable for an activity."
    assert client.put(url, headers=h, json={"letters": {lead["id"]: "X"}}).status_code == 400
    raci = client.put(url, headers=h, json={"letters": {lead["id"]: "R", board["id"]: "A"}}).json()
    assert raci["issues"] == [] and len(raci["cells"]) == 2
    raci = client.put(url, headers=h, json={"letters": {lead["id"]: "A", board["id"]: "I"}}).json()
    assert {c["letter"] for c in raci["cells"]} == {"A", "I"} and raci["issues"][0]["text"] == "No role is responsible."
    assert client.post(f"{A}/raci/activities", headers=login(client, "kim@acme.test", PW), json={"tenantId": tid, "title": "Other"}).status_code == 403
    roles = client.delete(f"{A}/org-roles/{board['id']}", headers=h).json()["roles"]
    assert [r["name"] for r in roles] == ["Information security lead"]
    assert len(client.get(f"{A}/people?tenant_id={tid}", headers=h).json()["raci"]["cells"]) == 1


def test_competence_records(client, admin, ctx):
    h, boss, kim, tid = ctx
    today = date.today()
    add = lambda **b: client.post(f"{A}/competence", headers=h, json={"tenantId": tid, "userId": kim["id"], "kind": "training", "title": "Phishing awareness", "achievedOn": today.isoformat(), **b})  # noqa: E731
    assert add(achievedOn=(today + timedelta(days=1)).isoformat()).json()["detail"] == "The achieved date cannot be in the future."
    assert add(expiresOn=(today - timedelta(days=1)).isoformat()).status_code == 400
    assert add(kind="vibes").status_code == 400
    rows = add(expiresOn=(today + timedelta(days=10)).isoformat()).json()["competence"]
    assert rows[0]["status"] == "expiring"
    add(title="CISSP", kind="qualification")
    # Kim sees only their own records and no RACI.
    kh = login(client, "kim@acme.test", PW)
    p = client.get(f"{A}/people?tenant_id={tid}", headers=kh).json()
    assert p["raci"] is not None and len(p["competence"]) == 2  # control owners can see controls, so the full view
    person(client, admin, tid, "sam@acme.test", "staff")
    p = client.get(f"{A}/people?tenant_id={tid}", headers=login(client, "sam@acme.test", PW)).json()
    assert p["roles"] == [] and p["raci"] is None and p["competence"] == []
    rid = rows[0]["id"]
    assert client.delete(f"{A}/competence/{rid}", headers=kh).status_code == 403
    assert len(client.delete(f"{A}/competence/{rid}", headers=h).json()["competence"]) == 1


def test_campaign_console_and_portal(client, admin, ctx):
    from fenrir_cloud import mailer
    h, boss, kim, tid = ctx
    draft = generate(client, h, tid, "objectives-plan")["versionId"]
    due = (date.today() + timedelta(days=14)).isoformat()
    start = lambda **b: client.post(f"{A}/acknowledgements/campaigns", headers=h, json={"tenantId": tid, "dueOn": due, **b})  # noqa: E731
    assert start(documentVersionId=draft).json()["detail"] == "Only a published document can be sent for acknowledgement."
    vid = published(client, h, boss, tid)
    assert start(documentVersionId=vid, dueOn="2020-01-01").status_code == 400
    assert start(documentVersionId=vid, audienceRoles=["wizard"]).status_code == 400
    # A client portal account with the staff role.
    jo = client.post("/api/console/users", headers=admin, json={"email": "jo@acme.test", "password": PW, "name": "Jo", "role": "client", "tenantId": tid}).json()
    assert client.put(f"{A}/memberships", headers=admin, json={"tenantId": tid, "userId": jo["id"], "role": "staff"}).status_code == 200
    mailer.OUTBOX.clear()
    c = start(documentVersionId=vid, audienceRoles=["staff", "control_owner"]).json()
    assert c["progress"] == {"total": 2, "done": 0, "percent": 0}
    sent = {m["to"]: m for m in mailer.OUTBOX}
    assert set(sent) == {"jo@acme.test", "kim@acme.test"} and "client portal" in sent["jo@acme.test"]["body"]
    assert start(documentVersionId=vid).json()["detail"] == "This document already has an open campaign."
    assert client.get(f"{A}/acknowledgements/campaigns?tenant_id={tid}", headers=h).json()["candidates"] == []
    # Jo reads and acknowledges in the portal.
    joh = login(client, "jo@acme.test", PW)
    pending = client.get("/api/portal/isms/acknowledgements", headers=joh).json()["pending"]
    assert [p["id"] for p in pending] == [c["id"]]
    doc = client.get(f"/api/portal/isms/acknowledgements/{c['id']}", headers=joh).json()
    assert "Acme Dental" in doc["html"] and doc["acknowledgedAt"] is None
    url = f"/api/portal/isms/acknowledgements/{c['id']}/acknowledge"
    assert client.post(url, headers=joh, json={"sha256": doc["sha256"]}).status_code == 400  # must confirm
    assert client.post(url, headers=joh, json={"sha256": "0" * 64, "confirm": True}).status_code == 409
    assert client.post(url, headers=joh, json={"sha256": doc["sha256"], "confirm": True}).json()["acknowledgedAt"]
    assert client.get("/api/portal/isms/acknowledgements", headers=joh).json()["pending"] == []
    # The approver is not in the audience.
    bdoc = client.get(f"{A}/acknowledgements/{c['id']}/read", headers=boss).json()
    assert client.post(f"{A}/acknowledgements/{c['id']}/acknowledge", headers=boss, json={"sha256": bdoc["sha256"], "confirm": True}).status_code == 403
    # Kim acknowledges in the console.
    kh = login(client, "kim@acme.test", PW)
    assert [p["id"] for p in client.get(f"{A}/acknowledgements/mine", headers=kh).json()["pending"]] == [c["id"]]
    client.post(f"{A}/acknowledgements/{c['id']}/acknowledge", headers=kh, json={"sha256": doc["sha256"], "confirm": True})
    d = client.get(f"{A}/acknowledgements/campaigns/{c['id']}", headers=h).json()
    assert d["progress"]["percent"] == 100 and {p["via"] for p in d["people"]} == {"portal", "console"}
    by = {u["name"]: u for u in client.get(f"{A}/acknowledgements/campaigns?tenant_id={tid}", headers=h).json()["byUser"]}
    assert by["Jo"] == {"userId": jo["id"], "name": "Jo", "asked": 1, "done": 1} and by["Boss"]["asked"] == 0
    assert client.get(f"{A}/acknowledgements/campaigns/{c['id']}", headers=kh).status_code == 403
    closed = client.post(f"{A}/acknowledgements/campaigns/{c['id']}/close", headers=h).json()
    assert closed["status"] == "closed"
    assert client.post(f"{A}/acknowledgements/{c['id']}/acknowledge", headers=boss, json={"sha256": doc["sha256"], "confirm": True}).status_code == 400
    actions = [e["action"] for e in client.get("/api/console/audit?limit=100", headers=admin).json()]
    assert actions.count("isms.document_acknowledged") == 2


def test_acknowledgements_are_final_and_reminders_run_daily(client, admin, ctx):
    from fenrir_cloud import db as database
    from fenrir_cloud import mailer
    from fenrir_cloud.isms import people
    from fenrir_cloud.isms.models import AcknowledgementsAreFinal, IsmsAcknowledgement
    from sqlalchemy import select

    h, boss, kim, tid = ctx
    vid = published(client, h, boss, tid)
    due = (date.today() + timedelta(days=2)).isoformat()
    c = client.post(f"{A}/acknowledgements/campaigns", headers=h, json={"tenantId": tid, "dueOn": due, "documentVersionId": vid,
                                                                       "audienceRoles": ["control_owner", "approver"]}).json()
    doc = client.get(f"{A}/acknowledgements/{c['id']}/read", headers=boss).json()
    client.post(f"{A}/acknowledgements/{c['id']}/acknowledge", headers=boss, json={"sha256": doc["sha256"], "confirm": True})
    mailer.OUTBOX.clear()
    with database.session_factory()() as db:
        assert people.send_reminders(db) == 1
        db.commit()
        assert people.send_reminders(db) == 0  # once a day
        assert [m["to"] for m in mailer.OUTBOX] == ["kim@acme.test"]
        row = db.execute(select(IsmsAcknowledgement)).scalar_one()
        row.via = "forged"
        with pytest.raises(AcknowledgementsAreFinal):
            db.commit()
        db.rollback()
        db.delete(db.execute(select(IsmsAcknowledgement)).scalar_one())
        with pytest.raises(AcknowledgementsAreFinal):
            db.commit()


def test_isolation(client, admin, ctx):
    h, boss, kim, tid = ctx
    vid = published(client, h, boss, tid)
    c = client.post(f"{A}/acknowledgements/campaigns", headers=h, json={"tenantId": tid, "documentVersionId": vid,
                                                                       "dueOn": date.today().isoformat()}).json()
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", "isms_manager")
    g = login(client, "isms@globex.test", PW)
    assert client.get(f"{A}/acknowledgements/{c['id']}/read", headers=g).status_code == 404
    assert client.get(f"{A}/acknowledgements/campaigns?tenant_id={tid}", headers=g).status_code == 404
    assert client.get(f"{A}/acknowledgements/mine", headers=g).json()["pending"] == []
    gc = client.post("/api/console/users", headers=admin, json={"email": "z@globex.test", "password": PW, "name": "Z", "role": "client", "tenantId": other["id"]}).json()
    client.put(f"{A}/memberships", headers=admin, json={"tenantId": other["id"], "userId": gc["id"], "role": "staff"})
    assert client.get(f"/api/portal/isms/acknowledgements/{c['id']}", headers=login(client, "z@globex.test", PW)).status_code == 404


def test_roles_and_raci_reach_the_roles_document(client, admin, ctx):
    h, boss, kim, tid = ctx
    lead = client.post(f"{A}/org-roles", headers=h, json={"tenantId": tid, "name": "Information security lead",
                                                          "holderIds": [kim["id"]]}).json()["roles"][0]
    a = client.post(f"{A}/raci/activities", headers=h, json={"tenantId": tid, "title": "Run the risk assessment"}).json()["activities"][0]
    client.put(f"{A}/raci/activities/{a['id']}", headers=h, json={"letters": {lead["id"]: "A"}})
    g = generate(client, h, tid, "roles-and-responsibilities")
    html = client.get(f"{A}/documents/{g['documentId']}", headers=h).json()["html"]
    assert "Information security lead" in html and "Kim" in html and "Run the risk assessment" in html
