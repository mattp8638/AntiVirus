"""Auditor workspace: an external auditor (a Fenrir viewer with an expiring ISMS auditor role) draws saved samples,
requests evidence that control owners answer, and every ISMS page they open is in the audit log."""

from datetime import datetime, timedelta, timezone

import pytest
from conftest import login
from test_isms_soa import HALCYON, PW, person, programme

A = "/api/console/isms"


@pytest.fixture()
def ctx(client, admin, tenant):
    h = programme(client, admin, tenant, HALCYON)
    tid = tenant["id"]
    kim = person(client, admin, tid, "kim@acme.test", "control_owner")
    aud = client.post("/api/console/users", headers=admin, json={"tenantId": tid, "email": "ada@audit.test", "password": PW,
                                                                 "name": "Ada", "role": "viewer"}).json()
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    assert client.put(f"{A}/memberships", headers=admin, json={"tenantId": tid, "userId": aud["id"], "role": "auditor",
                                                              "expiresAt": expires}).status_code == 200
    controls = {c["ref"]: c for c in client.get(f"{A}/controls?tenant_id={tid}", headers=h).json()["controls"]}
    client.patch(f"{A}/controls/{controls['CC-BKP-01']['id']}", headers=h, json={"ownerId": kim["id"]})
    return h, login(client, "ada@audit.test", PW), login(client, "kim@acme.test", PW), kim, tid, controls


def test_samples_are_saved_and_reproducible(client, admin, ctx):
    h, ah, kh, kim, tid, controls = ctx
    draw = lambda **b: client.post(f"{A}/auditor/samples", headers=ah, json={"tenantId": tid, "population": "controls", "size": 5, "seed": "AUD-001", **b})  # noqa: E731
    assert draw(population="secrets").status_code == 400
    assert draw(size=0).status_code == 400 and draw(size=201).status_code == 400
    assert draw(population="nonconformities").json()["detail"] == "That population is empty."
    one = draw(note="Control sample").json()["samples"][0]
    two = draw().json()["samples"][0]
    assert one["items"] == two["items"] and len(one["items"]) == 5 and one["populationSize"] > 5
    assert one["createdByName"] == "Ada"
    assert client.post(f"{A}/auditor/samples", headers=kh, json={"tenantId": tid, "population": "controls", "size": 1}).status_code == 403


def test_evidence_requests(client, admin, ctx):
    from fenrir_cloud import mailer
    h, ah, kh, kim, tid, controls = ctx
    mailer.OUTBOX.clear()
    req = lambda **b: client.post(f"{A}/auditor/requests", headers=ah, json={"tenantId": tid, **b})  # noqa: E731
    assert req(request="x").status_code == 400
    assert req(request="Last restore test", controlId="itc_nope").status_code == 400
    rows = req(request="Last restore test", controlId=controls["CC-BKP-01"]["id"], dueOn="2027-01-10").json()["requests"]
    r = rows[0]
    assert r["controlRef"] == "CC-BKP-01" and r["status"] == "open"
    assert [m["to"] for m in mailer.OUTBOX] == ["kim@acme.test"] and "10/01/2027" in mailer.OUTBOX[0]["body"]
    req(request="Board minutes")  # not tied to a control: only managers answer it
    # Kim sees only requests for controls Kim owns.
    mine = client.get(f"{A}/auditor?tenant_id={tid}", headers=kh).json()
    assert [x["request"] for x in mine["requests"]] == ["Last restore test"] and mine["samples"] == []
    general = next(x for x in client.get(f"{A}/auditor?tenant_id={tid}", headers=h).json()["requests"] if x["controlId"] is None)
    assert client.post(f"{A}/auditor/requests/{general['id']}/answer", headers=kh, json={"response": "Here"}).status_code == 403
    url = f"{A}/auditor/requests/{r['id']}"
    assert client.post(f"{url}/answer", headers=kh, json={}).json()["detail"] == "Add a note or choose evidence."
    answered = client.post(f"{url}/answer", headers=kh, json={"response": "Restored a file on 02/11"}).json()["requests"]
    assert next(x for x in answered if x["id"] == r["id"])["answeredByName"] == "Kim"
    assert client.post(f"{url}/close", headers=kh).status_code == 403
    closed = client.post(f"{url}/close", headers=ah).json()["requests"]
    assert next(x for x in closed if x["id"] == r["id"])["status"] == "closed"
    assert client.post(f"{url}/answer", headers=kh, json={"response": "More"}).json()["detail"] == "That request is closed."


def test_auditor_views_are_logged_and_access_ends(client, admin, ctx):
    from fenrir_cloud import db as database
    from fenrir_cloud.isms.models import IsmsMembership
    from sqlalchemy import select
    h, ah, kh, kim, tid, controls = ctx
    assert client.get(f"{A}/soa?tenant_id={tid}&framework=iso27001", headers=ah).status_code == 200
    assert client.get(f"{A}/risks?tenant_id={tid}", headers=ah).status_code == 200
    events = [e for e in client.get("/api/console/audit?limit=50", headers=admin).json() if e["action"] == "isms.auditor_viewed"]
    assert {e["target"] for e in events} >= {"/api/console/isms/soa", "/api/console/isms/risks"}
    assert client.post(f"{A}/risks", headers=ah, json={"tenantId": tid, "title": "x y z"}).status_code == 403  # read only
    with database.session_factory()() as db:
        m = db.execute(select(IsmsMembership).where(IsmsMembership.role == "auditor")).scalar_one()
        m.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
        db.commit()
    assert client.get(f"{A}/auditor?tenant_id={tid}", headers=ah).status_code == 403


def test_isolation(client, admin, ctx):
    h, ah, kh, kim, tid, controls = ctx
    r = client.post(f"{A}/auditor/requests", headers=ah, json={"tenantId": tid, "request": "Board minutes"}).json()["requests"][0]
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", "isms_manager")
    g = login(client, "isms@globex.test", PW)
    assert client.post(f"{A}/auditor/requests/{r['id']}/answer", headers=g, json={"response": "x y"}).status_code == 404
    assert client.get(f"{A}/auditor?tenant_id={tid}", headers=g).status_code == 404
