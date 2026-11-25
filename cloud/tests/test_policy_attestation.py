"""Policy acknowledgement by staff (GRC-08): assignment, acknowledgement of the approved text by hash, a new version
makes people due again, exceptions, reminders and the evidence export."""

from datetime import timedelta

from conftest import login
from test_documentation_vault import stepup

from fenrir_cloud import attestation, mailer
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import PolicyAttestation, utcnow


def _approve(client, admin, pid):
    client.post(f"/api/console/grc/policies/{pid}/workflow", headers=admin, json={"action": "submit"})
    r = client.post(f"/api/console/grc/policies/{pid}/workflow", headers=stepup(client, admin), json={"action": "approve"})
    assert r.status_code == 200, r.text
    return r.json()


def test_staff_acknowledge_each_approved_version(client, admin, tenant):
    tid = tenant["id"]
    for email in ("jo@acme.test", "sam@acme.test"):
        client.post("/api/console/users", headers=admin, json={"email": email, "password": "a-long-password-3", "name": email[:3],
                                                               "role": "client", "tenantId": tid})
    jo = login(client, "jo@acme.test", "a-long-password-3")
    r = client.post("/api/console/grc/policies", headers=admin, json={"tenantId": tid, "title": "Acceptable Use", "body": "Be careful."})
    pid = r.json()["id"]
    assert client.post(f"/api/console/grc/policies/{pid}/assignments", headers=jo, json={"allPortalUsers": True}).status_code == 403
    r = client.post(f"/api/console/grc/policies/{pid}/assignments", headers=admin, json={"allPortalUsers": True, "dueDays": 7})
    assert r.json() == {"assigned": 2}
    assert client.get("/api/portal/policies", headers=jo).json() == [], "nothing to read until a version is approved"
    _approve(client, admin, pid)

    mine = client.get("/api/portal/policies", headers=jo).json()
    assert [(m["title"], m["status"]) for m in mine] == [("Acceptable Use", "outstanding")]
    doc = client.get(f"/api/portal/policies/{pid}", headers=jo).json()
    assert doc["body"] == "Be careful." and len(doc["sha256"]) == 64
    url = f"/api/portal/policies/{pid}/acknowledge"
    assert client.post(url, headers=jo, json={"version": doc["version"], "sha256": doc["sha256"]}).status_code == 400
    assert client.post(url, headers=jo, json={"version": doc["version"], "sha256": "0" * 64, "confirm": True}).status_code == 409
    r = client.post(url, headers=jo, json={"version": doc["version"], "sha256": doc["sha256"], "confirm": True})
    assert r.status_code == 200, r.text

    view = client.get(f"/api/console/grc/policies/{pid}/attestations", headers=admin).json()
    assert view["counts"] == {"current": 1, "outstanding": 1}
    sam = next(p for p in view["people"] if p["email"] == "sam@acme.test")

    # A new approved version: Jo must read it again, and the old acknowledgement stays on record.
    client.patch(f"/api/console/grc/policies/{pid}", headers=admin, json={"body": "Be careful. Lock your screen."})
    _approve(client, admin, pid)
    assert client.get("/api/portal/policies", headers=jo).json()[0]["status"] == "outstanding"
    assert client.post(url, headers=jo, json={"version": doc["version"], "sha256": doc["sha256"], "confirm": True}).status_code == 409
    doc2 = client.get(f"/api/portal/policies/{pid}", headers=jo).json()
    client.post(url, headers=jo, json={"version": doc2["version"], "sha256": doc2["sha256"], "confirm": True})

    # Sam is on leave: an exception with a reason and an end date.
    bad = client.post(f"/api/console/grc/attestations/{sam['id']}/exception", headers=admin, json={"reason": "", "until": "2099-01-01"})
    assert bad.status_code == 400
    ok = client.post(f"/api/console/grc/attestations/{sam['id']}/exception", headers=admin,
                     json={"reason": "Parental leave", "until": "2099-01-01"})
    assert ok.status_code == 200
    view = client.get(f"/api/console/grc/policies/{pid}/attestations", headers=admin).json()
    assert view["counts"] == {"current": 1, "exception": 1}
    jo_row = next(p for p in view["people"] if p["email"] == "jo@acme.test")
    assert [h["version"] for h in jo_row["history"]] == [doc2["version"], doc["version"]]

    # Reminders: Sam's exception ends; overdue people get one every 7 days.
    client.post(f"/api/console/grc/attestations/{sam['id']}/exception", headers=admin, json={"until": None})
    with session_factory()() as db:
        a = db.get(PolicyAttestation, sam["id"])
        a.assigned_at = utcnow() - timedelta(days=30)
        db.commit()
        from fenrir_cloud.models import GrcPolicy
        db.get(GrcPolicy, pid).approved_at = utcnow() - timedelta(days=30)
        db.commit()
        before = len(mailer.OUTBOX)
        assert attestation.remind(db) == 1
        assert attestation.remind(db) == 0, "not again within 7 days"
        assert mailer.OUTBOX[before]["to"] == "sam@acme.test"
    view = client.get(f"/api/console/grc/policies/{pid}/attestations", headers=admin).json()
    assert view["counts"] == {"current": 1, "overdue": 1}

    csv_text = client.get(f"/api/console/grc/policies/{pid}/attestations.csv", headers=admin).text
    assert csv_text.count("jo@acme.test") == 2 and doc["sha256"] in csv_text and doc2["sha256"] in csv_text
