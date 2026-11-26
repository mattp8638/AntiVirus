"""ISMS evidence: links, notes and files (stored encrypted, virus scanned), expiry, and Fenrir's automated results."""

from datetime import date, timedelta

import pytest
from conftest import login

from fenrir_cloud.isms import scanning

PW = "a-long-password-123"


def person(client, admin, tenant_id, email, isms_role):
    user = client.post("/api/console/users", headers=admin, json={"tenantId": tenant_id, "email": email, "password": PW,
                                                                  "name": email.split("@")[0].title(),
                                                                  "role": "tenant_analyst"}).json()
    assert client.put("/api/console/isms/memberships", headers=admin,
                      json={"tenantId": tenant_id, "userId": user["id"], "role": isms_role}).status_code == 200
    return user


@pytest.fixture()
def prog(client, admin, tenant):
    person(client, admin, tenant["id"], "isms@acme.test", "isms_manager")
    h = login(client, "isms@acme.test", PW)
    client.put("/api/console/isms/programme/frameworks", headers=h, json={"tenantId": tenant["id"], "frameworks": {"iso27001": {}}})
    client.post("/api/console/isms/programme/apply", headers=h, json={"tenantId": tenant["id"]})
    ctl = {c["ref"]: c for c in client.get(f"/api/console/isms/controls?tenant_id={tenant['id']}", headers=h).json()["controls"]}
    return h, tenant["id"], ctl


def state(client, h, tid, ref):
    return next(c["state"] for c in client.get(f"/api/console/isms/controls?tenant_id={tid}", headers=h).json()["controls"]
                if c["ref"] == ref)


def implement(client, h, control):
    r = client.post(f"/api/console/isms/controls/{control['id']}/assessment", headers=h,
                    json={"answer": "yes", "implementation": "Done"})
    assert r.status_code == 200, r.text


def note(client, h, tid, ids, **extra):
    return client.post("/api/console/isms/evidence", headers=h, json={"tenantId": tid, "title": "Restore test", "kind": "note",
                                                                       "note": "Restored a file on 01/11/2026", "controlIds": ids, **extra})


def test_links_and_notes_are_checked_and_evidence_a_control(client, admin, prog):
    h, tid, ctl = prog
    bkp = ctl["CC-BKP-01"]
    assert note(client, h, tid, []).status_code == 400
    assert note(client, h, tid, ["itc_nope"]).status_code == 400
    assert client.post("/api/console/isms/evidence", headers=h, json={"tenantId": tid, "title": "x", "kind": "link",
                                                                      "url": "ftp://x", "controlIds": [bkp["id"]]}).status_code == 400
    implement(client, h, bkp)
    assert state(client, h, tid, "CC-BKP-01") == "implemented"
    e = note(client, h, tid, [bkp["id"]]).json()
    assert (e["current"], e["scanStatus"], [c["ref"] for c in e["controls"]]) == (True, "not_required", ["CC-BKP-01"])
    assert state(client, h, tid, "CC-BKP-01") == "implemented_evidenced"
    assert client.delete(f"/api/console/isms/evidence/{e['id']}", headers=h).status_code == 200
    assert state(client, h, tid, "CC-BKP-01") == "implemented"


def test_expired_evidence_stops_counting(client, admin, prog):
    from fenrir_cloud import db as database
    from fenrir_cloud.isms import evidence

    h, tid, ctl = prog
    implement(client, h, ctl["CC-BKP-01"])
    e = note(client, h, tid, [ctl["CC-BKP-01"]["id"]], validUntil=(date.today() + timedelta(days=5)).isoformat()).json()
    assert state(client, h, tid, "CC-BKP-01") == "implemented_evidenced"
    r = client.patch(f"/api/console/isms/evidence/{e['id']}", headers=h, json={"validUntil": "2020-01-01"}).json()
    assert r["current"] is False
    assert state(client, h, tid, "CC-BKP-01") == "implemented"
    client.patch(f"/api/console/isms/evidence/{e['id']}", headers=h, json={"validUntil": (date.today() + timedelta(days=5)).isoformat()})
    with database.session_factory()() as db:  # the hourly job flags evidence about to expire, once
        evidence.tick(db)
        evidence.tick(db)
    events = [x for x in client.get("/api/console/audit?limit=100", headers=admin).json() if x["action"] == "isms.evidence_expiring"]
    assert len(events) == 1


def test_files_are_encrypted_scanned_and_downloadable_once_clean(client, admin, prog, monkeypatch):
    h, tid, ctl = prog
    url = f"/api/console/isms/evidence/upload?tenant_id={tid}&controls={ctl['CC-BKP-01']['id']}&filename=report.pdf&title=Backup%20report"
    r = client.post(url, headers={**h, "Content-Type": "application/pdf"}, content=b"%PDF-1.4 backup report")
    assert r.status_code == 200, r.text
    e = r.json()
    assert (e["scanStatus"], e["filename"], e["size"]) == ("clean", "report.pdf", 22)  # development: not scanned, noted
    assert "Not scanned" in e["scanDetail"]
    got = client.get(f"/api/console/isms/evidence/{e['id']}/download", headers=h)
    assert got.status_code == 200 and got.content == b"%PDF-1.4 backup report"
    from fenrir_cloud.config import get_settings
    stored = list((get_settings().artifact_dir / "isms-evidence").iterdir())
    assert stored and all(b"backup report" not in p.read_bytes() for p in stored)  # encrypted at rest
    bad = client.post(url.replace("report.pdf", "tool.exe"), headers=h, content=b"MZ")
    assert bad.status_code == 400 and "Program and script files" in bad.json()["detail"]
    assert client.post(url, headers=h, content=b"").status_code == 400


def test_infected_files_are_deleted_and_pending_files_cannot_be_downloaded(client, admin, prog, monkeypatch):
    h, tid, ctl = prog
    url = f"/api/console/isms/evidence/upload?tenant_id={tid}&controls={ctl['CC-BKP-01']['id']}&filename=x.docx"
    monkeypatch.setattr(scanning, "configured", lambda: True)
    monkeypatch.setattr(scanning, "scan", lambda data: ("infected", "Eicar-Test-Signature"))
    e = client.post(url, headers=h, content=b"X5O!P%@AP").json()
    assert (e["scanStatus"], e["scanDetail"], e["current"]) == ("infected", "Eicar-Test-Signature", False)
    assert client.get(f"/api/console/isms/evidence/{e['id']}/download", headers=h).status_code == 400
    monkeypatch.setattr(scanning, "scan", lambda data: ("failed", "The virus scanner could not be reached."))
    e = client.post(url, headers=h, content=b"fine").json()
    assert e["scanStatus"] == "pending"
    assert client.get(f"/api/console/isms/evidence/{e['id']}/download", headers=h).status_code == 409
    from fenrir_cloud import db as database
    from fenrir_cloud.isms import evidence
    monkeypatch.setattr(scanning, "scan", lambda data: ("clean", None))
    with database.session_factory()() as db:
        assert evidence.rescan_pending(db, tid) == 1
        db.commit()
    assert client.get(f"/api/console/isms/evidence/{e['id']}/download", headers=h).status_code == 200
    actions = [x["action"] for x in client.get("/api/console/audit?limit=100", headers=admin).json()]
    assert "isms.evidence_infected" in actions and "isms.evidence_downloaded" in actions


def test_fenrir_automated_results_become_evidence(client, admin, prog):
    from fenrir_cloud import db as database
    from fenrir_cloud.models import GrcEvidence, utcnow

    h, tid, ctl = prog

    def fenrir(status):
        with database.session_factory()() as db:
            db.add(GrcEvidence(tenant_id=tid, title=f"Backups: automated evidence ({status})", kind="automated",
                               control_id="FC-BACKUP", data={"status": status}, sha256="a" * 64, description="PASS backups",
                               valid_until=utcnow() + timedelta(days=30), uploaded_by="system:grc"))
            db.commit()

    fenrir("passing")
    out = client.post("/api/console/isms/evidence/import-fenrir", headers=h, json={"tenantId": tid}).json()
    assert (out["imported"], out["passing"], out["controlsChanged"]) == (1, 1, 1)
    assert state(client, h, tid, "CC-BKP-01") == "implemented_evidenced"
    assert client.post("/api/console/isms/evidence/import-fenrir", headers=h, json={"tenantId": tid}).json()["imported"] == 0
    fenrir("failing")
    out = client.post("/api/console/isms/evidence/import-fenrir", headers=h, json={"tenantId": tid}).json()
    assert (out["failing"], out["controlsChanged"]) == (1, 1)
    assert state(client, h, tid, "CC-BKP-01") == "in_progress"
    listing = client.get(f"/api/console/isms/evidence?tenant_id={tid}&control_id={ctl['CC-BKP-01']['id']}", headers=h).json()["evidence"]
    assert [e["source"] for e in listing] == ["fenrir:FC-BACKUP"]  # the failing result evidences nothing


def test_permissions_and_isolation(client, admin, prog, tenant):
    h, tid, ctl = prog
    person(client, admin, tid, "staff@acme.test", "staff")
    staff = login(client, "staff@acme.test", PW)
    assert note(client, staff, tid, [ctl["CC-BKP-01"]["id"]]).status_code == 403
    e = note(client, h, tid, [ctl["CC-BKP-01"]["id"]]).json()
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", "isms_manager")
    g = login(client, "isms@globex.test", PW)
    assert client.get(f"/api/console/isms/evidence/{e['id']}/download", headers=g).status_code == 404
    assert client.delete(f"/api/console/isms/evidence/{e['id']}", headers=g).status_code == 404
    assert note(client, g, other["id"], [ctl["CC-BKP-01"]["id"]]).status_code == 400  # not their control
