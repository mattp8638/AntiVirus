"""FIX-08 / AT-21: a framework revision that keeps a requirement id but changes its meaning must not carry the old
approval over. Before the fix, re-importing a framework kept every "implemented" status by id, whatever it now said."""

import csv
import io
import json

import pytest

from conftest import login

IMPORT = "/api/console/grc/library/frameworks/import"


def framework(a1_text, extra=()):
    reqs = [{"id": "A1", "title": "Firewall", "text": a1_text},
            {"id": "A2", "title": "Patching", "text": "Apply critical patches within 14 days."}, *extra]
    return json.dumps({"sections": [{"id": "1", "title": "Controls", "requirements": reqs}]})


def load(client, headers, tid, content, dry=False, version="v1"):
    return client.post(IMPORT, headers=headers, json={"tenantId": tid, "key": "acme-controls", "name": "Acme controls", "version": version,
                                                       "format": "json", "content": content, "dryRun": dry})


def view(client, headers, tid):
    reply = client.get(f"/api/console/grc/programmes/{tid}/acme-controls", headers=headers)
    assert reply.status_code == 200, reply.text
    data = reply.json()
    return data, {r["id"]: r for s in data["sections"] for r in s["requirements"]}


def answer(client, headers, tid, rid, **body):
    return client.patch(f"/api/console/grc/programmes/{tid}/acme-controls/requirements/{rid}", headers=headers, json=body)


def setup(client, admin, tid):
    assert load(client, admin, tid, framework("Boundary firewalls block inbound connections by default.")).status_code == 200
    client.post("/api/console/grc/programmes", headers=admin, json={"tenantId": tid, "frameworkKey": "acme-controls", "createPolicies": False})
    assert answer(client, admin, tid, "A1", status="implemented", answer="Yes, default deny on the edge firewall").status_code == 200
    assert answer(client, admin, tid, "A2", status="implemented").status_code == 200


def test_changed_wording_needs_review_and_does_not_count_as_done(client, admin, tenant):
    tid = tenant["id"]
    setup(client, admin, tid)
    assert view(client, admin, tid)[0]["progress"] == 100

    revised = framework("Boundary firewalls block inbound AND outbound connections by default.", extra=[{"id": "A3", "title": "MFA", "text": "Use MFA."}])
    dry = load(client, admin, tid, revised, dry=True, version="v2")
    assert dry.status_code == 200 and dry.json()["dryRun"] is True
    diff = dry.json()["diff"]
    assert diff["changed"] == ["A1"] and diff["added"] == ["A3"] and diff["removed"] == [] and diff["unchanged"] == 1
    assert "outbound" in diff["changedDetail"][0]["after"] and "outbound" not in diff["changedDetail"][0]["before"]
    assert view(client, admin, tid)[0]["version"] == "v1"  # a dry run changes nothing

    assert load(client, admin, tid, revised, version="v2").status_code == 200
    data, rows = view(client, admin, tid)
    assert rows["A1"]["status"] == "needs_review" and rows["A1"]["needsReview"] and rows["A1"]["recordedStatus"] == "implemented"
    assert "outbound" not in rows["A1"]["previousWording"]
    assert rows["A2"]["status"] == "implemented" and not rows["A2"]["needsReview"]  # unchanged wording keeps its approval
    assert data["counts"]["needs_review"] == 1 and data["counts"]["implemented"] == 1 and data["progress"] == 33

    # Re-confirming against the new wording clears the review.
    assert answer(client, admin, tid, "A1", status="implemented", answer="Yes, default deny both ways").status_code == 200
    data, rows = view(client, admin, tid)
    assert rows["A1"]["status"] == "implemented" and not rows["A1"]["needsReview"] and data["counts"]["needs_review"] == 0


def test_answers_given_before_hashes_existed_are_backfilled_from_the_old_wording(client, admin, tenant):
    from fenrir_cloud.db import session_factory
    from fenrir_cloud.models import GrcRequirementState

    tid = tenant["id"]
    setup(client, admin, tid)
    db = session_factory()()
    try:  # what a pre-migration-23 row looks like
        for row in db.query(GrcRequirementState).filter(GrcRequirementState.tenant_id == tid):
            row.requirement_hash = row.requirement_text = None
        db.commit()
    finally:
        db.close()
    assert load(client, admin, tid, framework("Something entirely different."), version="v2").status_code == 200
    rows = view(client, admin, tid)[1]
    assert rows["A1"]["status"] == "needs_review" and rows["A2"]["status"] == "implemented"


def test_historical_assessment_is_exportable_after_revision(client, admin, tenant):
    tid = tenant["id"]
    setup(client, admin, tid)
    load(client, admin, tid, framework("Revised firewall wording."), version="v2")
    snaps = client.get(f"/api/console/grc/programmes/{tid}/acme-controls/snapshots", headers=admin).json()
    assert len(snaps) == 1 and snaps[0]["version"] == "v1" and snaps[0]["progress"] == 100 and "import" in snaps[0]["reason"]
    old = client.get(f"/api/console/grc/programmes/{tid}/acme-controls/export", headers=admin, params={"snapshot": snaps[0]["id"]})
    assert old.status_code == 200
    a1 = next(r for r in csv.DictReader(io.StringIO(old.text)) if r["ID"] == "A1")
    assert a1["Question"].startswith("Boundary firewalls") and a1["Status"] == "implemented"
    now = client.get(f"/api/console/grc/programmes/{tid}/acme-controls/export", headers=admin)
    a1 = next(r for r in csv.DictReader(io.StringIO(now.text)) if r["ID"] == "A1")
    assert a1["Question"] == "Revised firewall wording." and a1["Status"] == "needs review" and a1["Answered wording (if changed since)"]

    manual = client.post(f"/api/console/grc/programmes/{tid}/acme-controls/snapshots", headers=admin, json={"label": "Submitted to IASME"})
    assert manual.status_code == 200 and manual.json()["label"] == "Submitted to IASME"
    assert client.post(f"/api/console/grc/programmes/{tid}/acme-controls/snapshots", headers=admin, json={"label": ""}).status_code == 422
    assert client.get(f"/api/console/grc/programmes/{tid}/acme-controls/export", headers=admin, params={"snapshot": "grcs_nope"}).status_code == 404


@pytest.fixture()
def second_tenant_admin(client, admin):
    other = client.post("/api/console/tenants", json={"name": "Other Customer", "template": "balanced"}, headers=admin).json()
    created = client.post("/api/console/users", headers=admin, json={"tenantId": other["id"], "email": "boss@other.example",
                                                                    "password": "other-password-123", "role": "tenant_admin"})
    assert created.status_code == 200, created.text
    return login(client, "boss@other.example", "other-password-123"), other["id"]


def test_snapshots_are_customer_scoped(client, admin, tenant, second_tenant_admin):
    tid = tenant["id"]
    setup(client, admin, tid)
    load(client, admin, tid, framework("Revised."), version="v2")
    snap = client.get(f"/api/console/grc/programmes/{tid}/acme-controls/snapshots", headers=admin).json()[0]
    other_headers, other_tid = second_tenant_admin
    assert client.get(f"/api/console/grc/programmes/{tid}/acme-controls/snapshots", headers=other_headers).status_code in (403, 404)
    # The other customer cannot read it through their own tenant path either.
    assert client.get(f"/api/console/grc/programmes/{other_tid}/acme-controls/export", headers=other_headers,
                      params={"snapshot": snap["id"]}).status_code == 404


def test_deleting_an_import_also_flags_changed_requirements(client, admin, tenant):
    tid = tenant["id"]
    # Replace a built-in framework, answer it, then remove the import: the built-in wording returns and is flagged.
    content = json.dumps({"sections": [{"id": "1", "requirements": [{"id": "A1.1", "title": "Organisation name", "text": "Our own wording."}]}]})
    reply = client.post(IMPORT, headers=admin, json={"tenantId": tid, "key": "cyber-essentials", "name": "CE custom", "format": "json", "content": content})
    assert reply.status_code == 200
    assert client.patch(f"/api/console/grc/programmes/{tid}/cyber-essentials/requirements/A1.1", headers=admin,
                        json={"status": "implemented"}).status_code == 200
    imported = next(f for f in client.get("/api/console/grc/library", headers=admin, params={"tenant_id": tid}).json()["frameworks"]
                    if f["key"] == "cyber-essentials")
    assert imported["source"] == "imported" and imported["importedId"]
    assert client.delete(f"/api/console/grc/library/frameworks/imported/{imported['importedId']}", headers=admin).status_code == 200
    data = client.get(f"/api/console/grc/programmes/{tid}/cyber-essentials", headers=admin).json()
    rows = {r["id"]: r for s in data["sections"] for r in s["requirements"]}
    assert rows["A1.1"]["status"] == "needs_review"  # same id in the built-in booklet, different wording
    assert data["counts"]["implemented"] == 0
    assert len(client.get(f"/api/console/grc/programmes/{tid}/cyber-essentials/snapshots", headers=admin).json()) == 1
