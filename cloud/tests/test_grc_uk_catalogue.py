"""UK catalogue, working assessment flows and retention of superseded assessments."""
import csv
import io
import json

import pytest

from fenrir_cloud import grcprogramme as gp
from fenrir_cloud.db import session_factory
from fenrir_cloud.grccatalogue import CATALOGUE
from fenrir_cloud.models import GrcAdoption, GrcFramework, GrcRequirementState

EXPECTED = {
    "cyber-essentials", "cyber-essentials-plus", "def-stan-05-138", "ncsc-caf",
    "govassure", "govs-007", "uk-gdpr", "eu-gdpr", "iso-27001", "nist-csf-2",
    "soc2", "pci-dss", "cis-v8-ig1", "nis2", "dora",
}
NEW = ["cyber-essentials-plus", "def-stan-05-138", "govassure", "govs-007",
       "eu-gdpr", "pci-dss", "nis2", "dora"]


def requirement(view, rid):
    return next(r for s in view["sections"] for r in s["requirements"] if r["id"] == rid)


def test_uk_catalogue_across_all_selectors(client, admin, tenant):
    reply = client.get("/api/console/grc/library", headers=admin, params={"tenant_id": tenant["id"]})
    assert reply.status_code == 200, reply.text
    library = reply.json()
    assert {f["key"] for f in library["frameworks"]} == EXPECTED == set(CATALOGUE)
    for framework in library["frameworks"]:
        for field in ("owner", "assessmentStyle", "targetScope", "jurisdiction", "sourceUrl", "currentVersion"):
            assert framework[field], (framework["key"], field)
        assert framework["sourceUrl"].startswith("https://")
        assert framework["jurisdiction"] in {"UK", "UK-targeted"}
        assert framework["requirements"] > 0
    for policy in library["policies"]:
        assert set(policy["frameworks"]) <= EXPECTED
    selectors = client.get("/api/console/grc/frameworks", headers=admin).json()
    assert set(selectors["frameworks"]) == {f["name"] for f in CATALOGUE.values()}
    controls = client.get("/api/console/grc/controls", headers=admin, params={"tenant_id": tenant["id"]}).json()
    assert {f["framework"] for f in controls["frameworks"]} <= EXPECTED
    assert "essential-eight" not in json.dumps([library, selectors, controls]).lower()
    assert "acsc" not in json.dumps([library, selectors, controls]).lower()


@pytest.mark.parametrize("key", NEW)
def test_new_programme_answer_evidence_policy_and_export(client, admin, tenant, key):
    tid = tenant["id"]
    base = f"/api/console/grc/programmes/{tid}/{key}"
    adopted = client.post("/api/console/grc/programmes", headers=admin,
                          json={"tenantId": tid, "frameworkKey": key, "owner": "UK Security Lead"})
    assert adopted.status_code == 200, adopted.text
    assert adopted.json()["policiesCreated"], key
    view = client.get(base, headers=admin).json()
    assert view["adopted"] and not view["retired"] and view["progress"] == 0
    assert view["owner"] == CATALOGUE[key]["owner"]
    first = view["sections"][0]["requirements"][0]
    evidence = client.post("/api/console/grc/evidence", headers=admin,
                           json={"tenantId": tid, "title": "Approved assessment scope", "kind": "link",
                                 "url": "https://evidence.example/scope", "links": [f"{key}:{first['id']}"]})
    assert evidence.status_code == 200, evidence.text
    saved = client.patch(base + "/requirements/" + first["id"], headers=admin,
                         json={"answer": "Reviewed by the accountable owner", "status": "implemented", "owner": "Security Lead"})
    assert saved.status_code == 200, saved.text
    view = client.get(base, headers=admin).json()
    answered = requirement(view, first["id"])
    assert answered["answer"] == "Reviewed by the accountable owner"
    assert answered["evidence"][0]["title"] == "Approved assessment scope"
    assert view["counts"]["implemented"] == 1 and view["signals"]["withEvidence"] == 1
    listing = client.get("/api/console/grc/programmes", headers=admin, params={"tenant_id": tid}).json()
    assert any(p["key"] == key and p["adopted"] for p in listing)
    frozen = client.post(base + "/snapshots", headers=admin, json={"label": "Assessment review"})
    assert frozen.status_code == 200, frozen.text
    exported = client.get(base + "/export", headers=admin)
    assert exported.status_code == 200, exported.text
    rows = list(csv.DictReader(io.StringIO(exported.text)))
    row = next(r for r in rows if r["ID"] == first["id"])
    assert len(rows) == view["total"] and row["Answer"] == answered["answer"]
    assert "Approved assessment scope" in row["Evidence"]


def test_retired_assessments_are_hidden_but_existing_answers_export(client, admin, tenant):
    tid = tenant["id"]
    old = gp.builtin_frameworks(include_retired=True)["essential-eight"]
    first = gp.requirements(old)[0]
    with session_factory()() as db:
        db.add(GrcAdoption(tenant_id=tid, framework_key="essential-eight", status="active", adopted_by="legacy"))
        db.add(GrcRequirementState(tenant_id=tid, framework_key="essential-eight",
                                  requirement_id=first["id"], status="implemented", answer="Historical answer"))
        db.add(GrcFramework(tenant_id=tid, key="old-local", name="ACSC Essential Eight custom",
                            short="Old assessment", sections=old["sections"], created_by="legacy"))
        db.commit()
    library = client.get("/api/console/grc/library", headers=admin, params={"tenant_id": tid}).json()
    assert {"essential-eight", "old-local"}.isdisjoint({f["key"] for f in library["frameworks"]})
    assert client.get("/api/console/grc/programmes", headers=admin, params={"tenant_id": tid}).json() == []
    base = f"/api/console/grc/programmes/{tid}/essential-eight"
    view = client.get(base, headers=admin)
    assert view.status_code == 200, view.text
    assert view.json()["retired"]
    assert requirement(view.json(), first["id"])["answer"] == "Historical answer"
    exported = client.get(base + "/export", headers=admin)
    assert exported.status_code == 200 and "Historical answer" in exported.text
    assert client.get(f"/api/console/grc/programmes/{tid}/old-local", headers=admin).json()["retired"]
    assert client.post("/api/console/grc/programmes", headers=admin,
                       json={"tenantId": tid, "frameworkKey": "essential-eight"}).status_code == 404
    assert client.patch(base + "/requirements/" + first["id"], headers=admin,
                        json={"answer": "Changed"}).status_code == 404
    denied = client.post("/api/console/grc/library/frameworks/import", headers=admin,
                         json={"tenantId": tid, "key": "new-local", "name": "ACSC Essential Eight",
                               "content": json.dumps({"sections": old["sections"]})})
    assert denied.status_code == 422
    assert client.post("/api/console/grc/records", headers=admin,
                       json={"tenantId": tid, "kind": "risk", "title": "New risk", "framework": "Essential Eight"}).status_code == 422


@pytest.mark.parametrize("with_hash", [False, True])
def test_caf4_reassigned_outcome_needs_review(client, admin, tenant, with_hash):
    old_req = {"title": "Assurance", "text": "You have gained confidence that your security measures work, through testing and audit.",
               "type": "control"}
    with session_factory()() as db:
        db.add(GrcRequirementState(tenant_id=tenant["id"], framework_key="ncsc-caf",
                                  requirement_id="A2.b", status="implemented", answer="Old assurance answer",
                                  requirement_hash=gp.requirement_hash(old_req) if with_hash else None))
        db.commit()
    base = f"/api/console/grc/programmes/{tenant['id']}/ncsc-caf"
    view = client.get(base, headers=admin).json()
    assert view["version"] == "4.0" and view["total"] == 41
    assert requirement(view, "A2.b")["needsReview"]
    assert requirement(view, "A2.b")["status"] == "needs_review"
    assert requirement(view, "A2.c")["status"] == "not_started"
    assert requirement(view, "A4.b")["status"] == "not_started"
    saved = client.patch(base + "/requirements/A2.b", headers=admin,
                         json={"status": "implemented", "answer": "Current threat assessment reviewed"})
    assert saved.status_code == 200, saved.text
    current = client.get(base, headers=admin).json()
    assert not requirement(current, "A2.b")["needsReview"]


def test_previous_register_labels_still_link_to_current_controls(client, admin, tenant):
    created = client.post("/api/console/grc/records", headers=admin,
                          json={"tenantId": tenant["id"], "kind": "evidence", "title": "Existing asset register",
                                "framework": "NIST CSF", "control": "ID.AM"})
    assert created.status_code == 200, created.text
    report = client.get("/api/console/grc/controls", headers=admin, params={"tenant_id": tenant["id"]}).json()
    nist = next(f for f in report["frameworks"] if f["framework"] == "nist-csf-2")
    linked = next(c for c in nist["controls"] if c["id"] == "ID.AM")
    assert any(r["id"] == created.json()["id"] for r in linked["records"])
