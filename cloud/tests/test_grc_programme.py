"""Per-customer compliance programmes: frameworks with requirements, answers, policies (adopt, edit, approve,
versions) and evidence (files stored encrypted, links, expiry), plus importing an exact question set."""

import csv
import io
import json

from fenrir_cloud import grcprogramme as gp
from fenrir_cloud.config import get_settings
from test_documentation_vault import stepup


def req(view, rid):
    return next(r for s in view["sections"] for r in s["requirements"] if r["id"] == rid)


def test_library_is_consistent():
    frameworks = gp.builtin_frameworks()
    assert {"iso-27001", "cyber-essentials", "nist-csf-2", "uk-gdpr", "soc2", "cis-v8-ig1", "essential-eight", "ncsc-caf"} <= set(frameworks)
    assert len(gp.requirements(frameworks["iso-27001"])) == 118  # clauses 4-10 + 93 Annex A controls
    assert len([r for r in gp.requirements(frameworks["iso-27001"]) if r["id"].startswith("A.")]) == 93
    assert len(gp.requirements(frameworks["cis-v8-ig1"])) == 56
    for template in gp.policy_templates().values():
        for key, ids in template["maps"].items():
            known = {r["id"] for r in gp.requirements(frameworks[key])}
            assert set(ids) <= known, (template["key"], key, set(ids) - known)
    from fenrir_cloud import compliance
    checks = {f"{k}/{c[0]}" for k, f in compliance.FRAMEWORKS.items() for c in f["controls"]}
    for framework in frameworks.values():
        for r in gp.requirements(framework):
            assert set(r["auto"]) <= checks, (framework["key"], r["id"], r["auto"])


def test_adopt_answer_policies_and_evidence(client, admin, tenant):
    tid = tenant["id"]
    adopted = client.post("/api/console/grc/programmes", headers=admin,
                          json={"tenantId": tid, "frameworkKey": "cyber-essentials", "owner": "Jo Bloggs", "securityContact": "it@acme.example"})
    assert adopted.status_code == 200, adopted.text
    assert "Access Control Policy" in adopted.json()["policiesCreated"]

    view = client.get(f"/api/console/grc/programmes/{tid}/cyber-essentials", headers=admin).json()
    assert view["adopted"] and view["questionSet"] and view["total"] == 71 and view["progress"] == 0
    a71 = req(view, "A7.1")
    assert a71["type"] == "yesno" and a71["policies"][0]["title"] == "Access Control Policy" and a71["policies"][0]["status"] == "draft"
    assert any(c["ref"] == "cyber-essentials/CE-4" for c in req(view, "A8.1")["checks"])  # automatic evidence from Fenrir

    # Answer a question and mark it done; N/A needs a reason.
    patch = lambda rid, body: client.patch(f"/api/console/grc/programmes/{tid}/cyber-essentials/requirements/{rid}", headers=admin, json=body)
    assert patch("A7.1", {"answer": "Yes", "status": "implemented", "notes": "Managers approve in the service desk"}).status_code == 200
    assert patch("A2.6", {"status": "not_applicable"}).status_code == 400
    assert patch("A2.6", {"status": "not_applicable", "naReason": "No mobile devices access company data"}).status_code == 200
    assert patch("NOPE", {"status": "implemented"}).status_code == 404

    # Policy: placeholders filled, edit, submit, approve (step-up), version kept; editing starts a new draft.
    policies = client.get("/api/console/grc/policies", headers=admin, params={"tenant_id": tid}).json()
    access = next(p for p in policies if p["templateKey"] == "access-control")
    full = client.get(f"/api/console/grc/policies/{access['id']}", headers=admin).json()
    assert tenant["name"] in full["body"] and "Jo Bloggs" in full["body"] and "{{" not in full["body"]
    client.patch(f"/api/console/grc/policies/{access['id']}", headers=admin, json={"body": full["body"] + "\n\nReviewed with the MD."})
    assert client.post(f"/api/console/grc/policies/{access['id']}/workflow", headers=admin, json={"action": "submit"}).json()["status"] == "in_review"
    assert client.post(f"/api/console/grc/policies/{access['id']}/workflow", headers=admin, json={"action": "approve"}).status_code == 403
    approved = client.post(f"/api/console/grc/policies/{access['id']}/workflow", headers=stepup(client, admin), json={"action": "approve"}).json()
    assert approved["status"] == "approved" and approved["approvedVersion"] == 1 and approved["reviewDue"] and len(approved["versions"]) == 1
    edited = client.patch(f"/api/console/grc/policies/{access['id']}", headers=admin, json={"body": "Changed"}).json()
    assert edited["status"] == "draft" and edited["version"] == 2 and edited["approvedVersion"] == 1
    published = client.get(f"/api/console/grc/policies/{access['id']}/download", headers=admin)
    assert "Reviewed with the MD." in published.text  # the approved version, not the draft

    # Evidence: an uploaded file (encrypted on disk) and a link, attached to requirements.
    content = b"Joiner form 2026: approved by manager"
    up = client.post("/api/console/grc/evidence/upload", headers={**admin, "Content-Type": "application/pdf"}, content=content,
                     params={"tenant_id": tid, "filename": "../../joiner form.pdf", "title": "Joiner approval sample",
                             "links": "cyber-essentials:A7.1,iso-27001:A.5.18"})
    assert up.status_code == 200, up.text
    evidence = up.json()
    assert evidence["filename"] == "joiner form.pdf" and set(evidence["links"]) == {"cyber-essentials:A7.1", "iso-27001:A.5.18"}
    stored = (get_settings().artifact_dir / "grc-evidence").iterdir()
    assert all(content not in path.read_bytes() for path in stored)
    down = client.get(f"/api/console/grc/evidence/{evidence['id']}/download", headers=admin)
    assert down.content == content
    link = client.post("/api/console/grc/evidence", headers=admin, json={"tenantId": tid, "title": "MFA report", "kind": "link",
                                                                         "url": "https://entra.microsoft.com/report", "links": ["cyber-essentials:A7.11"],
                                                                         "validUntil": "2020-01-01T00:00:00Z"})
    assert link.status_code == 200 and link.json()["expired"] is True
    assert client.post("/api/console/grc/evidence", headers=admin, json={"tenantId": tid, "title": "x", "kind": "link", "url": "http://x"}).status_code == 400

    view = client.get(f"/api/console/grc/programmes/{tid}/cyber-essentials", headers=admin).json()
    assert req(view, "A7.1")["evidence"][0]["title"] == "Joiner approval sample"
    assert req(view, "A7.11")["evidence"][0]["expired"] is True
    assert view["counts"]["implemented"] == 1 and view["counts"]["not_applicable"] == 1 and view["progress"] == 3
    assert view["signals"]["withEvidence"] == 1  # the expired link does not count

    listing = client.get("/api/console/grc/programmes", headers=admin, params={"tenant_id": tid}).json()
    assert [p["key"] for p in listing] == ["cyber-essentials"] and "sections" not in listing[0]

    # Export for the assessor.
    exported = client.get(f"/api/console/grc/programmes/{tid}/cyber-essentials/export", headers=admin)
    rows = list(csv.DictReader(io.StringIO(exported.text)))
    a71_row = next(r for r in rows if r["ID"] == "A7.1")
    assert a71_row["Answer"] == "Yes" and a71_row["Status"] == "implemented" and "Joiner approval sample" in a71_row["Evidence"]


def test_import_exact_question_set_replaces_builtin_for_customer(client, admin, tenant):
    tid = tenant["id"]
    content = "section,id,title,text,type\nA1 Organisation,A1.1,What is your organisation's name?,,text\n" \
              "A4 Firewalls,A4.1,Do you have firewalls at the boundaries of your organisation's internal networks?,,yesno\n"
    reply = client.post("/api/console/grc/library/frameworks/import", headers=admin,
                        json={"tenantId": tid, "key": "cyber-essentials", "name": "Cyber Essentials (IASME booklet)", "version": "Willow",
                              "questionSet": True, "format": "csv", "content": content})
    assert reply.status_code == 200, reply.text
    assert reply.json() == {"key": "cyber-essentials", "requirements": 2, "replacesBuiltIn": True}
    client.post("/api/console/grc/programmes", headers=admin, json={"tenantId": tid, "frameworkKey": "cyber-essentials", "createPolicies": False})
    view = client.get(f"/api/console/grc/programmes/{tid}/cyber-essentials", headers=admin).json()
    assert view["total"] == 2 and view["source"] == "imported" and view["version"] == "Willow"
    assert req(view, "A4.1")["title"].startswith("Do you have firewalls") and req(view, "A4.1")["type"] == "yesno"
    assert req(view, "A4.1")["suggestedPolicies"][0]["key"] == "network-security"  # same id keeps the policy mapping

    bad = client.post("/api/console/grc/library/frameworks/import", headers=admin,
                      json={"tenantId": tid, "key": "x-y", "name": "Broken", "format": "csv", "content": "foo,bar\n1,2\n"})
    assert bad.status_code == 400
    dup = client.post("/api/console/grc/library/frameworks/import", headers=admin,
                      json={"tenantId": tid, "key": "dup-set", "name": "Dup", "format": "json",
                            "content": json.dumps({"sections": [{"id": "1", "requirements": [["1.1", "a"], ["1.1", "b"]]}]})})
    assert dup.status_code == 400 and "Duplicate" in dup.text
