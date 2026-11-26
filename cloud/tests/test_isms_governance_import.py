"""Moving a customer's earlier Governance records into the ISMS (decisions R3, R9, R10)."""

import io

from conftest import login
from docx import Document as Docx
from test_documentation_vault import stepup


def legacy(client, admin, tid):
    """Earlier Governance data built through the earlier API, as a customer would have it."""
    for key in ("cyber-essentials", "iso-27001", "nist-csf-2", "soc2"):
        assert client.post("/api/console/grc/programmes", headers=admin, json={
            "tenantId": tid, "frameworkKey": key, "owner": "Jo Bloggs", "createPolicies": key == "cyber-essentials",
            "scope": "All Acme Dental surgeries"}).status_code == 200
    patch = lambda key, rid, body: client.patch(f"/api/console/grc/programmes/{tid}/{key}/requirements/{rid}",  # noqa: E731
                                                headers=admin, json=body)
    assert patch("cyber-essentials", "A7.1", {"answer": "Yes", "status": "implemented", "notes": "Service desk"}).status_code == 200
    assert patch("iso-27001", "A.7.4", {"status": "not_applicable", "naReason": "No premises we control"}).status_code == 200
    assert patch("nist-csf-2", "GV.SC", {"status": "not_applicable", "naReason": "No suppliers in scope"}).status_code == 200
    assert patch("iso-27001", "6.1.2", {"status": "not_applicable", "naReason": "Trying to skip a clause"}).status_code == 200
    policies = client.get("/api/console/grc/policies", headers=admin, params={"tenant_id": tid}).json()
    access = next(p for p in policies if p["templateKey"] == "access-control")
    client.post(f"/api/console/grc/policies/{access['id']}/workflow", headers=admin, json={"action": "submit"})
    client.post(f"/api/console/grc/policies/{access['id']}/workflow", headers=stepup(client, admin), json={"action": "approve"})
    client.patch(f"/api/console/grc/policies/{access['id']}", headers=admin, json={"body": "# Access control\n\nA new draft."})
    up = client.post("/api/console/grc/evidence/upload", headers={**admin, "Content-Type": "application/pdf"},
                     content=b"Joiner form 2026", params={"tenant_id": tid, "filename": "joiner.pdf", "title": "Joiner approval",
                                                          "links": "cyber-essentials:A7.1,iso-27001:A.5.18"})
    assert up.status_code == 200, up.text
    assert client.post("/api/console/grc/records", headers=admin, json={
        "tenantId": tid, "kind": "risk", "title": "Ransomware", "likelihood": 4, "impact": 5, "owner": "Jo Bloggs"}).status_code == 200
    assert client.post("/api/console/grc/records", headers=admin, json={
        "tenantId": tid, "kind": "audit", "title": "Internal audit 2026", "control": "CC-GOV-10"}).status_code == 200
    return access


def test_preview_then_move_then_move_again(client, admin, tenant):
    tid = tenant["id"]
    access = legacy(client, admin, tid)
    me = client.get("/api/console/auth/me", headers=admin).json()["user"]
    client.put("/api/console/isms/memberships", headers=admin, json={"tenantId": tid, "userId": me["id"], "role": "isms_manager"})
    p = client.get(f"/api/console/isms/governance-import?tenant_id={tid}", headers=admin).json()
    assert p["frameworks"] == ["cyber-essentials", "iso27001", "nist-csf", "soc2"] and p["policies"] >= 1 and p["alreadyMoved"] == 0

    out = client.post("/api/console/isms/governance-import", headers=admin, json={"tenantId": tid}).json()
    assert out["frameworks"] == 4 and out["answers"] == 4 and out["evidence"] == 1 and out["risks"] == 1 and out["notes"] == 1
    assert any("6.1.2: mandatory" in s for s in out["skipped"])  # a mandatory clause cannot be excluded

    # Frameworks and the scope came across; the NIST CSF category exclusion reached all its subcategories.
    chosen = {f["framework"] for f in client.get(f"/api/console/isms/programme/frameworks?tenant_id={tid}", headers=admin).json()["frameworks"] if f["selected"]}
    assert chosen == {"cyber-essentials", "iso27001", "nist-csf", "soc2"}
    assert client.get(f"/api/console/isms/scope?tenant_id={tid}", headers=admin).json()["statement"] == "All Acme Dental surgeries"
    soa = {r["ref"]: r for r in client.get(f"/api/console/isms/soa?tenant_id={tid}&framework=iso27001", headers=admin).json()["rows"]}
    assert (soa["A.7.4"]["applicable"], soa["A.7.4"]["justification"]) == (False, "No premises we control")
    assert soa["A.7.4"]["earlierAnswers"][0]["naReason"] == "No premises we control"
    nist = client.get(f"/api/console/isms/soa?tenant_id={tid}&framework=nist-csf", headers=admin).json()["rows"]
    gvsc = [r for r in nist if r["ref"].startswith("GV.SC-")]
    assert gvsc and all(not r["applicable"] for r in gvsc)
    ce = client.get(f"/api/console/isms/soa?tenant_id={tid}&framework=cyber-essentials", headers=admin).json()
    assert any(a["sourceRef"] == "A7.1" for r in ce["rows"] for a in r["earlierAnswers"])  # matched by topic

    # The policy became a document: approved version published, the later edit a draft; Word copy stamped.
    docs = {d["title"]: d for d in client.get(f"/api/console/isms/documents?tenant_id={tid}", headers=admin).json()["documents"] if d["source"] == "imported"}
    doc = docs[access["title"]]
    detail = client.get(f"/api/console/isms/documents/{doc['documentId']}", headers=admin).json()
    assert {v["version"]: v["state"] for v in detail["versions"]} == {1: "published", 2: "draft"}
    published = next(v for v in detail["versions"] if v["state"] == "published")
    word = client.get(f"/api/console/isms/documents/versions/{published['id']}/file?format=docx", headers=admin)
    cells = [c.text for t in Docx(io.BytesIO(word.content)).tables for r in t.rows for c in r.cells]
    assert "Published" in cells

    # Evidence: the file was re-encrypted into the ISMS store and linked to controls of the requirements.
    ev = client.get(f"/api/console/isms/evidence?tenant_id={tid}", headers=admin).json()["evidence"]
    joiner = next(e for e in ev if e["title"] == "Joiner approval")
    assert joiner["controls"] and client.get(f"/api/console/isms/evidence/{joiner['id']}/download", headers=admin).content == b"Joiner form 2026"
    audit_note = next(e for e in ev if e["title"].startswith("Audit:"))
    assert [c["ref"] for c in audit_note["controls"]] == ["CC-GOV-10"]
    risk = client.get(f"/api/console/isms/risks?tenant_id={tid}", headers=admin).json()["risks"][0]
    assert (risk["title"], risk["inherentScore"]) == ("Ransomware", 20) and "Jo Bloggs" in risk["description"]

    # Running again adds nothing; the earlier records are still there.
    again = client.post("/api/console/isms/governance-import", headers=admin, json={"tenantId": tid}).json()
    assert (again["answers"], again["documents"], again["evidence"], again["risks"], again["notes"]) == (0, 0, 0, 0, 0)
    assert client.get("/api/console/grc/policies", headers=admin, params={"tenant_id": tid}).json()
    assert "isms.governance_imported" in [e["action"] for e in client.get("/api/console/audit?limit=50", headers=admin).json()]


def test_moving_needs_the_right_roles(client, admin, tenant):
    tid = tenant["id"]
    assert client.post("/api/console/isms/governance-import", headers=admin, json={"tenantId": tid}).status_code == 403  # no ISMS role
