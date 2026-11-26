"""ISMS documents: generation from live data, the approval lifecycle, frozen versions, wording and files."""

import io

import pytest
from conftest import login
from docx import Document as Docx

PW = "a-long-password-123"
DOC = "information-security-policy"


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
    person(client, admin, tenant["id"], "boss@acme.test", "approver")
    h = login(client, "isms@acme.test", PW)
    a = login(client, "boss@acme.test", PW)
    tid = tenant["id"]
    client.put("/api/console/isms/programme/frameworks", headers=h, json={"tenantId": tid, "frameworks": {"iso27001": {}}})
    client.post("/api/console/isms/programme/apply", headers=h, json={"tenantId": tid, "answers": {"develops_software": False}})
    client.put("/api/console/isms/scope", headers=h, json={"tenantId": tid, "statement": "Dental practice IT"})
    return h, a, tid


def generate(client, h, tid, doc_type=DOC):
    r = client.post("/api/console/isms/documents/generate", headers=h, json={"tenantId": tid, "docType": doc_type})
    assert r.status_code == 200, r.text
    return r.json()


def act(client, headers, vid, action):
    return client.post(f"/api/console/isms/documents/versions/{vid}/{action}", headers=headers)


def test_documents_are_generated_from_live_data(client, admin, prog):
    h, a, tid = prog
    listing = client.get(f"/api/console/isms/documents?tenant_id={tid}", headers=h).json()["documents"]
    assert len(listing) >= 17 and all(d["latest"] is None for d in listing)
    g = generate(client, h, tid)
    d = client.get(f"/api/console/isms/documents/{g['documentId']}", headers=h).json()
    assert d["number"] == "ACM-POL-001" and d["viewing"]["state"] == "draft"
    assert "Acme Dental" in d["html"]
    assert "secure-development" not in d["html"]  # the section switched off by "no in-house development"
    soa = generate(client, h, tid, "statement-of-applicability")
    html = client.get(f"/api/console/isms/documents/{soa['documentId']}", headers=h).json()["html"]
    assert "A.8.25" in html and "<script" not in html


def test_lifecycle_and_frozen_versions(client, admin, prog):
    h, a, tid = prog
    g = generate(client, h, tid)
    vid = g["versionId"]
    person(client, admin, tid, "exec@acme.test", "executive_viewer")
    assert act(client, login(client, "exec@acme.test", PW), vid, "submit").status_code == 403
    assert act(client, a, vid, "approve").status_code == 400  # not in review yet
    assert act(client, h, vid, "submit").json()["state"] == "in_review"
    assert client.post("/api/console/isms/documents/generate", headers=h, json={"tenantId": tid, "docType": DOC}).status_code == 400
    approved = act(client, a, vid, "approve").json()
    assert (approved["state"], approved["approvedBy"]) == ("approved", "Boss")
    assert act(client, a, vid, "publish").json()["state"] == "published"
    # Regenerating makes version 2 and leaves version 1 as it was.
    g2 = generate(client, h, tid)
    assert (g2["version"], g2["versionId"] != vid) == (2, True)
    from fenrir_cloud import db as database
    from fenrir_cloud.isms.models import FrozenDocumentVersion, IsmsDocumentVersion
    with database.session_factory()() as db:
        v1 = db.get(IsmsDocumentVersion, vid)
        v1.html = "<p>Tampered</p>"
        with pytest.raises(FrozenDocumentVersion):
            db.flush()
        db.rollback()
        with pytest.raises(FrozenDocumentVersion):
            db.delete(db.get(IsmsDocumentVersion, vid))
            db.flush()
        db.rollback()
    act(client, h, g2["versionId"], "submit")
    act(client, a, g2["versionId"], "approve")
    act(client, a, g2["versionId"], "publish")
    states = {v["version"]: v["state"] for v in client.get(f"/api/console/isms/documents/{g['documentId']}", headers=h).json()["versions"]}
    assert states == {1: "superseded", 2: "published"}
    actions = [e["action"] for e in client.get("/api/console/audit?limit=100", headers=admin).json()]
    for needed in ("isms.document_generated", "isms.document_submit", "isms.document_approve", "isms.document_publish"):
        assert needed in actions


def test_out_of_date_and_wording_overrides(client, admin, prog):
    h, a, tid = prog
    g = generate(client, h, tid)
    row = lambda: next(d for d in client.get(f"/api/console/isms/documents?tenant_id={tid}", headers=h).json()["documents"] if d["docType"] == DOC)  # noqa: E731
    assert row()["outOfDate"] is False
    client.put("/api/console/isms/scope", headers=h, json={"tenantId": tid, "statement": "All IT at both surgeries"})
    detail = client.get(f"/api/console/isms/documents/{g['documentId']}", headers=h).json()
    if row()["outOfDate"]:
        assert detail["changes"]
    blocks = [b["ref"] for b in detail["templateBlocks"]]
    put = lambda content: client.put("/api/console/isms/documents/wording", headers=h, json={  # noqa: E731
        "tenantId": tid, "docType": DOC, "blockRef": blocks[0], "content": content})
    assert put("Our own words for {{organization.legal_name}}.").status_code == 200
    assert row()["outOfDate"] is True
    generate(client, h, tid)
    assert "Our own words for Acme Dental" in client.get(f"/api/console/isms/documents/{g['documentId']}", headers=h).json()["html"]
    assert put("{{#each x}} broken").status_code == 400
    bad = client.put("/api/console/isms/documents/wording", headers=h, json={"tenantId": tid, "docType": DOC, "blockRef": "nope", "content": "x"})
    assert bad.status_code == 400


def test_files_and_who_can_read_what(client, admin, prog):
    h, a, tid = prog
    person(client, admin, tid, "sam@acme.test", "staff")
    sam = login(client, "sam@acme.test", PW)
    g = generate(client, h, tid)
    url = f"/api/console/isms/documents/versions/{g['versionId']}/file"
    docx = client.get(url + "?format=docx", headers=h)
    assert docx.status_code == 200
    text = "\n".join(p.text for p in Docx(io.BytesIO(docx.content)).paragraphs)
    assert "ACM-POL-001" in "\n".join(c.text for t in Docx(io.BytesIO(docx.content)).tables for r in t.rows for c in r.cells)
    assert "Information security policy" in text or "information security" in text.lower()
    assert client.get(url + "?format=pdf", headers=h).content[:5] == b"%PDF-"
    assert client.get(url, headers=sam).status_code == 404  # a draft is not for staff
    assert client.get(f"/api/console/isms/documents?tenant_id={tid}", headers=sam).json()["documents"] == []
    assert client.get(f"/api/console/isms/documents/{g['documentId']}", headers=sam).json()["versions"] == []
    act(client, h, g["versionId"], "submit"); act(client, a, g["versionId"], "approve"); act(client, a, g["versionId"], "publish")
    final = client.get(url + "?format=docx", headers=sam)
    assert final.status_code == 200
    cells = [c.text for t in Docx(io.BytesIO(final.content)).tables for r in t.rows for c in r.cells]
    assert any(c.startswith("Boss,") for c in cells)  # the approved copy carries the approver
    assert client.post("/api/console/isms/documents/generate", headers=sam, json={"tenantId": tid, "docType": DOC}).status_code == 403


def test_documents_are_isolated(client, admin, prog):
    h, a, tid = prog
    g = generate(client, h, tid)
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", "isms_manager")
    x = login(client, "isms@globex.test", PW)
    assert client.get(f"/api/console/isms/documents/{g['documentId']}", headers=x).status_code == 404
    assert client.get(f"/api/console/isms/documents/versions/{g['versionId']}/file", headers=x).status_code == 404
    assert act(client, x, g["versionId"], "submit").status_code == 404
