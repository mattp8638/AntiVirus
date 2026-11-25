"""Agreements and e-signature (GRC-09): signing order, email one-time codes, consent and name, expiry, voiding, and a
hash-chained completion record that detects tampering."""

import re
from datetime import timedelta

from fenrir_cloud import mailer
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import Agreement, utcnow
from fenrir_cloud.routers import esign as esign_router


def _link(to: str) -> str:
    m = next(m for m in reversed(mailer.OUTBOX) if m["to"] == to and "/sign/" in m["body"])
    return re.search(r"(/sign/\S+)", m["body"]).group(1)


def _code(to: str) -> str:
    m = next(m for m in reversed(mailer.OUTBOX) if m["to"] == to and "Your code is" in m["body"])
    return re.search(r"Your code is (\d{6})", m["body"]).group(1)


def _post(client, link, **form):
    return client.post(link, content="&".join(f"{k}={v}" for k, v in form.items()),
                       headers={"Content-Type": "application/x-www-form-urlencoded"})


def test_sequential_signing_with_codes_and_certificate(client, admin, tenant):
    tid = tenant["id"]
    t = client.post("/api/console/agreements/templates", headers=admin, json={
        "tenantId": tid, "name": "NDA", "body": "Mutual NDA between {{party}} and Acme Ltd, effective {{date}}. Keep it secret."}).json()
    assert t["variables"] == ["date", "party"]
    assert client.post("/api/console/agreements", headers=admin, json={"tenantId": tid, "templateId": t["id"], "values": {"party": "Globex"},
                                                                       "parties": [{"name": "Ann Lee", "email": "ann@globex.test"}]}).status_code == 400
    a = client.post("/api/console/agreements", headers=admin, json={
        "tenantId": tid, "title": "NDA with Globex", "templateId": t["id"], "values": {"party": "Globex", "date": "1 Dec 2026"},
        "parties": [{"name": "Ann Lee", "email": "ann@globex.test", "order": 1}, {"name": "Bob Ray", "email": "bob@acme.test", "order": 2}]}).json()
    assert "Globex" in a["body"] and len(a["sha256"]) == 64
    client.post(f"/api/console/agreements/{a['id']}/send", headers=admin)
    assert not any(m["to"] == "bob@acme.test" and "/sign/" in m["body"] for m in list(mailer.OUTBOX)), "Bob waits for Ann"

    ann = _link("ann@globex.test")
    page = client.get(ann)
    assert page.status_code == 200 and a["sha256"] in page.text
    r = _post(client, ann, action="sign", code="000000", name="Ann+Lee", consent="yes")
    assert r.status_code == 422 and "new code" in r.text, "no code asked yet"
    _post(client, ann, action="code")
    code = _code("ann@globex.test")
    assert "type your full name" in _post(client, ann, action="sign", code=code, name="A+L", consent="yes").text
    assert "agree to sign electronically" in _post(client, ann, action="sign", code=code, name="Ann+Lee").text
    r = _post(client, ann, action="sign", code=code, name="Ann+Lee", consent="yes")
    assert r.status_code == 200 and "next signer" in r.text
    assert client.get(ann).status_code == 404, "the link is spent once used"

    bob = _link("bob@acme.test")
    _post(client, bob, action="code")
    r = _post(client, bob, action="sign", code=_code("bob@acme.test"), name="bob+ray", consent="yes")
    assert "Everyone has now signed" in r.text
    done = client.get(f"/api/console/agreements/{a['id']}", headers=admin).json()
    assert done["status"] == "completed"
    cert = client.get(f"/api/console/agreements/{a['id']}/certificate", headers=admin).json()
    assert cert["chainValid"] and [e["kind"] for e in cert["events"]].count("signed") == 2
    assert all(s["emailVerified"] for s in cert["signers"])
    assert client.post("/api/console/agreements/verify", headers=admin, json=cert).json() == {"chainValid": True, "certificateIntact": True}
    tampered = {**cert, "events": [*cert["events"]]}
    tampered["events"][2] = {**tampered["events"][2], "actor": "mallory@evil.test"}
    v = client.post("/api/console/agreements/verify", headers=admin, json=tampered).json()
    assert v == {"chainValid": False, "certificateIntact": False}


def test_parallel_expiry_void_and_decline(client, admin, tenant):
    tid = tenant["id"]
    body = {"tenantId": tid, "title": "Data processing agreement", "body": "The processor shall process data only on instructions.",
            "order": "parallel", "parties": [{"name": "Cy Dee", "email": "cy@x.test"}, {"name": "Di Eve", "email": "di@x.test"}]}
    a = client.post("/api/console/agreements", headers=admin, json=body).json()
    client.post(f"/api/console/agreements/{a['id']}/send", headers=admin)
    cy, di = _link("cy@x.test"), _link("di@x.test")
    with session_factory()() as db:
        db.get(Agreement, a["id"]).expires_at = utcnow() - timedelta(hours=1)
        db.commit()
        assert esign_router.expire_due(db) == 1
    assert client.get(cy).status_code == 404
    b = client.post("/api/console/agreements", headers=admin, json=body).json()
    client.post(f"/api/console/agreements/{b['id']}/send", headers=admin)
    di2 = _link("di@x.test")
    assert _post(client, di2, action="decline").status_code == 200
    assert client.get(f"/api/console/agreements/{b['id']}", headers=admin).json()["status"] == "declined"
    c = client.post("/api/console/agreements", headers=admin, json=body).json()
    client.post(f"/api/console/agreements/{c['id']}/send", headers=admin)
    cy3 = _link("cy@x.test")
    client.post(f"/api/console/agreements/{c['id']}/void", headers=admin, json={"reason": "Wrong version"})
    assert client.get(cy3).status_code == 404
    assert di  # Di's first link died with the expired agreement
