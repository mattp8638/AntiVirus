"""Trust centre (GRC-14, FLOW-10): frozen documents shown after disclosure approval, public and gated, NDA access
requests with expiry, revocation stopping access at once, and the access log."""

from datetime import timedelta
from urllib.parse import parse_qs, urlparse

from test_documentation_vault import stepup

from fenrir_cloud.db import session_factory
from fenrir_cloud.models import TrustAccessRequest, utcnow


def test_trust_centre_documents_requests_and_revocation(client, admin, tenant):
    tid = tenant["id"]
    pol = client.post("/api/console/grc/policies", headers=admin, json={"tenantId": tid, "title": "Information Security", "body": "We protect data."}).json()
    client.post(f"/api/console/grc/policies/{pol['id']}/workflow", headers=admin, json={"action": "submit"})
    client.post(f"/api/console/grc/policies/{pol['id']}/workflow", headers=stepup(client, admin), json={"action": "approve"})

    assert client.put("/api/console/trust", headers=admin, json={"tenantId": tid, "slug": "Acme!"}).status_code == 400
    assert client.put("/api/console/trust", headers=admin, json={"tenantId": tid, "slug": "acme", "published": True}).status_code == 400, "an NDA first"
    c = client.put("/api/console/trust", headers=admin, json={"tenantId": tid, "slug": "acme", "title": "Acme trust centre",
                                                              "overview": "Our security programme.", "ndaText": "Keep it confidential.",
                                                              "published": True, "defaultDays": 14}).json()
    assert c["published"] and c["url"] == "/trust/acme"

    pub = client.post("/api/console/trust/documents", headers=admin, json={"tenantId": tid, "kind": "note", "access": "public",
                                                                          "title": "Security overview", "text": "ISO 27001 aligned."}).json()
    gated = client.post("/api/console/trust/documents", headers=admin, json={"tenantId": tid, "kind": "policy", "sourceId": pol["id"]}).json()
    assert gated["access"] == "gated" and gated["status"] == "pending" and len(gated["sha256"]) == 64
    assert client.get("/api/trust/acme").json()["documents"] == [], "nothing shown before disclosure approval"
    for d in (pub, gated):
        client.post(f"/api/console/trust/documents/{d['id']}/decision", headers=admin, json={"action": "approve"})

    page = client.get("/api/trust/acme").json()
    assert {d["title"]: d["open"] for d in page["documents"]} == {"Security overview": True, "Information Security (version 1)": False}
    assert page["generatedAt"] and all(d["asOf"] for d in page["documents"]), "snapshot dates shown"
    r = client.get(f"/api/trust/acme/documents/{pub['id']}")
    assert r.status_code == 200 and r.text == "ISO 27001 aligned." and r.headers["X-Content-SHA256"] == pub["sha256"]
    assert client.get(f"/api/trust/acme/documents/{gated['id']}").status_code == 403

    # An access request: the NDA must be accepted as shown.
    bad = client.post("/api/trust/acme/requests", json={"name": "Ann", "email": "ann@globex.test", "acceptNda": True, "ndaSha256": "0" * 64})
    assert bad.status_code == 400
    ok = client.post("/api/trust/acme/requests", json={"name": "Ann", "email": "ann@globex.test", "company": "Globex",
                                                       "reason": "Supplier due diligence", "acceptNda": True, "ndaSha256": page["ndaSha256"]})
    assert ok.status_code == 200
    req = client.get("/api/console/trust", headers=admin, params={"tenantId": tid}).json()["requests"][0]
    assert req["status"] == "pending" and req["ndaSha256"] == page["ndaSha256"]
    dec = client.post(f"/api/console/trust/requests/{req['id']}/decision", headers=admin, json={"action": "approve", "days": 7}).json()
    token = parse_qs(urlparse(dec["link"]).query)["access"][0]
    got = client.get(f"/api/trust/acme/documents/{gated['id']}", params={"access": token})
    assert got.status_code == 200 and "We protect data." in got.text
    assert client.get("/api/trust/acme", params={"access": token}).json()["access"]["email"] == "ann@globex.test"

    # Revocation stops later access at once; so does expiry.
    client.post(f"/api/console/trust/requests/{req['id']}/decision", headers=admin, json={"action": "revoke"})
    assert client.get(f"/api/trust/acme/documents/{gated['id']}", params={"access": token}).status_code == 403
    dec = client.post(f"/api/console/trust/requests/{req['id']}/decision", headers=admin, json={"action": "approve"}).json()
    token2 = parse_qs(urlparse(dec["link"]).query)["access"][0]
    assert client.get(f"/api/trust/acme/documents/{gated['id']}", params={"access": token}).status_code == 403, "old link stays dead"
    with session_factory()() as db:
        db.get(TrustAccessRequest, req["id"]).expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
    assert client.get(f"/api/trust/acme/documents/{gated['id']}", params={"access": token2}).status_code == 403
    # Withdrawing a document stops it for everyone.
    client.post(f"/api/console/trust/documents/{pub['id']}/decision", headers=admin, json={"action": "withdraw"})
    assert client.get(f"/api/trust/acme/documents/{pub['id']}").status_code == 404

    log = client.get("/api/console/trust", headers=admin, params={"tenantId": tid}).json()["accessLog"]
    outcomes = [(a["outcome"], a["reason"]) for a in log]
    assert ("served", "gated") in outcomes and ("refused", "no valid access") in outcomes and ("refused", "not available") in outcomes


def test_trust_centre_public_page(client, admin, tenant):
    tid = tenant["id"]
    client.put("/api/console/trust", headers=admin, json={"tenantId": tid, "slug": "acme-page", "title": "Acme trust",
                                                          "overview": "<script>x</script>", "ndaText": "Confidential.", "published": True})
    d = client.post("/api/console/trust/documents", headers=admin, json={"tenantId": tid, "kind": "note", "title": "Pen test summary",
                                                                        "text": "No criticals."}).json()
    client.post(f"/api/console/trust/documents/{d['id']}/decision", headers=admin, json={"action": "approve"})
    page = client.get("/trust/acme-page")
    assert page.status_code == 200 and "Pen test summary" in page.text and "Available on request" in page.text
    assert "<script>x</script>" not in page.text, "escaped"
    nda = client.get("/api/trust/acme-page").json()["ndaSha256"]
    r = client.post("/trust/acme-page", content=f"name=Ann&email=ann%40globex.test&accept=yes&nda={nda}",
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 200 and "Thank you" in r.text
    assert client.get("/trust/nope").status_code == 404
