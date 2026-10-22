"""Policies, tenancy, DNS, intel, exposure, compliance, CRM/PSA/billing, audit."""

import base64

import dns.message
import dns.rcode
import httpx

from conftest import enroll, login
from fenrir_cloud import exposure
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import Device


# --------------------------------------------------------------------------- policy


def test_policy_schema_and_templates(client, admin):
    schema = client.get("/api/console/policy-schema", headers=admin).json()
    assert schema["fieldCount"] >= 150
    assert {s["key"] for s in schema["sections"]} >= {"antimalware", "ransomware", "dns", "deviceControl", "attackSurface"}
    strict = client.get("/api/console/policy-templates/strict", headers=admin).json()
    assert strict["deviceControl"]["usbStorage"] == "read-only"


def test_policy_validation(client, admin, tenant):
    bad = client.post("/api/console/policies", json={"tenantId": tenant["id"], "settings": {"antimalware": {"realtimeExecuteBlockThreshold": 5}}},
                      headers=admin)
    assert bad.status_code == 400 and "between" in bad.json()["detail"]
    unknown = client.post("/api/console/policies", json={"tenantId": tenant["id"], "settings": {"nope": {}}}, headers=admin)
    assert unknown.status_code == 400


def test_global_lock_beats_device_override(client, admin, tenant, device):
    client.put("/api/console/policies/pol_global", json={"settings": {}, "locks": ["antimalware.realtimeProtection"]}, headers=admin)
    override = client.post("/api/console/policies", json={"tenantId": tenant["id"], "name": "Kiosk exception",
                                                          "settings": {"antimalware": {"realtimeProtection": False},
                                                                       "deviceControl": {"usbStorage": "block"}}},
                           headers=admin).json()
    client.patch(f"/api/console/devices/{device['deviceId']}", json={"policyId": override["id"]}, headers=admin)
    detail = client.get(f"/api/console/devices/{device['deviceId']}", headers=admin).json()["policy"]
    assert detail["settings"]["antimalware"]["realtimeProtection"] is True
    assert detail["settings"]["deviceControl"]["usbStorage"] == "block"
    assert detail["overridesBlocked"][0]["setting"] == "antimalware.realtimeProtection"
    assert detail["origin"]["deviceControl.usbStorage"].startswith("device:")
    # The agent sees a new revision on its next check-in.
    check = client.post(f"/api/v1/devices/{device['deviceId']}/policy-check-in", json={"currentPolicyRevision": device["policy"]["revision"]},
                        headers=device["headers"]).json()
    assert check["changed"] is True
    assert check["policy"]["modules"]["deviceControl"]["usbStorage"] == "block"


# --------------------------------------------------------------------------- tenancy


def test_customer_user_cannot_see_other_tenants(client, admin, tenant):
    other = client.post("/api/console/tenants", json={"name": "Globex"}, headers=admin).json()
    enroll(client, admin, other, hostname="GLOBEX-01", serial="G1")
    enroll(client, admin, tenant, hostname="ACME-02", serial="A2")
    client.post("/api/console/users", json={"tenantId": tenant["id"], "email": "it@acme.test", "password": "acme-password-123",
                                            "role": "tenant_admin"}, headers=admin)
    acme = login(client, "it@acme.test", "acme-password-123")
    hosts = {d["hostname"] for d in client.get("/api/console/devices", headers=acme).json()}
    assert hosts == {"ACME-02"}
    globex_device = next(d for d in client.get("/api/console/devices", headers=admin).json() if d["hostname"] == "GLOBEX-01")
    assert client.get(f"/api/console/devices/{globex_device['id']}", headers=acme).status_code == 404
    assert client.post("/api/console/tenants", json={"name": "x"}, headers=acme).status_code == 403
    # Customer admins cannot mint MSP roles.
    escalate = client.post("/api/console/users", json={"tenantId": tenant["id"], "email": "x@acme.test",
                                                       "password": "acme-password-123", "role": "msp_admin"}, headers=acme)
    assert escalate.status_code == 403


def test_viewer_cannot_respond(client, admin, tenant, device):
    client.post("/api/console/users", json={"tenantId": tenant["id"], "email": "ro@acme.test", "password": "viewer-password-1",
                                            "role": "viewer"}, headers=admin)
    viewer = login(client, "ro@acme.test", "viewer-password-1")
    response = client.post(f"/api/console/devices/{device['deviceId']}/commands", json={"type": "device.isolate"}, headers=viewer)
    assert response.status_code == 403


# --------------------------------------------------------------------------- DNS


def _query(name, rdtype="A"):
    return dns.message.make_query(name, rdtype).to_wire()


def test_doh_blocks_intel_domain_and_category(client, admin, device):
    client.post("/api/console/intel/indicators", json={"tenantId": None, "values": ["evil-c2.example"], "category": "command-and-control"},
                headers=admin)
    token = device["dnsOverHttpsUrl"].split("/dns/")[1].split("/")[0]
    wire = _query("beacon.evil-c2.example")
    response = client.post(f"/dns/{token}/dns-query", content=wire, headers={"Content-Type": "application/dns-message"})
    assert response.status_code == 200 and response.headers["X-Fenrir-Dns-Action"] == "block"
    answer = dns.message.from_wire(response.content)
    assert answer.answer[0][0].to_text() == "0.0.0.0"
    # GET form (RFC 8484) + DoH bypass category blocked by default.
    param = base64.urlsafe_b64encode(_query("dns.google")).rstrip(b"=").decode()
    get = client.get(f"/dns/{token}/dns-query?dns={param}")
    assert get.headers["X-Fenrir-Dns-Action"] == "block"
    log = client.get("/api/console/dns/log", headers=admin).json()
    assert {e["qname"] for e in log["entries"]} >= {"beacon.evil-c2.example", "dns.google"}


def test_doh_forwards_allowed_queries(client, device, monkeypatch):
    from fenrir_cloud import dnsfilter

    def fake_forward(wire, upstream, client=None):
        query = dns.message.from_wire(wire)
        reply = dns.message.make_response(query)
        reply.answer.append(dns.rrset.from_text(query.question[0].name, 60, "IN", "A", "93.184.216.34"))
        return reply.to_wire()

    monkeypatch.setattr(dnsfilter, "forward", fake_forward)
    token = device["dnsOverHttpsUrl"].split("/dns/")[1].split("/")[0]
    response = client.post(f"/dns/{token}/dns-query", content=_query("example.com"), headers={"Content-Type": "application/dns-message"})
    assert response.headers["X-Fenrir-Dns-Action"] == "allow"
    assert dns.message.from_wire(response.content).answer[0][0].to_text() == "93.184.216.34"


def test_dns_check_explains_and_detects_dga(client, admin, tenant):
    result = client.get(f"/api/console/dns/check?domain=xkqzjvbwplrtm4h8.biz&tenant_id={tenant['id']}", headers=admin).json()
    assert result["action"] == "block" and result["category"] == "dga"
    assert client.get(f"/api/console/dns/check?domain=wikipedia.org&tenant_id={tenant['id']}", headers=admin).json()["action"] == "allow"


def test_unknown_resolver_token(client):
    assert client.post("/dns/nope/dns-query", content=_query("a.com"), headers={"Content-Type": "application/dns-message"}).status_code == 404


# --------------------------------------------------------------------------- intel feed


def test_feed_sync_from_signaturedb_worker(client, admin):
    bundle = {"summary": {"version": "v42"}, "hashes": [{"type": "sha256", "value": "c" * 64, "source": "malwarebazaar",
                                                         "malwareFamily": "LockBit"}],
              "urls": [{"url": "http://drop.example/p.exe", "source": "urlhaus", "threat": "malware_download"}],
              "rules": [{"ruleType": "yara", "name": "r1", "content": "rule r1 { condition: true }"}]}
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=bundle))
    from fenrir_cloud import intel

    db = session_factory()()
    try:
        result = intel.sync_feed(db, "https://feed.test", client=httpx.Client(transport=transport))
    finally:
        db.close()
    assert result == {**result, "version": "v42", "hashes": 1, "urls": 1, "yaraRules": 1}
    lookup = client.get(f"/api/console/intel/lookup?value={'c' * 64}", headers=admin).json()
    assert lookup["verdict"] == "malicious" and "LockBit" not in lookup["category"]


# --------------------------------------------------------------------------- exposure


def test_inventory_and_osv_matching(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="ACME-SRV", os_version="Ubuntu 22.04.4 LTS", serial="S9")
    client.post(f"/api/v1/devices/{device['deviceId']}/telemetry", json={"events": [{
        "eventId": "inv-1", "eventType": "device.inventory.snapshot", "occurredAt": "2030-01-01T00:00:00Z",
        "payload": {"software": [{"name": "openssl", "version": "3.0.2-0ubuntu1.10"}, {"name": "bash", "version": "5.1"}]}}]},
        headers=device["headers"])

    def handler(request: httpx.Request):
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "UBUNTU-CVE-2024-0727"}]}, {}]})
        if "known_exploited" in str(request.url):
            return httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2024-0727"}]})
        return httpx.Response(200, json={"id": "UBUNTU-CVE-2024-0727", "aliases": ["CVE-2024-0727"], "summary": "PKCS12 crash",
                                         "affected": [{"package": {"name": "openssl"},
                                                       "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.14"}]}]}]})

    db = session_factory()()
    try:
        result = exposure.scan_device(db, db.get(Device, device["deviceId"]), client=httpx.Client(transport=httpx.MockTransport(handler)))
        db.commit()
    finally:
        db.close()
    assert result["found"] == 1
    vulns = client.get(f"/api/console/vulnerabilities?tenant_id={tenant['id']}", headers=admin).json()
    assert vulns[0]["vulnId"] == "CVE-2024-0727" and vulns[0]["knownExploited"] and vulns[0]["priority"] == "P1"
    assert vulns[0]["fixedVersion"] == "3.0.2-0ubuntu1.14"


def test_external_asset_requires_attestation(client, admin, tenant):
    refused = client.post("/api/console/exposure/assets", json={"tenantId": tenant["id"], "target": "acme.example"}, headers=admin)
    assert refused.status_code == 400
    ok = client.post("/api/console/exposure/assets", json={"tenantId": tenant["id"], "target": "acme.example",
                                                           "ownershipConfirmed": True}, headers=admin)
    assert ok.status_code == 200 and ok.json()["ownershipAttestedBy"] == "admin@fenrir.local"


def test_compliance_scores(client, admin, tenant, device):
    report = client.get(f"/api/console/compliance?tenant_id={tenant['id']}", headers=admin).json()
    names = {f["framework"] for f in report["frameworks"]}
    assert {"cyber-essentials", "cis-v8-ig1", "nist-csf-2", "essential-eight", "iso-27001"} <= names
    ce = next(f for f in report["frameworks"] if f["framework"] == "cyber-essentials")
    assert 0 <= ce["score"] <= 100 and all(c["evidence"] for c in ce["controls"])


# --------------------------------------------------------------------------- CRM / PSA / billing


def test_lead_to_customer_to_invoice(client, admin):
    lead = client.post("/api/console/crm/leads", json={"company": "Initech", "contact": "Bill L", "email": "bill@initech.test",
                                                       "value": 12000, "seats": 50, "stage": "Proposal"}, headers=admin).json()
    converted = client.post(f"/api/console/crm/leads/{lead['id']}/convert", json={"template": "strict"}, headers=admin).json()
    tenant = converted["tenant"]
    assert converted["contract"]["pricePerDevice"] == 20.0
    policy = client.get(f"/api/console/policies/{converted['policyId']}", headers=admin).json()
    assert policy["effective"]["settings"]["privilege"]["removeLocalAdmins"] is True
    for i in range(3):
        enroll(client, admin, tenant, hostname=f"INITECH-{i}", serial=f"I{i}")
    ticket = client.post("/api/console/tickets", json={"accountTenantId": tenant["id"], "subject": "Printer", "priority": "P4"},
                         headers=admin).json()
    assert ticket["number"] == 1001 and ticket["slaDueAt"]
    client.patch(f"/api/console/tickets/{ticket['id']}", json={"addMinutes": 90, "comment": "Fixed driver", "status": "Resolved"},
                 headers=admin)
    client.patch(f"/api/console/billing/contracts/{converted['contract']['id']}", json={"hourlyRate": 80, "includedHours": 1},
                 headers=admin)
    invoices = client.post("/api/console/billing/invoices/generate", json={}, headers=admin).json()["created"]
    invoice = next(i for i in invoices if i["accountTenantId"] == tenant["id"])
    lines = {line["description"]: line for line in invoice["lines"]}
    assert lines["Protected endpoints (complete)"]["quantity"] == 3
    assert lines["Support time beyond allowance (hours)"]["quantity"] == 0.5
    assert invoice["total"] == round((3 * 20 + 0.5 * 80) * 1.2, 2)
    assert client.post("/api/console/billing/invoices/generate", json={}, headers=admin).json()["created"] == []
    pipeline = client.get("/api/console/crm-pipeline", headers=admin).json()
    assert pipeline[0]["stage"] == "Won"


def test_executive_report(client, admin, tenant, device):
    data = client.get(f"/api/console/reports/executive?tenant_id={tenant['id']}", headers=admin).json()
    assert data["devices"]["total"] == 1
    html = client.get(f"/api/console/reports/executive.html?tenant_id={tenant['id']}", headers=admin)
    assert "Acme Dental" in html.text


# --------------------------------------------------------------------------- audit


def test_audit_chain_detects_tampering(client, admin, tenant):
    assert client.get("/api/console/audit/verify", headers=admin).json()["valid"] is True
    from fenrir_cloud.models import AuditLog

    db = session_factory()()
    try:
        row = db.query(AuditLog).order_by(AuditLog.id).offset(1).first()
        row.actor = "someone-else"
        db.commit()
    finally:
        db.close()
    result = client.get("/api/console/audit/verify", headers=admin).json()
    assert result["valid"] is False and result["brokenAt"] == row.id


def test_login_rejects_bad_password(client):
    assert client.post("/api/console/auth/login", json={"email": "admin@fenrir.local", "password": "nope"}).status_code == 401
    assert client.get("/api/console/devices").status_code == 401


# --------------------------------------------------------------------------- static ML model


def test_model_manifest_download_and_scoring(client, admin, device):
    from pathlib import Path

    manifest = client.get("/api/v1/agent/model/manifest").json()
    assert manifest["version"].startswith("fenrir-pe-v") and len(manifest["sha256"]) == 64
    blob = client.get("/api/v1/agent/model").content
    assert blob[:4] == b"FGBT" and len(blob) == manifest["size"]
    sample = (Path(__file__).resolve().parents[2] / "ml" / "testdata" / "hello64.exe").read_bytes()
    result = client.post("/api/console/ml/score", content=sample, headers=admin).json()
    assert result["pe"] is True and 0 <= result["score"] <= 1 and result["verdict"] in {"clean", "suspicious"}
    text = client.post("/api/console/ml/score", content=b"just text", headers=admin).json()
    assert text["pe"] is False
