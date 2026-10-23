from datetime import timedelta

import httpx

from conftest import enroll
from fenrir_cloud import events, exposure, vulnmgmt
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import Device, Ticket, Vulnerability, utcnow


def _inventory(client, device, software):
    client.post(f"/api/v1/devices/{device['deviceId']}/telemetry", json={"events": [{
        "eventId": f"inv-{len(software)}-{utcnow().timestamp()}", "eventType": "device.inventory.snapshot",
        "occurredAt": "2030-01-01T00:00:00Z", "payload": {"software": software}}]}, headers=device["headers"])


def _scan(device_id, vulnerable=True):
    def handler(request: httpx.Request):
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "UBUNTU-CVE-2024-0727"}]} if vulnerable else {}]})
        if "known_exploited" in str(request.url):
            return httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2024-0727"}]})
        return httpx.Response(200, json={"id": "UBUNTU-CVE-2024-0727", "aliases": ["CVE-2024-0727"], "summary": "PKCS12 crash",
                                         "affected": [{"package": {"name": "openssl"},
                                                       "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.14"}]}]}]})

    db = session_factory()()
    try:
        result = exposure.scan_device(db, db.get(Device, device_id), client=httpx.Client(transport=httpx.MockTransport(handler)))
        db.commit()
        events.process(db)
        db.commit()
        return result
    finally:
        db.close()


def test_remediation_lifecycle_with_verified_fix(client, admin, tenant):
    exposure._KEV_CACHE = (0.0, set())
    client.patch(f"/api/console/tenants/{tenant['id']}", headers=admin, json={"settings": {"vulnerabilityAutoTicket": "kev"}})
    device = enroll(client, admin, tenant, hostname="ACME-SRV", os_version="Ubuntu 22.04.4 LTS", serial="S9")
    client.patch(f"/api/console/devices/{device['deviceId']}", headers=admin, json={"criticality": "critical"})
    _inventory(client, device, [{"name": "openssl", "version": "3.0.2-0ubuntu1.10"}])
    assert _scan(device["deviceId"])["found"] == 1

    entry = client.get(f"/api/console/vulnerabilities?tenant_id={tenant['id']}&status=", headers=admin).json()[0]
    row = entry["devices"][0]
    assert entry["riskScore"] >= 10 and row["criticality"] == "critical" and "3.0.2-0ubuntu1.14" in entry["recommendation"]
    # Known-exploited + auto-ticket setting: a ticket was opened and linked, due in 14 days.
    assert row["ticketId"] and row["status"] == "patching" and row["dueAt"]

    # Manual "fixed" is refused: only a rescan verifies.
    refused = client.patch(f"/api/console/vulnerabilities/{row['id']}", headers=admin, json={"status": "fixed"})
    assert refused.status_code == 400 and "rescan" in refused.text

    # The package is updated; the rescan no longer finds it -> verified fixed, ticket resolved.
    _inventory(client, device, [{"name": "openssl", "version": "3.0.2-0ubuntu1.14"}])
    result = _scan(device["deviceId"], vulnerable=False)
    assert result["verifiedFixed"] == 1
    db = session_factory()()
    try:
        vuln = db.get(Vulnerability, row["id"])
        assert vuln.status == "fixed" and vuln.verified_at is not None
        ticket = db.get(Ticket, row["ticketId"])
        assert ticket.status == "Resolved" and any("Rescan confirmed" in c["text"] for c in ticket.comments)
    finally:
        db.close()
    trends = client.get(f"/api/console/vulnerabilities/trends?tenant_id={tenant['id']}&weeks=2", headers=admin).json()
    assert trends[-1]["found"] == 1 and trends[-1]["fixed"] == 1 and trends[-1]["open"]["critical"] == 0

    # It comes back: reopened, and a new detection event is raised.
    _inventory(client, device, [{"name": "openssl", "version": "3.0.2-0ubuntu1.10"}])
    _scan(device["deviceId"])
    db = session_factory()()
    try:
        assert db.get(Vulnerability, row["id"]).status in {"open", "patching"}
    finally:
        db.close()


def test_risk_acceptance_needs_reason_approver_and_expiry(client, admin, tenant):
    exposure._KEV_CACHE = (0.0, set())
    device = enroll(client, admin, tenant, hostname="ACME-SRV2", os_version="Ubuntu 22.04.4 LTS", serial="S10")
    _inventory(client, device, [{"name": "openssl", "version": "3.0.2-0ubuntu1.10"}])
    _scan(device["deviceId"])
    row = client.get(f"/api/console/vulnerabilities?tenant_id={tenant['id']}", headers=admin).json()[0]["devices"][0]
    assert row["ticketId"] is None  # auto-ticket is off by default
    no_reason = client.patch(f"/api/console/vulnerabilities/{row['id']}", headers=admin, json={"status": "accepted"})
    assert no_reason.status_code == 400
    too_long = (utcnow() + timedelta(days=400)).isoformat()
    assert client.patch(f"/api/console/vulnerabilities/{row['id']}", headers=admin,
                        json={"status": "accepted", "reason": "Air-gapped", "expiresAt": too_long}).status_code == 400
    soon = (utcnow() + timedelta(days=30)).isoformat()
    ok = client.patch(f"/api/console/vulnerabilities/{row['id']}", headers=admin,
                      json={"status": "accepted", "reason": "Isolated lab host", "expiresAt": soon})
    assert ok.status_code == 200 and ok.json()["exceptionApprovedBy"] == "admin@fenrir.local"
    # When the review date passes, the acceptance lapses and the vulnerability reopens.
    db = session_factory()()
    try:
        assert vulnmgmt.expire_acceptances(db, utcnow() + timedelta(days=31)) == 1
        db.commit()
        assert db.get(Vulnerability, row["id"]).status == "open"
    finally:
        db.close()
    ticket = client.post("/api/console/vulnerabilities/ticket", headers=admin, json={"vulnId": "CVE-2024-0727", "tenantId": tenant["id"]})
    assert ticket.status_code == 200 and ticket.json()["linked"] == 1
    assert client.patch(f"/api/console/vulnerabilities/{row['id']}", headers=admin, json={"assignee": "tech@msp.test"}).json()["assignee"] == "tech@msp.test"


def test_protection_health_alerts_and_rollup(client, admin, tenant, device):
    hb = lambda state: client.post(f"/api/v1/devices/{device['deviceId']}/heartbeat", headers=device["headers"],
                                   json={"agentVersion": "1.0.0", "healthState": state})
    hb("healthy")
    client.post("/api/console/releases", headers=admin, json={"platform": "windows", "version": "1.2.0",
                                                               "url": "https://example.test/a.msi", "sha256": "a" * 64})
    health = client.get(f"/api/console/protection/health?tenant_id={tenant['id']}", headers=admin).json()
    row = health["devices"][0]
    assert row["status"] == "outdated" and row["latestAgentVersion"] == "1.2.0" and row["noRecentScan"]
    hb("degraded")
    alerts = client.get(f"/api/console/alerts?tenant_id={tenant['id']}", headers=admin).json()
    alerts = alerts["items"] if isinstance(alerts, dict) else alerts
    health_alerts = [a for a in alerts if a["ruleId"] == "fenrir.health.protection-degraded"]
    assert len(health_alerts) == 1 and health_alerts[0]["status"] == "new"
    hb("degraded")  # no duplicate while it stays degraded
    assert client.get(f"/api/console/protection/health?tenant_id={tenant['id']}", headers=admin).json()["totals"]["unprotected"] == 1
    hb("healthy")
    alerts = client.get(f"/api/console/alerts?tenant_id={tenant['id']}&status=", headers=admin).json()
    alerts = alerts["items"] if isinstance(alerts, dict) else alerts
    health_alerts = [a for a in alerts if a["ruleId"] == "fenrir.health.protection-degraded"]
    assert len(health_alerts) == 1 and health_alerts[0]["status"] == "resolved"


def test_failed_job_retry_and_contract_renewals(client, admin, tenant, device):
    scripts = client.get("/api/console/rmm/scripts", headers=admin).json()
    eicar = next(s for s in scripts if s["name"].startswith("Validate real-time protection (EICAR test)"))
    job = client.post(f"/api/console/rmm/scripts/{eicar['id']}/run", headers=admin,
                      json={"targets": {"deviceIds": [device["deviceId"]]}}).json()
    items = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]
    command = next(i for i in items if i["type"] == "script.run")
    assert "EICAR" in command["payloadJson"]
    client.post(f"/api/v1/devices/{device['deviceId']}/commands/{command['id']}/complete", headers=device["headers"],
                json={"status": "failed", "resultJson": '{"exitCode": 1, "stdout": "FAIL"}'})
    assert client.get(f"/api/console/rmm/jobs/{job['id']}", headers=admin).json()["status"] == "failed"
    retried = client.post(f"/api/console/rmm/jobs/{job['id']}/retry", headers=admin).json()
    assert retried["retried"] == 1 and retried["status"] == "running"
    items = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]
    assert any('"retryOf"' in i["payloadJson"] for i in items)

    from datetime import date, timedelta
    end = (date.today() + timedelta(days=20)).isoformat()
    created = client.post("/api/console/billing/contracts", headers=admin,
                          json={"accountTenantId": tenant["id"], "name": "Managed IT", "monthlyFee": 500, "endDate": end})
    assert created.status_code == 200, created.text
    renewals = client.get("/api/console/billing/renewals?days=30", headers=admin).json()
    assert renewals and renewals[0]["daysLeft"] == 20 and renewals[0]["account"] == "Acme Dental"
