"""PII discovery and dark-web exposure correlation (datadiscovery.py, darkweb.py)."""

import json

import httpx
import pytest

from conftest import enroll, login
from fenrir_cloud import darkweb, datadiscovery
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import BreachExposure, Device, M365Connection, Tenant, Ticket, Vulnerability


def poll(client, device):
    return client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]


def complete(client, device, command_id, result, status="completed"):
    response = client.post(f"/api/v1/devices/{device['deviceId']}/commands/{command_id}/complete",
                           json={"status": status, "resultJson": json.dumps(result)}, headers=device["headers"])
    assert response.status_code == 200, response.text


def test_linux_pii_scan_marks_device_and_raises_priority(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="ACME-FS", os_version="Ubuntu 22.04", serial="P1")
    with session_factory()() as db:
        db.add(Vulnerability(tenant_id=tenant["id"], device_id=device["deviceId"], vuln_id="CVE-2024-4444", package="libxml2",
                             severity="medium", epss=0.0001))
        db.commit()
    scan = client.post(f"/api/console/devices/{device['deviceId']}/pii-scan", headers=admin).json()
    command = next(c for c in poll(client, device) if c["type"] == "pii.scan")
    complete(client, device, command["id"], {"pii": {"filesScanned": 120, "filesWithPii": 2, "truncated": False,
                                                     "counts": {"payment-card": 3, "email": 9, "secret": 4},
                                                     "files": [{"path": "/home/jo/Documents/customers.csv", "types": {"payment-card": 3}}]}})
    scans = client.get("/api/console/pii/scans", params={"tenant_id": tenant["id"]}, headers=admin).json()
    assert scans[0]["id"] == scan["id"] and scans[0]["sensitivity"] == "high"
    assert scans[0]["counts"] == {"payment-card": 3, "email": 9}  # unknown types are dropped
    entry = client.get(f"/api/console/vulnerabilities?tenant_id={tenant['id']}", headers=admin).json()[0]
    assert entry["priority"] == "P3" and "pii-high" in entry["devices"][0]["exposure"]


def test_windows_pii_scan_parses_script_output_and_clears_flag(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="ACME-PC", serial="P2")
    with session_factory()() as db:
        db.get(Device, device["deviceId"]).exposure_flags = ["pii-high"]
        db.commit()
    client.post(f"/api/console/devices/{device['deviceId']}/pii-scan", headers=admin)
    command = next(c for c in poll(client, device) if c["type"] == "script.run")
    payload = json.loads(command["payloadJson"])
    assert payload["language"] == "powershell" and datadiscovery.MARKER in payload["body"]
    output = "scanning...\n" + datadiscovery.MARKER + json.dumps({"filesScanned": 40, "filesWithPii": 1, "counts": {"email": 2},
                                                                  "files": [{"path": "C:\\Users\\jo\\Documents\\a.txt", "types": {"email": 2}}]})
    complete(client, device, command["id"], {"exitCode": 0, "stdout": output})
    scans = client.get("/api/console/pii/scans", params={"tenant_id": tenant["id"]}, headers=admin).json()
    assert scans[0]["sensitivity"] == "low" and scans[0]["files"][0]["path"].endswith("a.txt")
    with session_factory()() as db:
        assert "pii-high" not in (db.get(Device, device["deviceId"]).exposure_flags or [])


def test_failed_pii_scan_is_recorded(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="ACME-PC2", serial="P3")
    client.post(f"/api/console/devices/{device['deviceId']}/pii-scan", headers=admin)
    command = next(c for c in poll(client, device) if c["type"] == "script.run")
    complete(client, device, command["id"], {"exitCode": 1, "stdout": "access denied"})
    scan = client.get("/api/console/pii/scans", params={"tenant_id": tenant["id"]}, headers=admin).json()[0]
    assert scan["status"] == "failed" and scan["error"]


def hibp(domains: dict, catalogue: list, status: int = 200):
    calls = []

    def handler(request: httpx.Request):
        calls.append(request)
        if request.url.path == "/api/v3/breaches":
            return httpx.Response(200, json=catalogue)
        domain = request.url.path.rsplit("/", 1)[1]
        if request.headers.get("hibp-api-key") != "test-key":
            return httpx.Response(401)
        if domain not in domains:
            return httpx.Response(404)
        return httpx.Response(status, json=domains[domain])

    return httpx.Client(transport=httpx.MockTransport(handler)), calls


CATALOGUE = [{"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Email addresses", "Passwords"]},
             {"Name": "Newsletter", "Title": "Newsletter", "BreachDate": "2020-01-01", "DataClasses": ["Email addresses"]}]


def test_breached_accounts_correlate_with_directory_mfa_and_devices(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="ACME-JO", serial="D1")
    with session_factory()() as db:
        db.get(Device, device["deviceId"]).metrics = {"loggedOnUser": "ACME\\jo"}
        db.add(M365Connection(tenant_id=tenant["id"], name="Acme", directory_id="d" * 36, client_id="c" * 36, credentials_envelope={},
                              snapshot={"users": [{"userPrincipalName": "jo@acme.test", "accountEnabled": True},
                                                  {"userPrincipalName": "sam@acme.test", "accountEnabled": True}],
                                        "mfaRegistration": [{"userPrincipalName": "jo@acme.test", "isMfaRegistered": False, "isAdmin": False},
                                                            {"userPrincipalName": "sam@acme.test", "isMfaRegistered": True, "isAdmin": False}]}))
        db.add(Vulnerability(tenant_id=tenant["id"], device_id=device["deviceId"], vuln_id="CVE-2024-5555", package="x", severity="medium",
                             epss=0.0001))
        db.commit()
    assert client.put("/api/console/darkweb/settings", json={"tenantId": tenant["id"], "domains": ["not a domain"]},
                      headers=admin).status_code == 422
    assert client.put("/api/console/darkweb/settings", json={"tenantId": tenant["id"], "enabled": True, "domains": ["Acme.test"]},
                      headers=admin).status_code == 200

    http, _ = hibp({"acme.test": {"jo": ["Adobe"], "sam": ["Adobe", "Newsletter"]}}, CATALOGUE)
    with session_factory()() as db:
        tenant_row = db.get(Tenant, tenant["id"])
        assert darkweb.sync_tenant(db, tenant_row, http, key="test-key") == {"exposures": 3, "new": 3}
        db.commit()
    exposures = client.get("/api/console/darkweb/exposures", params={"tenant_id": tenant["id"]}, headers=admin).json()
    jo = next(e for e in exposures if e["email"] == "jo@acme.test")
    sam = {e["breach"]: e for e in exposures if e["email"] == "sam@acme.test"}
    # Password exposed, account enabled, no MFA, signed in on a managed device: high risk with a ticket.
    assert jo["risk"] == "high" and jo["correlation"]["mfaRegistered"] is False and jo["correlation"]["hostnames"] == ["ACME-JO"]
    assert jo["ticketId"]
    assert sam["Adobe"]["risk"] == "medium" and sam["Newsletter"]["risk"] == "low"
    # The breached user's device: its vulnerabilities rank one level higher.
    entry = client.get(f"/api/console/vulnerabilities?tenant_id={tenant['id']}", headers=admin).json()[0]
    assert entry["priority"] == "P3" and "breached-user" in entry["devices"][0]["exposure"]

    # Remediating the exposure clears the device flag; a second sync does not duplicate rows or tickets.
    assert client.patch(f"/api/console/darkweb/exposures/{jo['id']}", json={"status": "remediated"}, headers=admin).status_code == 200
    with session_factory()() as db:
        assert "breached-user" not in (db.get(Device, device["deviceId"]).exposure_flags or [])
        darkweb.sync_tenant(db, db.get(Tenant, tenant["id"]), hibp({"acme.test": {"jo": ["Adobe"]}}, CATALOGUE)[0], key="test-key")
        db.commit()
        assert db.query(BreachExposure).count() == 3
        assert db.query(Ticket).filter(Ticket.source == "dark-web").count() == 1


def test_dark_web_errors_and_scope(client, admin, tenant):
    with session_factory()() as db:
        tenant_row = db.get(Tenant, tenant["id"])
        with pytest.raises(darkweb.DarkWebError, match="FENRIR_HIBP_API_KEY"):
            darkweb.sync_tenant(db, tenant_row, key="")
        tenant_row.settings = {**(tenant_row.settings or {}), "darkWeb": {"domains": ["acme.test"]}}
        with pytest.raises(darkweb.DarkWebError, match="verified"):
            darkweb.sync_tenant(db, tenant_row, hibp({"acme.test": {}}, CATALOGUE)[0], key="wrong")
        db.commit()
    assert "verified" in client.get("/api/console/darkweb/settings", params={"tenant_id": tenant["id"]}, headers=admin).json()["lastError"]
    other = client.post("/api/console/tenants", json={"name": "Other Co", "template": "balanced"}, headers=admin).json()
    client.post("/api/console/users", json={"email": "ta@other.test", "name": "T", "role": "tenant_admin", "tenantId": other["id"],
                                            "password": "a-long-enough-password-1"}, headers=admin)
    outsider = login(client, "ta@other.test", "a-long-enough-password-1")
    assert client.get("/api/console/darkweb/settings", params={"tenant_id": tenant["id"]}, headers=outsider).status_code == 404
    assert client.get("/api/console/darkweb/exposures", headers=outsider).json() == []
