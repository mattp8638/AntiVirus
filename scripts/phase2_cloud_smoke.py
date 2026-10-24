#!/usr/bin/env python3
"""Phase 2 HTTP smoke through the ACTUAL Docker/PostgreSQL stack.

No mocked database or TestClient. Endpoint requests emulate an agent; a live
Windows/Linux VM is still required for release sign-off.
Only use with an isolated, disposable lab stack/tenant.
"""
from __future__ import annotations

import hashlib
import json
import struct
import os
import uuid
from urllib.error import HTTPError
from urllib.request import Request, urlopen


BASE = os.environ.get("FENRIR_SMOKE_URL", "http://127.0.0.1:8080").rstrip("/")
EMAIL = os.environ.get("FENRIR_ADMIN_EMAIL", "admin@fenrir.local")
PASSWORD = os.environ.get("FENRIR_ADMIN_PASSWORD")
if not PASSWORD:
    raise SystemExit("FENRIR_ADMIN_PASSWORD is required for isolated smoke test")


def request(method: str, path: str, body: dict | None = None, headers: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json", **(headers or {})}
    req = Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urlopen(req, timeout=20) as res:
            content = res.read(1024 * 1024)
            return res.status, json.loads(content) if content else {}
    except HTTPError as exc:
        return exc.code, {}


def require(response, status=200):
    actual, body = response
    if actual != status:
        raise AssertionError(f"HTTP expected {status}, received {actual}")
    return body


def main():
    login = require(request("POST", "/api/console/auth/login",
                            {"email": EMAIL, "password": PASSWORD}))
    auth = {"Authorization": "Bearer " + login["token"]}
    customer = require(request("POST", "/api/console/tenants", {
        "name": "PHASE2-DISPOSABLE-CI-" + uuid.uuid4().hex[:8], "template": "balanced"
    }, auth))
    customer_id = customer["id"]

    # The Windows PE must have been cross-compiled automatically inside the
    # Ubuntu Docker image. Two customer downloads must each be a unique EXE;
    # no staged release or public customer-token download is permitted.
    status = require(request("GET", "/api/console/enrollment-installers/status", headers=auth))
    assert status["windows"]["ready"] and status["windows"]["mode"] == "cloud-built"
    def get_installer(label):
        req = Request(BASE + "/api/console/enrollment-installers", method="POST",
                      data=json.dumps({"os": "windows", "tenantId": customer_id,
                                       "label": label}).encode(),
                      headers={"Content-Type": "application/json", **auth})
        with urlopen(req, timeout=60) as response:
            assert response.status == 200
            assert "no-store" in response.headers["Cache-Control"]
            assert "Fenrir-Windows-Installer.exe" in response.headers["Content-Disposition"]
            return response.read(180 * 1024 * 1024 + 4096)
    def unpack_installer(binary):
        assert binary.startswith(b"MZ") and binary[-8:] == b"FENRIR01"
        size = struct.unpack("<I", binary[-12:-8])[0]
        assert 0 < size <= 4096
        data = binary[-44-size:-44]
        assert hashlib.sha256(data).digest() == binary[-44:-12]
        server, token, empty = data.decode("ascii").split("\n")
        assert not empty
        return server, token
    exe1 = get_installer("Lab Windows A")
    exe2 = get_installer("Lab Windows B")
    assert exe1 != exe2
    server1, token1 = unpack_installer(exe1)
    server2, token2 = unpack_installer(exe2)
    assert server1 == server2 == BASE and token1 != token2
    assert token1.startswith("fet_") and token2.startswith("fet_")

    enrollment_token = require(request("POST", "/api/console/enrollment-tokens", {
        "tenantId": customer_id, "label": "Phase 2 CI synthetic agent"
    }, auth))["token"]
    dev = require(request("POST", "/api/v1/enroll", {
        "hostname": "P2-SYNTHETIC-AGENT", "platform": "windows",
        "osVersion": "Windows 11 Pro", "serialNumber": uuid.uuid4().hex,
        "enrollmentToken": enrollment_token
    }))
    device_id = dev["deviceId"]
    agent_auth = {"X-Device-Api-Key": dev["deviceApiKey"]}
    assets = require(request("GET", "/api/console/psa/configurations?"
                             "accountTenantId=" + customer_id, headers=auth))
    assert len(assets) == 1 and assets[0]["deviceId"] == device_id
    asset_id = assets[0]["id"]

    rule = require(request("POST", "/api/console/rmm/conditions", {
        "tenantId": customer_id, "name": "Phase 2 synthetic disk alert",
        "metric": "disk_free_percent", "operator": "<",
        "threshold": 10, "durationMinutes": 0,
        "actions": [{"type": "command", "command": "inventory.refresh"}, {"type": "ticket"}]
    }, auth))
    def heartbeat(free):
        return require(request("POST", f"/api/v1/devices/{device_id}/heartbeat", {
            "healthState": "healthy", "metrics": {
                "manufacturer": "Test Vendor", "model": "Disposable VM",
                "disks": [{"mount": "C:", "totalGb": 100,
                           "freeGb": free, "freePercent": free}]
            }
        }, agent_auth))
    heartbeat(2)
    tickets = require(request("GET", "/api/console/tickets", headers=auth))
    ticket = next(t for t in tickets if t["source"] == "rmm" and t["deviceId"] == device_id)
    td = require(request("GET", f"/api/console/tickets/{ticket['id']}", headers=auth))
    assert len(td["rmmJobs"]) == 1 and td["rmmJobs"][0]["ticketId"] == ticket["id"]

    pending = require(request("GET", f"/api/v1/devices/{device_id}/commands/pending", headers=agent_auth))
    command = next(c for c in pending["items"] if c["type"] == "inventory.refresh")
    pending_again = require(request("GET", f"/api/v1/devices/{device_id}/commands/pending", headers=agent_auth))
    assert command["id"] in {x["id"] for x in pending_again["items"]}

    heartbeat(75)
    not_yet = require(request("GET", f"/api/console/tickets/{ticket['id']}", headers=auth))
    assert not_yet["status"] not in {"Resolved", "Closed"}
    completion_url = f"/api/v1/devices/{device_id}/commands/{command['id']}/complete"
    require(request("POST", completion_url, {"status": "completed", "resultJson": {"exitCode": 0}}, agent_auth))
    duplicate = require(request("POST", completion_url, {
        "status": "completed", "resultJson": {"exitCode": 0}
    }, agent_auth))
    assert duplicate.get("duplicate") is True
    finished = require(request("GET", f"/api/console/tickets/{ticket['id']}", headers=auth))
    assert finished["status"] == "Resolved" and finished["rmmJobs"][0]["status"] == "completed"

    refreshed = require(request("GET", "/api/console/psa/configurations?"
                                "accountTenantId=" + customer_id, headers=auth))
    assert len(refreshed) == 1 and refreshed[0]["id"] == asset_id
    assert refreshed[0]["manufacturer"] == "Test Vendor"

    require(request("DELETE", f"/api/console/devices/{device_id}", headers=auth))
    retired = require(request("GET", "/api/console/psa/configurations?"
                              "accountTenantId=" + customer_id, headers=auth))
    assert retired[0]["status"] == "Retired"
    require(request("POST", f"/api/v1/devices/{device_id}/heartbeat", {}, agent_auth), 401)
    print("PASS: real HTTP + PostgreSQL: enrollment, CMDB, monitoring, PSA, "
          "RMM dispatch/ack/idempotency, verified closure and retirement.")
    print("Synthetic endpoint only — live VM evidence is still mandatory.")


if __name__ == "__main__":
    main()
