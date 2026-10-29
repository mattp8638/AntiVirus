import json

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"


def _policy(client, admin, tenant, privilege):
    policies = client.get(f"/api/console/policies?tenant_id={tenant['id']}", headers=admin).json()
    default = next(p for p in policies if p["id"] == tenant["defaultPolicyId"])
    response = client.put(f"/api/console/policies/{default['id']}", json={"settings": {"privilege": privilege}}, headers=admin)
    assert response.status_code == 200, response.text


def _pending_commands(client, device):
    return client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]


def test_elevation_request_approval_flow(client, admin, tenant, device):
    agent = f"/api/v1/devices/{device['deviceId']}/elevation-requests"
    body = {"user": "PC1\\jo", "userSid": SID, "reason": "Install the label printer driver"}
    # Privilege management is off by default.
    assert client.post(agent, headers=device["headers"], json=body).status_code == 403
    _policy(client, admin, tenant, {"enabled": True, "elevationRequests": "approval", "elevationMinutes": 15})
    assert client.post(agent, headers=device["headers"], json={**body, "userSid": "not-a-sid"}).status_code == 422
    first = client.post(agent, headers=device["headers"], json=body).json()
    assert first["status"] == "pending" and first["minutes"] == 15
    # Asking again while one is open returns the same request.
    assert client.post(agent, headers=device["headers"], json=body).json()["id"] == first["id"]

    listing = client.get("/api/console/elevation-requests?status=pending", headers=admin).json()
    assert [r["id"] for r in listing] == [first["id"]] and listing[0]["reason"].startswith("Install")
    approved = client.post(f"/api/console/elevation-requests/{first['id']}/approve", headers=admin, json={"minutes": 30}).json()
    assert approved["status"] == "approved" and approved["minutes"] == 30
    assert client.post(f"/api/console/elevation-requests/{first['id']}/approve", headers=admin, json={}).status_code == 409
    grant = next(c for c in _pending_commands(client, device) if c["type"] == "elevation.grant")
    payload = json.loads(grant["payloadJson"])
    assert payload["userSid"] == SID and payload["minutes"] == 30
    done = client.post(f"/api/v1/devices/{device['deviceId']}/commands/{grant['id']}/complete", headers=device["headers"],
                       json={"status": "completed", "resultJson": "{}"})
    assert done.status_code == 200
    row = client.get("/api/console/elevation-requests", headers=admin).json()[0]
    assert row["status"] == "granted" and row["expiresAt"]

    revoked = client.post(f"/api/console/elevation-requests/{first['id']}/revoke", headers=admin).json()
    assert revoked["status"] == "revoked"
    assert any(c["type"] == "elevation.revoke" for c in _pending_commands(client, device))

    second = client.post(agent, headers=device["headers"], json=body).json()
    denied = client.post(f"/api/console/elevation-requests/{second['id']}/deny", headers=admin, json={"note": "Use the portal"}).json()
    assert denied["status"] == "denied" and denied["note"] == "Use the portal"


def test_elevation_auto_approve(client, admin, tenant, device):
    _policy(client, admin, tenant, {"enabled": True, "elevationRequests": "auto-approve"})
    result = client.post(f"/api/v1/devices/{device['deviceId']}/elevation-requests", headers=device["headers"],
                         json={"user": "PC1\\jo", "userSid": SID}).json()
    assert result["status"] == "approved" and result["minutes"] == 30
    assert any(c["type"] == "elevation.grant" for c in _pending_commands(client, device))
    trail = [e for e in client.get("/api/console/audit", headers=admin).json() if e["action"].startswith("elevation.")]
    assert [e["action"] for e in reversed(trail)] == ["elevation.requested", "elevation.approved"]
    assert trail[0]["actor"] == "policy:auto-approve"


def test_temporary_admin_account_lifecycle_is_audited_against_device_and_user(client, admin, tenant, device):
    _policy(client, admin, tenant, {"enabled": True, "elevationRequests": "approval", "elevationMinutes": 10})
    agent = f"/api/v1/devices/{device['deviceId']}/elevation-requests"
    run = {"user": "PC1\\jo", "userSid": SID, "reason": "Update the accounts package", "kind": "run"}
    assert client.post(agent, headers=device["headers"], json=run).status_code == 422  # no program
    assert client.post(agent, headers=device["headers"], json={**run, "target": "powershell.exe"}).status_code == 422  # not a full path
    target = "C:\\Program Files\\Sage\\Accounts\\Update.exe"
    request = client.post(agent, headers=device["headers"], json={**run, "target": target, "arguments": "/quiet"}).json()
    client.post(f"/api/console/elevation-requests/{request['id']}/approve", headers=admin, json={})
    grant = next(c for c in _pending_commands(client, device) if c["type"] == "elevation.grant")
    payload = json.loads(grant["payloadJson"])
    assert payload["kind"] == "run" and payload["target"] == target and payload["arguments"] == "/quiet"

    # The device created the temporary administrator; the password never reaches the cloud.
    result = {"granted": True, "account": "fadm-jo-1a2b", "accountSid": "S-1-5-21-9-9-9-1010", "until": "2026-10-29T15:00:00Z"}
    client.post(f"/api/v1/devices/{device['deviceId']}/commands/{grant['id']}/complete", headers=device["headers"],
                json={"status": "completed", "resultJson": json.dumps(result)})
    events = f"{agent}/{request['id']}/events"
    assert client.post(events, headers=device["headers"], json={"type": "launched", "target": target, "pid": 4242}).status_code == 200
    ended = client.post(events, headers=device["headers"], json={"type": "ended", "reason": "the program closed",
                                                                 "accountRemoved": True, "profileRemoved": True}).json()
    assert ended["status"] == "ended" and ended["endReason"] == "the program closed" and ended["account"] == "fadm-jo-1a2b"
    assert [e["type"] for e in ended["events"]] == ["requested", "approved", "granted", "launched", "ended"]
    assert ended["events"][2]["account"] == "fadm-jo-1a2b"

    detail = client.get(f"/api/console/elevation-requests/{request['id']}", headers=admin).json()
    assert detail["kind"] == "run" and detail["target"] == target and detail["grantedAt"] and detail["endedAt"]
    trail = [e for e in client.get("/api/console/audit", headers=admin).json() if e["action"].startswith("elevation.")]
    actions = [e["action"] for e in reversed(trail)]
    assert actions == ["elevation.requested", "elevation.approved", "elevation.account_created", "elevation.program_launched",
                       "elevation.account_removed"]
    hostname = detail["hostname"]
    assert all(e["target"] == f"{hostname}:PC1\\jo" for e in trail)
    created = next(e for e in trail if e["action"] == "elevation.account_created")
    details = created.get("details") or {}
    assert details.get("account") == "fadm-jo-1a2b" and details.get("userSid") == SID and "password" not in json.dumps(created).lower()

    # Another device cannot report on this request.
    from conftest import enroll

    other = enroll(client, admin, tenant, hostname="OTHER-PC", serial="ELV-2")
    assert client.post(f"/api/v1/devices/{other['deviceId']}/elevation-requests/{request['id']}/events", headers=other["headers"],
                       json={"type": "ended"}).status_code == 404


def test_technician_grants_the_signed_in_user_temporary_admin(client, admin, tenant, device):
    from fenrir_cloud import db as database
    from fenrir_cloud.models import Device

    base = "/api/console/elevation-requests"
    assert client.post(base, headers=admin, json={"deviceId": device["deviceId"], "reason": "Install the printer driver"}).status_code == 422
    with database.session_factory()() as db:  # what the agent reports at check-in
        db.get(Device, device["deviceId"]).metrics = {"loggedOnUser": "PC1\\jo", "loggedOnUserSid": SID}
        db.commit()
    assert client.post(base, headers=admin, json={"deviceId": device["deviceId"], "reason": ""}).status_code == 422  # say why
    granted = client.post(base, headers=admin, json={"deviceId": device["deviceId"], "reason": "Install the printer driver", "minutes": 15}).json()
    assert granted["status"] == "approved" and granted["user"] == "PC1\\jo" and granted["userSid"] == SID and granted["minutes"] == 15
    grant = next(c for c in _pending_commands(client, device) if c["type"] == "elevation.grant")
    assert json.loads(grant["payloadJson"])["requestId"] == granted["id"]
    trail = [e for e in client.get("/api/console/audit", headers=admin).json() if e["action"].startswith("elevation.")]
    assert [e["action"] for e in reversed(trail)] == ["elevation.requested", "elevation.approved"]
    assert all(e["actor"] == "admin@fenrir.local" for e in trail)
