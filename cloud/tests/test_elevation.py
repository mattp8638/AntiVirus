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
