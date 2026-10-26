from conftest import ADMIN_PASSWORD


def _stepup(client, admin):
    proof = client.post("/api/console/auth/reauth", headers=admin, json={"password": ADMIN_PASSWORD}).json()["reauthToken"]
    return {**admin, "X-Fenrir-Reauth": proof}


def test_local_admin_password_escrow_confirm_reveal(client, admin, device):
    agent = f"/api/v1/devices/{device['deviceId']}/local-admin"
    console = f"/api/console/devices/{device['deviceId']}/local-admin"
    assert client.post(agent + "/escrow", json={"account": "Administrator", "password": "x" * 20}).status_code == 401
    assert client.post(agent + "/escrow", headers=device["headers"], json={"account": "Administrator", "password": "short"}).status_code == 422
    first = client.post(agent + "/escrow", headers=device["headers"], json={"account": "Administrator", "password": "Fenrir-First-Pass-1!"}).json()["version"]
    client.post(agent + "/confirm", headers=device["headers"], json={"version": first, "applied": True})
    second = client.post(agent + "/escrow", headers=device["headers"], json={"account": "Administrator", "password": "Fenrir-Second-Pass-2!"}).json()["version"]
    client.post(agent + "/confirm", headers=device["headers"], json={"version": second, "applied": True})
    failed = client.post(agent + "/escrow", headers=device["headers"], json={"account": "Administrator", "password": "Fenrir-Third-Pass-3!"}).json()["version"]
    client.post(agent + "/confirm", headers=device["headers"], json={"version": failed, "applied": False, "error": "access denied"})

    listing = client.get(console, headers=admin).json()
    assert listing["enabled"] is False  # opt-in
    statuses = {i["id"]: i["status"] for i in listing["items"]}
    assert statuses == {first: "superseded", second: "active", failed: "failed"}
    assert "Pass" not in str(listing)  # passwords never appear in listings

    assert client.post(f"{console}/{second}/reveal", headers=admin).status_code == 403  # needs re-authentication
    shown = client.post(f"{console}/{second}/reveal", headers=_stepup(client, admin))
    assert shown.json()["password"] == "Fenrir-Second-Pass-2!" and shown.headers["Cache-Control"] == "no-store"
    assert client.post(f"{console}/{failed}/reveal", headers=_stepup(client, admin)).status_code == 404

    command = client.post(console + "/rotate", headers=admin).json()["commandId"]
    pending = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]
    assert any(c["id"] == command and c["type"] == "localadmin.rotate" for c in pending)
