"""FIX-03 / AT-02: console sessions are server-side and revocable.

Before the fix, a token issued before a password change kept working until it expired."""

import json

import pytest
from starlette.websockets import WebSocketDisconnect

from conftest import ADMIN_PASSWORD, login
from fenrir_cloud.security import totp_code
from test_documentation_vault import stepup
from test_remote import agent_command, start


def me(client, headers):
    return client.get("/api/console/auth/me", headers=headers).status_code


def test_old_token_stops_working_after_password_change(client, admin):
    laptop, phone = admin, login(client)
    changed = client.post("/api/console/auth/password", headers=laptop,
                          json={"currentPassword": ADMIN_PASSWORD, "newPassword": "another-long-password"})
    assert changed.status_code == 200 and changed.json()["sessionsRevoked"] == 2
    assert me(client, laptop) == 401 and me(client, phone) == 401
    assert me(client, {"Authorization": "Bearer " + changed.json()["token"]}) == 200
    assert client.post("/api/console/auth/login", json={"email": "admin@fenrir.local", "password": ADMIN_PASSWORD}).status_code == 401


def test_logout_and_listing_and_revoking_sessions(client, admin):
    other = login(client)
    listed = client.get("/api/console/auth/sessions", headers=admin).json()
    assert len(listed) == 2 and sum(s["current"] for s in listed) == 1
    target = next(s for s in listed if not s["current"])
    assert client.delete(f"/api/console/auth/sessions/{target['id']}", headers=admin).status_code == 200
    assert me(client, other) == 401 and me(client, admin) == 200
    third = login(client)
    assert client.post("/api/console/auth/sessions/revoke-others", headers=admin).json()["revoked"] == 1
    assert me(client, third) == 401
    assert client.post("/api/console/auth/logout", headers=admin).status_code == 200
    assert me(client, admin) == 401


def test_admin_disable_password_reset_and_sign_out_everywhere(client, admin, tenant):
    created = client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "tech@acme.example",
                                                                    "password": "tech-password-123", "role": "technician"})
    assert created.status_code == 200, created.text
    uid = created.json()["id"]
    tech = lambda: {"Authorization": "Bearer " + client.post("/api/console/auth/login", json={"email": "tech@acme.example", "password": pw[0]}).json()["token"]}
    pw = ["tech-password-123"]
    session = tech()
    assert me(client, session) == 200
    client.patch(f"/api/console/users/{uid}", headers=admin, json={"password": "reset-by-admin-456"})
    assert me(client, session) == 401  # admin password reset
    pw[0] = "reset-by-admin-456"
    session = tech()
    assert client.post(f"/api/console/users/{uid}/sessions/revoke", headers=admin).status_code == 403  # needs step-up
    assert client.post(f"/api/console/users/{uid}/sessions/revoke", headers=stepup(client, admin)).json()["revoked"] == 1
    assert me(client, session) == 401
    session = tech()
    client.patch(f"/api/console/users/{uid}", headers=admin, json={"active": False})
    assert me(client, session) == 401
    client.patch(f"/api/console/users/{uid}", headers=admin, json={"active": True})
    assert me(client, session) == 401  # re-enabling does not resurrect the old session


def test_enabling_mfa_ends_other_sessions(client, admin):
    other = login(client)
    setup = client.post("/api/console/auth/mfa/setup", headers=admin).json()
    client.post("/api/console/auth/mfa/enable", headers=admin, json={"code": totp_code(setup["secret"])})
    assert me(client, admin) == 200 and me(client, other) == 401


def test_tokens_without_a_server_session_are_refused(client, admin):
    from fenrir_cloud.config import get_settings
    from fenrir_cloud.security import issue_token

    user_id = client.get("/api/console/auth/me", headers=admin).json()["user"]["id"]
    forged = issue_token(get_settings().secret_key, user_id, 60, role="platform_admin", jti="session_never_issued")
    assert me(client, {"Authorization": "Bearer " + forged}) == 401
    legacy = issue_token(get_settings().secret_key, user_id, 60, role="platform_admin")  # pre-FIX-03 token, no jti
    assert me(client, {"Authorization": "Bearer " + legacy}) == 401


def test_remote_viewer_is_cut_off_when_its_console_session_ends(client, admin, tenant, device):
    session = start(client, admin, device, mode="desktop")
    payload = json.loads(agent_command(client, device)["payloadJson"])
    viewer = client.post(f"/api/console/remote/sessions/{session['id']}/viewer-token", headers=admin).json()
    with client.websocket_connect(f"/ws/remote/{session['id']}/agent?token={payload['token']}") as agent:
        with client.websocket_connect(f"{viewer['path']}?token={viewer['token']}") as browser:
            assert json.loads(browser.receive_text())["t"] == "hello"
            agent.receive_text()  # viewer.joined
            agent.send_bytes(b"frame-1")
            assert browser.receive_bytes() == b"frame-1"
            client.post("/api/console/auth/logout", headers=admin)  # technician signs out in another tab
            agent.send_bytes(b"frame-2")
            with pytest.raises(WebSocketDisconnect) as closed:
                browser.receive_bytes()
            assert closed.value.code == 4401
    # A viewer token minted by a session that has since ended cannot connect.
    fresh = login(client)
    second = start(client, fresh, device, mode="desktop")
    token = client.post(f"/api/console/remote/sessions/{second['id']}/viewer-token", headers=fresh).json()["token"]
    client.post("/api/console/auth/logout", headers=fresh)
    with pytest.raises(WebSocketDisconnect) as refused:
        with client.websocket_connect(f"/ws/remote/{second['id']}/viewer?token={token}") as ws:
            ws.receive_text()
    assert refused.value.code == 4401
