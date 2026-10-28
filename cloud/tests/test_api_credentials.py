"""CORE-04: scoped API credentials. Issue, use, scope, expiry, rotation, revocation and usage tracking; a credential is
its own service identity and never inherits its creator's (platform administrator's) unrestricted access."""

from datetime import timedelta

from conftest import ADMIN_PASSWORD, enroll, login
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import ApiCredential, utcnow
from test_documentation_vault import stepup

ROUTE = "/api/console/api-credentials"


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def create(client, headers, tenant_id, scopes, **extra):
    return client.post(ROUTE, headers=headers, json={"tenantId": tenant_id, "name": "PSA sync", "scopes": scopes, **extra})


def test_issue_use_and_scope(client, admin, tenant):
    device = enroll(client, admin, tenant)
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Co", "template": "balanced"}).json()
    enroll(client, admin, other, hostname="OTHER-1", serial="O-1")
    assert create(client, admin, tenant["id"], ["read"]).json()["detail"] == "reauth_required"  # minting needs a fresh password
    made = create(client, stepup(client, admin), tenant["id"], ["read"])
    assert made.status_code == 200, made.text
    token = made.json()["token"]
    assert token.startswith("fsk_") and made.json()["state"] == "active"
    key = bearer(token)
    # Reads within its customer only - even though a platform administrator created it.
    devices = client.get("/api/console/devices", headers=key).json()
    rows = devices if isinstance(devices, list) else devices.get("items", devices.get("devices", []))
    assert {d["id"] for d in rows} == {device["deviceId"]}
    assert client.get("/api/console/devices", headers=key, params={"tenant_id": other["id"]}).status_code in (403, 404)
    # Only the granted permission: no writes, no tenant creation, no platform actions, no vault.
    assert client.post("/api/console/tenants", headers=key, json={"name": "Nope", "template": "balanced"}).status_code == 403
    assert client.post("/api/console/tickets", headers=key, json={"subject": "x"}).status_code in (200, 403)  # anyone may ask for help
    assert client.get("/api/console/agent-rollouts", headers=key).status_code == 403
    assert client.post(ROUTE, headers=key, json={"tenantId": tenant["id"], "name": "x", "scopes": ["read"]}).status_code == 403
    # It cannot use sign-in endpoints or the portal, and its service user cannot sign in or be edited as a user.
    assert client.get("/api/console/auth/me", headers=key).status_code == 403
    listed = client.get(ROUTE, headers=admin).json()
    cred = listed["credentials"][0]
    assert "token" not in cred and cred["useCount"] >= 3 and cred["lastUsedAt"] and cred["prefix"] == token[:12]
    users = client.get("/api/console/users", headers=admin).json()
    assert not any(u["email"].startswith("api+") for u in users)
    db = session_factory()()
    try:
        service_user_id = db.get(ApiCredential, cred["id"]).service_user_id
    finally:
        db.close()
    assert client.patch(f"/api/console/users/{service_user_id}", headers=admin, json={"role": "tenant_admin"}).status_code == 404
    assert client.post("/api/console/auth/login", json={"email": f"api+{cred['id']}@service.fenrir", "password": "!service"}).status_code == 401


def test_cannot_grant_more_than_allowed(client, admin, tenant):
    for scope in ("platform", "manage_tenants", "vault", "m365_admin"):
        reply = create(client, stepup(client, admin), tenant["id"], [scope])
        assert reply.status_code == 400 and "cannot be given" in reply.text, scope
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "ta@acme.example",
                                                           "password": "acme-password-123", "role": "tenant_admin"})
    ta = login(client, "ta@acme.example", "acme-password-123")
    ta_step = {**ta, "X-Fenrir-Reauth": client.post("/api/console/auth/reauth", headers=ta, json={"password": "acme-password-123"}).json()["reauthToken"]}
    beyond = create(client, ta_step, tenant["id"], ["crm"])  # tenant admins have no CRM permission
    assert beyond.status_code == 400 and "do not have" in beyond.text
    assert create(client, ta_step, tenant["id"], ["read", "configure"]).status_code == 200
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Co", "template": "balanced"}).json()
    assert create(client, ta_step, other["id"], ["read"]).status_code == 404  # another customer
    assert create(client, stepup(client, admin), tenant["id"], ["read"], expiresDays=400).status_code == 422
    assert create(client, stepup(client, admin), tenant["id"], []).status_code == 422


def test_expiry_rotation_and_revocation(client, admin, tenant):
    made = create(client, stepup(client, admin), tenant["id"], ["read"]).json()
    old = bearer(made["token"])
    assert client.get("/api/console/devices", headers=old).status_code == 200
    assert client.post(f"{ROUTE}/{made['id']}/rotate", headers=admin).json()["detail"] == "reauth_required"
    rotated = client.post(f"{ROUTE}/{made['id']}/rotate", headers=stepup(client, admin)).json()
    new = bearer(rotated["token"])
    assert client.get("/api/console/devices", headers=old).status_code == 401  # the old secret stops at once
    assert client.get("/api/console/devices", headers=new).status_code == 200
    db = session_factory()()
    try:
        db.get(ApiCredential, made["id"]).expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
    finally:
        db.close()
    expired = client.get("/api/console/devices", headers=new)
    assert expired.status_code == 401 and "expired" in expired.text
    assert client.post(f"{ROUTE}/{made['id']}/revoke", headers=admin).json()["state"] == "revoked"
    assert client.get("/api/console/devices", headers=new).status_code == 401
    assert client.post(f"{ROUTE}/{made['id']}/rotate", headers=stepup(client, admin)).status_code == 409
    actions = [e["action"] for e in client.get("/api/console/audit", headers=admin).json()]
    assert {"api_credential.created", "api_credential.rotated", "api_credential.revoked"} <= set(actions)


def test_sensitive_actions_needing_a_password_check_are_impossible(client, admin, tenant):
    made = create(client, stepup(client, admin), tenant["id"], ["read", "configure"]).json()
    key = bearer(made["token"])
    reply = client.post(f"/api/console/users/{'usr_x'}/sessions/revoke", headers=key)
    assert reply.status_code in (403, 404)
    assert client.post("/api/console/auth/reauth", headers=key, json={"password": ADMIN_PASSWORD}).status_code == 403
