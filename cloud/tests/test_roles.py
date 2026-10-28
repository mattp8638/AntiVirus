"""CORE-02: custom roles, customer assignments and least privilege.

Before this change a customer's tenant admin could promote anyone in their customer - themselves included - to
msp_admin, because only platform_admin was guarded when changing a role."""

from conftest import enroll, login

USERS = "/api/console/users"
ROLES = "/api/console/roles"


def make_user(client, headers, tenant_id, email, role, **extra):
    reply = client.post(USERS, headers=headers, json={"tenantId": tenant_id, "email": email, "password": "long-password-123", "role": role, **extra})
    return reply


def me(client, headers):
    return client.get("/api/console/auth/me", headers=headers).json()


def test_customer_admin_cannot_escalate(client, admin, tenant):
    assert make_user(client, admin, tenant["id"], "ta@acme.example", "tenant_admin").status_code == 200
    ta = login(client, "ta@acme.example", "long-password-123")
    ta_id = me(client, ta)["user"]["id"]
    # Self-promotion and promoting others to MSP or platform roles are refused.
    for role in ("msp_admin", "platform_admin", "technician", "billing"):
        assert client.patch(f"{USERS}/{ta_id}", headers=ta, json={"role": role}).status_code == 403, role
    made = make_user(client, ta, tenant["id"], "viewer@acme.example", "viewer").json()
    assert client.patch(f"{USERS}/{made['id']}", headers=ta, json={"role": "msp_admin"}).status_code == 403
    assert make_user(client, ta, tenant["id"], "x@acme.example", "msp_admin").status_code == 403
    assert client.patch(f"{USERS}/{made['id']}", headers=ta, json={"role": "tenant_analyst"}).status_code == 200
    assert me(client, ta)["user"]["role"] == "tenant_admin"
    # Nor can they manage an account more powerful than their own in their customer.
    stronger = make_user(client, admin, tenant["id"], "msp-in-customer@acme.example", "msp_admin").json()
    assert client.patch(f"{USERS}/{stronger['id']}", headers=ta, json={"password": "taken-over-123456"}).status_code == 403


def test_remote_support_role_least_privilege(client, admin, tenant):
    msp_id = me(client, admin)["user"]["tenantId"]
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Co", "template": "balanced"}).json()
    device = enroll(client, admin, tenant)
    foreign = enroll(client, admin, other, hostname="OTHER-1", serial="O-1")
    role = client.post(ROLES, headers=admin, json={"tenantId": msp_id, "name": "Remote support", "permissions": ["read", "respond", "remote"]})
    assert role.status_code == 200, role.text
    role = role.json()
    # An MSP technician limited to one customer, with the remote-support role.
    made = make_user(client, admin, msp_id, "remote@msp.example", role["role"], assignedTenantIds=[tenant["id"]])
    assert made.status_code == 200, made.text
    tech = login(client, "remote@msp.example", "long-password-123")
    assert set(me(client, tech)["permissions"]) == {"read", "respond", "remote"}
    assert {t["id"] for t in me(client, tech)["tenants"]} == {tenant["id"]}
    assert client.post("/api/console/remote/sessions", headers=tech, json={"deviceId": device["deviceId"]}).status_code == 200
    assert client.post("/api/console/remote/sessions", headers=tech, json={"deviceId": foreign["deviceId"]}).status_code == 404
    script = client.post("/api/console/rmm/scripts", headers=admin, json={"name": "Echo", "language": "powershell", "body": "Write-Output 1"}).json()
    run = client.post(f"/api/console/rmm/scripts/{script['id']}/run", headers=tech, json={"targets": {"deviceIds": [device["deviceId"]]}})
    assert run.status_code == 403
    assert client.post(f"/api/console/devices/{device['deviceId']}/commands", headers=tech, json={"type": "device.isolate"}).status_code == 200
    # Taking "remote" away applies on the next request.
    assert client.patch(f"{ROLES}/{role['id']}", headers=admin, json={"permissions": ["read", "respond"]}).status_code == 200
    assert client.post("/api/console/remote/sessions", headers=tech, json={"deviceId": device["deviceId"]}).status_code == 403
    assert client.delete(f"{ROLES}/{role['id']}", headers=admin).status_code == 409  # still assigned


def test_script_runner_cannot_remote_or_wipe(client, admin, tenant):
    device = enroll(client, admin, tenant)
    role = client.post(ROLES, headers=admin, json={"tenantId": tenant["id"], "name": "Script runner",
                                                   "permissions": ["read", "configure", "scripts"]}).json()
    make_user(client, admin, tenant["id"], "scripts@acme.example", role["role"])
    runner = login(client, "scripts@acme.example", "long-password-123")
    script = client.post("/api/console/rmm/scripts", headers=admin, json={"tenantId": tenant["id"], "name": "Echo", "language": "powershell",
                                                                         "body": "Write-Output 1"}).json()
    assert client.post(f"/api/console/rmm/scripts/{script['id']}/run", headers=runner,
                       json={"targets": {"deviceIds": [device["deviceId"]]}}).status_code == 200
    assert client.post("/api/console/remote/sessions", headers=runner, json={"deviceId": device["deviceId"]}).status_code == 403
    assert client.post(f"/api/console/devices/{device['deviceId']}/commands", headers=runner,
                       json={"type": "localadmin.reduce"}).status_code == 403  # destructive


def test_custom_roles_cannot_exceed_their_creator(client, admin, tenant):
    make_user(client, admin, tenant["id"], "ta@acme.example", "tenant_admin")
    ta = login(client, "ta@acme.example", "long-password-123")
    assert client.post(ROLES, headers=ta, json={"name": "Sneaky", "permissions": ["read", "crm"]}).status_code == 403
    assert client.post(ROLES, headers=admin, json={"name": "Root", "permissions": ["platform"]}).status_code == 400
    mine = client.post(ROLES, headers=ta, json={"name": "Helpdesk", "permissions": ["read", "respond"]}).json()
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Co", "template": "balanced"}).json()
    # A customer's role cannot be given to a user of another customer, and an unknown role is refused.
    assert make_user(client, admin, other["id"], "o@other.example", mine["role"]).status_code == 400
    assert make_user(client, admin, tenant["id"], "u@acme.example", "custom:crl_missing").status_code == 400
    # Assignments must stay inside the user's own tenant.
    assert make_user(client, admin, tenant["id"], "a@acme.example", "viewer", assignedTenantIds=[other["id"]]).status_code == 400
    listing = client.get(ROLES, headers=ta).json()
    grantable = {p["key"] for p in listing["permissions"] if p["grantable"]}
    assert "crm" not in grantable and "platform" not in grantable and "remote" in grantable
    assert [r["name"] for r in listing["custom"]] == ["Helpdesk"]
    assert client.get(ROLES, headers=ta, params={"tenant_id": other["id"]}).status_code in (403, 404)
