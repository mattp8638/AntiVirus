"""ISMS roles per person per customer (plan decision R7), through the API."""

from datetime import datetime, timedelta, timezone

from conftest import login

PW = "a-long-password-123"


def make_user(client, admin, tenant_id, email, role):
    r = client.post("/api/console/users", headers=admin,
                    json={"tenantId": tenant_id, "email": email, "password": PW, "name": email.split("@")[0], "role": role})
    assert r.status_code == 200, r.text
    return r.json()


def customer(client, admin, name):
    r = client.post("/api/console/tenants", json={"name": name, "template": "balanced"}, headers=admin)
    assert r.status_code == 200, r.text
    return r.json()


def put(client, headers, tenant_id, user_id, role, expires=None):
    body = {"tenantId": tenant_id, "userId": user_id, "role": role}
    if expires:
        body["expiresAt"] = expires
    return client.put("/api/console/isms/memberships", headers=headers, json=body)


def soon(days=30):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def test_nobody_has_an_isms_role_until_one_is_granted(client, admin, tenant):
    me = client.get(f"/api/console/isms/me?tenant_id={tenant['id']}", headers=admin).json()
    assert me["role"] is None and me["permissions"] == []
    assert me["canManageRoles"] is True  # the platform admin holds Fenrir's grc permission


def test_grant_change_and_revoke_with_audit(client, admin, tenant):
    owner = make_user(client, admin, tenant["id"], "owner@acme.test", "tenant_analyst")
    r = put(client, admin, tenant["id"], owner["id"], "control_owner")
    assert r.status_code == 200, r.text
    assert (r.json()["role"], r.json()["email"]) == ("control_owner", "owner@acme.test")

    headers = login(client, "owner@acme.test", PW)
    me = client.get(f"/api/console/isms/me?tenant_id={tenant['id']}", headers=headers).json()
    assert me["role"] == "control_owner" and "evidence.upload" in me["permissions"]
    assert me["canManageRoles"] is False

    assert put(client, admin, tenant["id"], owner["id"], "approver").json()["role"] == "approver"
    listing = client.get(f"/api/console/isms/memberships?tenant_id={tenant['id']}", headers=admin).json()["memberships"]
    assert [(m["email"], m["role"]) for m in listing] == [("owner@acme.test", "approver")]

    assert client.delete(f"/api/console/isms/memberships/{listing[0]['id']}", headers=admin).status_code == 200
    assert client.get(f"/api/console/isms/me?tenant_id={tenant['id']}", headers=headers).json()["role"] is None

    events = client.get("/api/console/audit?limit=50", headers=admin).json()
    actions = [e["action"] for e in events if e["action"].startswith("isms.")]
    assert sorted(actions) == ["isms.role_changed", "isms.role_granted", "isms.role_revoked"]


def test_roles_are_checked(client, admin, tenant):
    user = make_user(client, admin, tenant["id"], "a@acme.test", "viewer")
    assert put(client, admin, tenant["id"], user["id"], "superuser").status_code == 400
    assert put(client, admin, tenant["id"], user["id"], "auditor").status_code == 400  # auditors need an expiry
    assert put(client, admin, tenant["id"], user["id"], "auditor", soon(400)).status_code == 400  # at most a year
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    assert put(client, admin, tenant["id"], user["id"], "approver", past).status_code == 400
    assert put(client, admin, tenant["id"], user["id"], "auditor", soon(30)).status_code == 200


def test_expired_roles_give_nothing(client, admin, tenant):
    from fenrir_cloud import db as database
    from fenrir_cloud.isms.models import IsmsMembership
    from fenrir_cloud.models import utcnow

    user = make_user(client, admin, tenant["id"], "aud@acme.test", "viewer")
    row_id = put(client, admin, tenant["id"], user["id"], "auditor", soon(10)).json()["id"]
    with database.session_factory()() as db:
        db.get(IsmsMembership, row_id).expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
    headers = login(client, "aud@acme.test", PW)
    assert client.get(f"/api/console/isms/me?tenant_id={tenant['id']}", headers=headers).json()["role"] is None


def test_portal_accounts_can_only_be_staff(client, admin, tenant):
    jo = make_user(client, admin, tenant["id"], "jo@acme.test", "client")
    assert put(client, admin, tenant["id"], jo["id"], "isms_manager").status_code == 400
    assert put(client, admin, tenant["id"], jo["id"], "staff").status_code == 200
    other = customer(client, admin, "Globex")
    assert put(client, admin, other["id"], jo["id"], "staff").status_code == 400  # not their organization


def test_the_person_must_see_the_customer_in_fenrir(client, admin, tenant):
    other = customer(client, admin, "Globex")
    globex_user = make_user(client, admin, other["id"], "g@globex.test", "tenant_admin")
    r = put(client, admin, tenant["id"], globex_user["id"], "isms_manager")
    assert r.status_code == 400 and "cannot see" in r.json()["detail"]


def test_isms_tenant_admins_manage_roles_without_fenrir_grc(client, admin, tenant):
    analyst = make_user(client, admin, tenant["id"], "lead@acme.test", "tenant_analyst")  # no grc permission
    staff = make_user(client, admin, tenant["id"], "s@acme.test", "viewer")
    headers = login(client, "lead@acme.test", PW)
    assert put(client, headers, tenant["id"], staff["id"], "staff").status_code == 403
    put(client, admin, tenant["id"], analyst["id"], "tenant_admin")
    assert put(client, headers, tenant["id"], staff["id"], "staff").status_code == 200


def test_tenant_isolation(client, admin, tenant):
    other = customer(client, admin, "Globex")
    acme_admin = make_user(client, admin, tenant["id"], "boss@acme.test", "tenant_admin")
    globex_admin = make_user(client, admin, other["id"], "boss@globex.test", "tenant_admin")
    put(client, admin, tenant["id"], acme_admin["id"], "isms_manager")
    globex_row = put(client, admin, other["id"], globex_admin["id"], "isms_manager").json()

    acme = login(client, "boss@acme.test", PW)
    assert client.get(f"/api/console/isms/memberships?tenant_id={other['id']}", headers=acme).status_code == 404
    assert client.get(f"/api/console/isms/me?tenant_id={other['id']}", headers=acme).status_code == 404
    assert client.delete(f"/api/console/isms/memberships/{globex_row['id']}", headers=acme).status_code == 404
    assert put(client, acme, other["id"], acme_admin["id"], "isms_manager").status_code == 404
    listing = client.get(f"/api/console/isms/memberships?tenant_id={tenant['id']}", headers=acme).json()["memberships"]
    assert [m["email"] for m in listing] == ["boss@acme.test"]


def test_role_catalogue(client, admin):
    roles = client.get("/api/console/isms/roles", headers=admin).json()["roles"]
    assert [r["role"] for r in roles] == ["tenant_admin", "isms_manager", "control_owner", "approver", "staff",
                                          "auditor", "executive_viewer"]


def test_candidates_are_people_who_can_see_the_customer(client, admin, tenant):
    other = customer(client, admin, "Globex")
    make_user(client, admin, tenant["id"], "in@acme.test", "viewer")
    make_user(client, admin, tenant["id"], "jo@acme.test", "client")
    make_user(client, admin, other["id"], "out@globex.test", "viewer")
    people = client.get(f"/api/console/isms/candidates?tenant_id={tenant['id']}", headers=admin).json()["people"]
    emails = {p["email"]: p["portal"] for p in people}
    assert emails["in@acme.test"] is False and emails["jo@acme.test"] is True
    assert "out@globex.test" not in emails
    assert "admin@fenrir.local" in emails  # MSP staff see every customer
