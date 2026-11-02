"""Microsoft 365 identity actions and onboarding/offboarding/bulk runs (mocked Microsoft; see m365_fake.py)."""
import uuid
from datetime import timedelta

import httpx
import pytest

from m365_fake import DL, DYNAMIC, GROUP, HELPDESK, MANAGER, SKU, USER, FakeTenant
from test_documentation_vault import stepup
from test_msp_modules import connection, post
from fenrir_cloud import db as database, m365_lifecycle
from fenrir_cloud.models import Alert, AuditLog, Contact, M365Action, M365Workflow, Ticket, utcnow


@pytest.fixture
def fake(monkeypatch):
    tenant = FakeTenant()
    monkeypatch.setattr(httpx, "Client", tenant.client)
    return tenant


def action(client, admin, conn, operation, parameters, target=USER):
    body = {"requestId": str(uuid.uuid4()), "operation": operation, "parameters": parameters}
    if target:
        body["targetId"] = target
    return client.post("/api/console/m365/connections/" + conn["id"] + "/actions", headers=admin, json=body)


def execute(client, admin, conn, job):
    response = client.post("/api/console/m365/connections/" + conn["id"] + "/actions/" + job["id"] + "/execute",
                           headers=stepup(client, admin), json={"confirmed": True})
    assert response.status_code == 200, response.text
    return response.json()


def stored_everywhere(text: str) -> bool:
    with database.session_factory()() as db:
        blobs = [str(a.result) + str(a.preview) + str(a.parameters) for a in db.query(M365Action)]
        blobs += [str(a.details) for a in db.query(AuditLog)]
        blobs += [str(w.steps) + str(w.options) for w in db.query(M365Workflow)]
    return any(text in b for b in blobs)


def test_input_checks_for_new_actions(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    assert action(client, admin, conn, "user.temp_admin", {"roleId": str(uuid.uuid4()), "hours": 2}).status_code == 422
    assert action(client, admin, conn, "user.temp_admin", {"roleId": HELPDESK, "hours": 100}).status_code == 422
    assert action(client, admin, conn, "user.tap", {"lifetimeMinutes": 5}).status_code == 422
    assert action(client, admin, conn, "group.create", {"displayName": "X", "mailNickname": "x"}, target=USER).status_code == 422
    assert action(client, admin, conn, "guest.invite", {"email": "not-an-email"}, target=None).status_code == 422
    assert action(client, admin, conn, "user.reset_mfa", {"anything": 1}).status_code == 422


def test_password_reset_and_tap_are_shown_once_and_never_stored(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    job = action(client, admin, conn, "user.reset_password", {"forceChange": True}).json()
    done = execute(client, admin, conn, job)
    password = done["secret"]
    assert done["status"] == "succeeded" and len(password) == 16 and fake.users[USER]["passwordSet"] == password
    assert not stored_everywhere(password)
    again = execute(client, admin, conn, job)  # a finished action is never replayed, and the secret is gone
    assert "secret" not in again and again["status"] == "succeeded"

    tap = execute(client, admin, conn, action(client, admin, conn, "user.tap", {"lifetimeMinutes": 60, "usableOnce": True}).json())
    assert tap["secret"] == "TAP-SECRET-4711" and tap["result"]["lifetimeMinutes"] == 60
    assert not stored_everywhere("TAP-SECRET-4711")


def test_mfa_reset_removes_methods_but_never_the_password(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    job = action(client, admin, conn, "user.reset_mfa", {}).json()
    assert [m["label"] for m in job["preview"]["methods"]] == ["Microsoft Authenticator", "Phone"]
    done = execute(client, admin, conn, job)
    assert done["status"] == "succeeded" and done["result"]["removed"] == ["Microsoft Authenticator", "Phone"]
    assert [m["id"] for m in fake.methods[USER]] == ["pw"]
    deletes = [p for m, p, _ in fake.requests if m == "DELETE"]
    assert deletes[0].endswith("/microsoftAuthenticatorMethods/auth-1") and "/phoneMethods/" in deletes[1]


def test_mfa_reset_reports_partial_success(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    job = action(client, admin, conn, "user.reset_mfa", {}).json()
    fake.fail[("DELETE", r"/phoneMethods/")] = 403
    done = execute(client, admin, conn, job)
    assert done["status"] == "partial" and done["result"]["failed"][0]["label"] == "Phone"
    assert "Insufficient privileges" in done["result"]["failed"][0]["reason"]


def test_temporary_admin_is_removed_when_it_expires(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    assert action(client, admin, conn, "user.temp_admin", {"roleId": HELPDESK, "hours": 2}).status_code == 400  # already holds it
    job = action(client, admin, conn, "user.temp_admin", {"roleId": "62e90394-69f5-4237-9190-012177145e10", "hours": 2}).json()
    assert job["preview"]["role"]["name"] == "Global Administrator"
    done = execute(client, admin, conn, job)
    assignment = done["result"]["assignmentId"]
    assert assignment in fake.assignments
    with database.session_factory()() as db:
        assert m365_lifecycle.expire_temp_admins(db) == 0  # not yet
        row = db.get(M365Action, job["id"])
        row.result = {**row.result, "expiresAt": (utcnow() - timedelta(minutes=1)).isoformat() + "Z"}
        db.commit()
        assert m365_lifecycle.expire_temp_admins(db) == 1
        assert db.get(M365Action, job["id"]).result["removedBy"] == "system:expiry"
        assert m365_lifecycle.expire_temp_admins(db) == 0
    assert assignment not in fake.assignments and "ra-1" in fake.assignments  # the role it did not grant stays


def test_temporary_admin_can_end_early_and_alerts_when_removal_keeps_failing(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    first = execute(client, admin, conn, action(client, admin, conn, "user.temp_admin", {"roleId": "62e90394-69f5-4237-9190-012177145e10", "hours": 4}).json())
    ended = client.post("/api/console/m365/connections/" + conn["id"] + "/actions/" + first["id"] + "/end-role", headers=stepup(client, admin)).json()
    assert ended["result"]["removal"] == "removed" and first["result"]["assignmentId"] not in fake.assignments

    second = execute(client, admin, conn, action(client, admin, conn, "user.temp_admin", {"roleId": "62e90394-69f5-4237-9190-012177145e10", "hours": 1}).json())
    fake.fail[("DELETE", r"/roleAssignments/")] = 403
    with database.session_factory()() as db:
        row = db.get(M365Action, second["id"])
        row.result = {**row.result, "expiresAt": (utcnow() - timedelta(minutes=1)).isoformat() + "Z"}
        db.commit()
        for _ in range(5):
            m365_lifecycle.expire_temp_admins(db)
        alerts = db.query(Alert).filter(Alert.rule_id.like("m365:temp-admin:%")).all()
        assert len(alerts) == 1 and alerts[0].severity == "high"


def test_guest_invite_and_group_creation(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    assert action(client, admin, conn, "guest.invite", {"email": "jo@acme.example"}, target=None).status_code == 400  # already there
    invite = execute(client, admin, conn, action(client, admin, conn, "guest.invite", {"email": "pat@partner.example", "sendEmail": False}, target=None).json())
    assert invite["result"]["redeemUrl"].startswith("https://") and fake.calls("POST", "/invitations")[0][2]["sendInvitationMessage"] is False
    assert action(client, admin, conn, "group.create", {"displayName": "Sales 2", "mailNickname": "sales"}, target=None).status_code == 400
    made = execute(client, admin, conn, action(client, admin, conn, "group.create",
                                               {"displayName": "Project X", "mailNickname": "projectx", "kind": "m365", "ownerId": MANAGER}, target=None).json())
    body = fake.calls("POST", "/groups")[0][2]
    assert made["status"] == "succeeded" and body["groupTypes"] == ["Unified"] and body["owners@odata.bind"][0].endswith(MANAGER)


def plan(client, admin, conn, kind, options, target=None):
    body = {"kind": kind, "options": options}
    if target:
        body["targetId"] = target
    return client.post("/api/console/m365/connections/" + conn["id"] + "/workflows", headers=admin, json=body)


def run(client, admin, flow, proof=None):
    response = client.post("/api/console/m365/workflows/" + flow["id"] + "/run", headers=proof or stepup(client, admin), json={"confirmed": True})
    assert response.status_code == 200, response.text
    return response.json()


def test_offboarding_plans_runs_and_records_everything(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    with database.session_factory()() as db:
        db.add(Contact(tenant_id=tenant["parentId"] if tenant.get("parentId") else tenant["id"], account_tenant_id=tenant["id"],
                       name="Jo Leaver", email="JO@acme.example", is_primary=True))
        db.commit()
    flow = plan(client, admin, conn, "offboard", {"removeLicences": True, "outOfOffice": True, "outOfOfficeMessage": "Jo has left."}, USER).json()
    steps = {s["key"]: s for s in flow["steps"]}
    assert [i["label"] for i in steps["remove_groups"]["items"]] == ["Sales"]
    assert "All staff" in steps["remove_groups"]["warning"] and "Newsletter" in steps["remove_groups"]["warning"]
    assert steps["remove_roles"]["detail"] == "Helpdesk Administrator"
    assert "30 days" in steps["remove_licences"]["warning"]
    assert flow["steps"][-1]["key"] == "open_ticket" and not fake.calls("PATCH") and not fake.calls("DELETE")  # planning changes nothing

    out = run(client, admin, flow)
    done = out["workflow"]
    assert done["status"] == "completed", done["steps"]
    user = fake.users[USER]
    assert user["accountEnabled"] is False and user["assignedLicenses"] == [] and user["automaticReplies"]["status"] == "alwaysEnabled"
    assert USER not in fake.groups[GROUP]["members"] and USER in fake.groups[DYNAMIC]["members"] and USER in fake.groups[DL]["members"]
    assert "ra-1" not in fake.assignments and [m["id"] for m in fake.methods[USER]] == ["pw"]
    with database.session_factory()() as db:
        ticket = db.get(Ticket, done["ticketId"])
        assert ticket.subject.startswith("Offboarding: Jo Leaver") and "Convert the mailbox to shared" in ticket.description
        assert "Block sign-in: done" in ticket.description
        contact = db.query(Contact).filter_by(name="Jo Leaver").one()
        assert "[left" in contact.notes and contact.is_primary is False
    assert run(client, admin, done)["workflow"]["status"] == "completed"  # nothing runs twice


def test_a_failed_step_is_retried_and_an_unknown_one_waits_for_a_person(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    flow = plan(client, admin, conn, "offboard", {"removeMfa": False, "markContact": False, "openTicket": False}, USER).json()
    fake.fail[("DELETE", r"/roleAssignments/")] = 403
    fake.fail[("POST", r"/revokeSignInSessions")] = 503
    out = run(client, admin, flow)["workflow"]
    status = {s["key"]: s["status"] for s in out["steps"]}
    assert out["status"] == "partial" and status["remove_roles"] == "failed" and status["revoke_sessions"] == "unknown"
    assert status["block_signin"] == "done" and status["remove_groups"] == "done"
    fake.fail.clear()
    revokes = len(fake.calls("POST", "revokeSignInSessions"))
    out = run(client, admin, out)["workflow"]
    status = {s["key"]: s["status"] for s in out["steps"]}
    assert status["remove_roles"] == "done" and status["revoke_sessions"] == "unknown"
    assert len(fake.calls("POST", "revokeSignInSessions")) == revokes  # unknown is never replayed by itself
    index = [s["key"] for s in out["steps"]].index("revoke_sessions")
    url = f"/api/console/m365/workflows/{out['id']}/steps/{index}/resolve"
    resolved = client.post(url, headers=stepup(client, admin), json={"outcome": "retry"}).json()
    assert resolved["steps"][index]["status"] == "pending"
    assert run(client, admin, resolved)["workflow"]["status"] == "completed"


def test_onboarding_creates_the_user_and_shows_the_password_once(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    profile = {"displayName": "Nia New", "userPrincipalName": "nia@acme.example", "mailNickname": "nia", "usageLocation": "GB", "jobTitle": "Sales"}
    assert plan(client, admin, conn, "onboard", {"profile": {**profile, "userPrincipalName": "jo@acme.example"}}).status_code == 400
    assert plan(client, admin, conn, "onboard", {"profile": profile, "groupIds": [DYNAMIC]}).status_code == 400
    flow = plan(client, admin, conn, "onboard", {"profile": profile, "managerId": MANAGER, "skuIds": [SKU], "groupIds": [GROUP]}).json()
    assert [s["key"] for s in flow["steps"]] == ["create_user", "set_manager", "assign_licences", "add_groups", "add_contact", "open_ticket"]
    out = run(client, admin, flow)
    assert out["workflow"]["status"] == "completed", [(x["key"], x["status"], x["result"]) for x in out["workflow"]["steps"]]
    secret = out["secrets"][0]
    new = next(u for u in fake.users.values() if u.get("userPrincipalName") == "nia@acme.example")
    assert secret["userPrincipalName"] == "nia@acme.example" and new["passwordSet"] == secret["password"]
    assert new["manager"] == MANAGER and new["assignedLicenses"] == [{"skuId": SKU}] and new["id"] in fake.groups[GROUP]["members"]
    assert not stored_everywhere(secret["password"])
    with database.session_factory()() as db:
        assert db.query(Contact).filter_by(email="nia@acme.example").count() == 1


def test_bulk_import_skips_bad_rows_and_continues_across_calls(client, admin, tenant, fake, monkeypatch):
    conn = connection(client, admin, tenant)
    rows = [{"displayName": f"User {i}", "userPrincipalName": f"user{i}@acme.example", "mailNickname": f"user{i}", "usageLocation": "GB"}
            for i in range(3)]
    rows += [{"displayName": "Dup", "userPrincipalName": "user0@acme.example", "mailNickname": "dup", "usageLocation": "GB"},
             {"displayName": "Exists", "userPrincipalName": "jo@acme.example", "mailNickname": "jo", "usageLocation": "GB"},
             {"displayName": "Elsewhere", "userPrincipalName": "x@other.example", "mailNickname": "x", "usageLocation": "GB"}]
    flow = plan(client, admin, conn, "bulk_create", {"rows": rows, "skuIds": [SKU], "groupIds": [GROUP]}).json()
    skipped = [s["result"] for s in flow["steps"] if s["status"] == "skipped"]
    assert flow["targetName"] == "3 new users" and len(skipped) == 3
    monkeypatch.setattr(m365_lifecycle, "RUN_BUDGET", 0.0)  # one user per call
    secrets, out, calls, proof = [], {"workflow": flow, "more": True}, 0, stepup(client, admin)
    while out["workflow"]["status"] != "completed" and calls < 10:
        out = run(client, admin, out["workflow"], proof)
        secrets += out["secrets"]
        calls += 1
    assert calls == 3 and len(secrets) == 3 and out["more"] is False
    made = [u for u in fake.users.values() if str(u.get("userPrincipalName", "")).startswith("user")]
    assert len(made) == 3 and all(u["assignedLicenses"] == [{"skuId": SKU}] for u in made)
    assert all(u["id"] in fake.groups[GROUP]["members"] for u in made)
    assert not any(stored_everywhere(s["password"]) for s in secrets)


def test_old_plans_must_be_planned_again_and_need_microsoft_admin_rights(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    flow = plan(client, admin, conn, "offboard", {}, USER).json()
    with database.session_factory()() as db:
        db.get(M365Workflow, flow["id"]).created_at = utcnow() - timedelta(minutes=31)
        db.commit()
    response = client.post("/api/console/m365/workflows/" + flow["id"] + "/run", headers=stepup(client, admin), json={"confirmed": True})
    assert response.status_code == 409 and not fake.calls("PATCH")
    assert client.post("/api/console/m365/workflows/" + flow["id"] + "/run", headers=admin, json={"confirmed": True}).status_code == 403


def test_offboarding_covers_devices_credentials_and_billing(client, admin, tenant, fake):
    """FLOW-05: a leaver's devices are listed to collect, credentials stored for their account are flagged for rotation,
    and the billing effect is shown; nothing on issued invoices changes."""
    from conftest import enroll
    from fenrir_cloud import crypto
    from fenrir_cloud.models import Contract, Device, VaultCredential

    conn = connection(client, admin, tenant)
    laptop = enroll(client, admin, tenant, hostname="JO-LAPTOP", serial="JO-1")
    other = enroll(client, admin, tenant, hostname="RECEPTION", serial="RC-1")
    with database.session_factory()() as db:
        db.get(Device, laptop["deviceId"]).metrics = {"loggedOnUser": "ACME\\jo"}
        db.get(Device, other["deviceId"]).metrics = {"loggedOnUser": "ACME\\sam"}
        cred = VaultCredential(tenant_id=tenant["id"], name="Supplier portal", username="jo@acme.example", url="", notes="",
                               ciphertext=crypto.encrypt("x", "t"), updated_by="admin")
        db.add(cred)
        db.add(Contract(tenant_id=tenant["id"], account_tenant_id=tenant["id"], name="Managed IT", plan="complete", active=True,
                        additions=[{"product": "Microsoft 365 seats", "quantity": 0, "unitPrice": 5, "autoCount": "m365-users"}]))
        db.commit()
        cred_id = cred.id
    flow = plan(client, admin, conn, "offboard", {"markContact": False}, USER).json()
    steps = {s["key"]: s for s in flow["steps"]}
    assert [i["label"] for i in steps["review_devices"]["items"]] == ["JO-LAPTOP"]
    assert [i["label"] for i in steps["flag_credentials"]["items"]] == ["Supplier portal"]
    assert "m365-users" in steps["billing_effect"]["detail"] and steps["billing_effect"]["where"] == "fenrir"

    done = run(client, admin, flow)["workflow"]
    assert done["status"] == "completed", done["steps"]
    with database.session_factory()() as db:
        assert "rotate this credential" in db.get(VaultCredential, cred_id).notes
        ticket = db.get(Ticket, done["ticketId"])
        assert "JO-LAPTOP" in ticket.description and "Rotate any stored credential" in ticket.description
