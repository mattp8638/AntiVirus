"""Everything the console lets you create can also be changed or removed, with guards where removal would lose history
or silently change what devices do."""

from conftest import enroll

RULE = """
title: Custom - block rclone exfil
id: custom-rclone-delete
logsource: {category: process_creation}
detection: {sel: {ProcessName: rclone.exe}, condition: sel}
level: medium
"""


def ok(reply, status=200):
    assert reply.status_code == status, reply.text
    return reply.json()


def step_up(client, admin):
    from conftest import ADMIN_PASSWORD

    token = ok(client.post("/api/console/auth/reauth", headers=admin, json={"password": ADMIN_PASSWORD}))["reauthToken"]
    return {**admin, "X-Fenrir-Reauth": token}


def test_a_protection_policy_in_use_is_not_deleted(client, admin, tenant):
    policy = ok(client.post("/api/console/policies", headers=admin, json={"tenantId": tenant["id"], "name": "Kiosks"}))
    group = ok(client.post("/api/console/groups", headers=admin, json={"tenantId": tenant["id"], "name": "Kiosks", "policyId": policy["id"]}))
    refused = client.delete(f"/api/console/policies/{policy['id']}", headers=admin)
    assert refused.status_code == 409 and "group 'Kiosks'" in refused.json()["detail"]
    ok(client.patch(f"/api/console/groups/{group['id']}", headers=admin, json={"policyId": None}))
    ok(client.delete(f"/api/console/policies/{policy['id']}", headers=admin))
    assert all(p["id"] != policy["id"] for p in client.get("/api/console/policies", headers=admin).json())


def test_a_device_override_keeps_its_policy(client, admin, tenant):
    policy = ok(client.post("/api/console/policies", headers=admin, json={"tenantId": tenant["id"], "name": "Override"}))
    pc = enroll(client, admin, tenant)
    ok(client.patch(f"/api/console/devices/{pc['deviceId']}", headers=admin, json={"policyId": policy["id"]}))
    assert "1 device override" in client.delete(f"/api/console/policies/{policy['id']}", headers=admin).json()["detail"]


def test_vault_credentials_are_deleted_only_after_a_fresh_sign_in(client, admin, tenant):
    cred = ok(client.post("/api/console/vault/credentials", headers=admin, json={"tenantId": tenant["id"], "name": "Router", "secret": "s3cret"}))
    assert client.delete(f"/api/console/vault/credentials/{cred['id']}", headers=admin).status_code == 403
    ok(client.delete(f"/api/console/vault/credentials/{cred['id']}", headers=step_up(client, admin)))
    assert all(c["id"] != cred["id"] for c in client.get("/api/console/vault/credentials", headers=admin).json())


def test_custom_detection_rules_delete_and_shipped_ones_turn_off(client, admin):
    custom = ok(client.post("/api/console/rules", headers=admin, json={"rule": RULE}))
    ok(client.delete(f"/api/console/rules/{custom['id']}", headers=admin))
    builtin = next(r for r in client.get("/api/console/rules", headers=admin).json() if r.get("builtin"))
    refused = client.delete(f"/api/console/rules/{builtin['id']}", headers=admin)
    assert refused.status_code == 409 and "turn it off" in refused.json()["detail"]


def test_automations_can_be_deleted(client, admin, tenant):
    rule = ok(client.post("/api/console/automations", headers=admin, json={"tenantId": tenant["id"], "name": "Isolate ransomware",
                                                                          "actions": [{"type": "ticket"}]}))
    ok(client.delete(f"/api/console/automations/{rule['id']}", headers=admin))
    assert all(r["id"] != rule["id"] for r in client.get("/api/console/automations", headers=admin).json())


def test_service_boards_with_tickets_or_the_last_board_stay(client, admin, tenant):
    first = ok(client.post("/api/console/psa/boards", headers=admin, json={"name": "Projects"}))
    boards = client.get("/api/console/psa/boards", headers=admin).json()
    ticket = ok(client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "Printer", "boardId": first["id"]}))
    refused = client.delete(f"/api/console/psa/boards/{first['id']}", headers=admin)
    assert refused.status_code == 409 and "ticket" in refused.json()["detail"]
    other = next((b for b in boards if b["id"] != first["id"]), None) or ok(client.post("/api/console/psa/boards", headers=admin, json={"name": "Desk"}))
    ok(client.patch(f"/api/console/tickets/{ticket['id']}", headers=admin, json={"boardId": other["id"]}))
    ok(client.delete(f"/api/console/psa/boards/{first['id']}", headers=admin))
    remaining = client.get("/api/console/psa/boards", headers=admin).json()
    if len(remaining) == 1:
        assert client.delete(f"/api/console/psa/boards/{remaining[0]['id']}", headers=admin).status_code == 409


def test_time_entries_can_be_removed_until_billed(client, admin, tenant):
    ticket = ok(client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "Laptop"}))
    entry = ok(client.post("/api/console/psa/time", headers=admin, json={"ticketId": ticket["id"], "hours": 0.5}))
    edited = ok(client.patch(f"/api/console/psa/time/{entry['id']}", headers=admin, json={"hours": 0.75, "notes": "Replaced battery"}))
    assert edited["notes"] == "Replaced battery"
    ok(client.delete(f"/api/console/psa/time/{entry['id']}", headers=admin))
    billed = ok(client.post("/api/console/psa/time", headers=admin, json={"ticketId": ticket["id"], "hours": 1}))
    from fenrir_cloud import db as database
    from fenrir_cloud.models import TimeEntry

    with database.session_factory()() as db:
        db.get(TimeEntry, billed["id"]).status = "Billed"
        db.commit()
    assert client.delete(f"/api/console/psa/time/{billed['id']}", headers=admin).status_code == 409


def test_quotes_delete_unless_accepted(client, admin, tenant):
    quote = ok(client.post("/api/console/psa/quotes", headers=admin, json={"accountTenantId": tenant["id"], "title": "Refresh",
                                                                         "lines": [{"description": "Labour", "quantity": 1, "unitPrice": 85}]}))
    ok(client.delete(f"/api/console/psa/quotes/{quote['id']}", headers=admin))
    accepted = ok(client.post("/api/console/psa/quotes", headers=admin, json={"accountTenantId": tenant["id"], "title": "Signed",
                                                                            "lines": [{"description": "Labour", "quantity": 1, "unitPrice": 85}]}))
    ok(client.patch(f"/api/console/psa/quotes/{accepted['id']}", headers=admin, json={"status": "Accepted"}))
    assert client.delete(f"/api/console/psa/quotes/{accepted['id']}", headers=admin).status_code == 409


def test_backup_plans_can_be_edited_and_removed(client, admin, tenant):
    plan = ok(client.post("/api/console/backup/plans", headers=admin, json={"tenantId": tenant["id"], "name": "File server", "provider": "Veeam"}))
    edited = ok(client.patch(f"/api/console/backup/plans/{plan['id']}", headers=admin, json={"name": "File server (nightly)", "rpoHours": 12}))
    assert edited["name"] == "File server (nightly)" and edited["rpoHours"] == 12
    ok(client.delete(f"/api/console/backup/plans/{plan['id']}", headers=admin))
    assert client.get("/api/console/backup/plans", headers=admin).json() == []


def test_network_monitors_can_be_deleted(client, admin, tenant):
    monitor = ok(client.post("/api/console/network/monitors", headers=admin, json={"tenantId": tenant["id"], "name": "Website",
                                                                                  "address": "203.0.113.10", "port": 443}))
    ok(client.delete(f"/api/console/network/monitors/{monitor['id']}", headers=admin))
    assert client.get("/api/console/network/monitors", headers=admin).json() == []


def test_external_assets_can_be_removed(client, admin, tenant):
    asset = ok(client.post("/api/console/exposure/assets", headers=admin, json={"tenantId": tenant["id"], "target": "acme.example",
                                                                               "ownershipConfirmed": True}))
    ok(client.delete(f"/api/console/exposure/assets/{asset['id']}", headers=admin))
    assert client.get("/api/console/exposure/assets", headers=admin).json() == []


def test_webhooks_can_be_edited(client, admin, tenant):
    hook = ok(client.post("/api/console/webhooks", headers=admin, json={"tenantId": tenant["id"], "name": "Slack", "url": "https://hooks.example/a",
                                                                       "kind": "slack", "events": ["incident.created"]}))
    edited = ok(client.patch(f"/api/console/webhooks/{hook['id']}", headers=admin, json={"url": "https://hooks.example/b", "events": ["*"]}))
    assert edited["url"] == "https://hooks.example/b" and edited["events"] == ["*"]
    assert client.patch(f"/api/console/webhooks/{hook['id']}", headers=admin, json={"url": "http://insecure"}).status_code == 400


def test_another_customer_cannot_delete_these(client, admin, tenant):
    from conftest import login

    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    client.post("/api/console/users", headers=admin, json={"tenantId": other["id"], "email": "ops@other.example",
                                                           "password": "other-password-123", "role": "tenant_admin"})
    ops = login(client, "ops@other.example", "other-password-123")
    policy = ok(client.post("/api/console/policies", headers=admin, json={"tenantId": tenant["id"], "name": "Ours"}))
    monitor = ok(client.post("/api/console/network/monitors", headers=admin, json={"tenantId": tenant["id"], "name": "Site",
                                                                                  "address": "203.0.113.10", "port": 443}))
    asset = ok(client.post("/api/console/exposure/assets", headers=admin, json={"tenantId": tenant["id"], "target": "acme.example",
                                                                               "ownershipConfirmed": True}))
    for path in (f"policies/{policy['id']}", f"network/monitors/{monitor['id']}", f"exposure/assets/{asset['id']}"):
        assert client.delete(f"/api/console/{path}", headers=ops).status_code in (403, 404), path


def test_customers_can_be_renamed_and_given_a_default_policy(client, admin, tenant):
    policy = ok(client.post("/api/console/policies", headers=admin, json={"tenantId": tenant["id"], "name": "Acme standard"}))
    saved = ok(client.patch(f"/api/console/tenants/{tenant['id']}", headers=admin, json={"name": "Acme Dental Group", "defaultPolicyId": policy["id"]}))
    assert saved["name"] == "Acme Dental Group" and saved["defaultPolicyId"] == policy["id"]
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    theirs = ok(client.post("/api/console/policies", headers=admin, json={"tenantId": other["id"], "name": "Theirs"}))
    assert client.patch(f"/api/console/tenants/{tenant['id']}", headers=admin, json={"defaultPolicyId": theirs["id"]}).status_code == 400
    assert client.patch(f"/api/console/tenants/{tenant['id']}", headers=admin, json={"name": ""}).status_code == 422
