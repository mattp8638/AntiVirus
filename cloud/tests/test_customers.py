"""Customer management: edit, archive and restore, and permanent deletion of a customer and everything it owns."""
from conftest import ADMIN_PASSWORD, enroll, login
from test_documentation_vault import stepup
from fenrir_cloud import db as database
from fenrir_cloud.models import AuditLog, Contact, Device, Tenant, Ticket, User


def make(client, admin, name):
    response = client.post("/api/console/tenants", json={"name": name, "template": "balanced"}, headers=admin)
    assert response.status_code == 200, response.text
    return response.json()


def populate(client, admin, tenant, serial):
    device = enroll(client, admin, tenant, hostname=f"{tenant['name'][:6]}-PC", serial=serial)
    ticket = client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "Printer"}).json()
    contact = client.post("/api/console/crm/contacts", headers=admin, json={"accountTenantId": tenant["id"], "name": "Pat", "email": f"pat@{serial}.example"})
    assert contact.status_code == 200, contact.text
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": f"portal@{serial}.example",
                                                           "password": ADMIN_PASSWORD, "role": "viewer"})
    return device, ticket


def test_edit_a_customer_from_crm(client, admin):
    customer = make(client, admin, "Acme Dental")
    saved = client.patch(f"/api/console/tenants/{customer['id']}", headers=admin, json={
        "name": "  Acme Dental Ltd ", "plan": "advanced", "accountOwner": "sam@msp.example",
        "profile": {"phone": "0113 496 0000", "website": "https://acme.example", "address": "1 High St, Leeds", "notes": "Key holder: Jo",
                    "ignored": "x"}})
    assert saved.status_code == 200, saved.text
    account = client.get(f"/api/console/crm/accounts/{customer['id']}", headers=admin).json()["account"]
    assert account["name"] == "Acme Dental Ltd" and account["plan"] == "advanced" and account["accountOwner"] == "sam@msp.example"
    assert account["profile"] == {"phone": "0113 496 0000", "website": "https://acme.example", "address": "1 High St, Leeds", "notes": "Key holder: Jo"}
    assert client.patch(f"/api/console/tenants/{customer['id']}", headers=admin, json={"name": "  "}).status_code == 422


def test_archive_hides_the_customer_and_stops_enrolment_until_restored(client, admin):
    customer = make(client, admin, "Archive Me")
    token = client.post("/api/console/enrollment-tokens", json={"tenantId": customer["id"], "label": "t"}, headers=admin).json()["token"]
    archived = client.post(f"/api/console/tenants/{customer['id']}/archive", headers=admin, json={"archived": True}).json()
    assert archived["archived"] is True
    assert customer["id"] not in {a["id"] for a in client.get("/api/console/crm/accounts", headers=admin).json()}
    assert customer["id"] in {a["id"] for a in client.get("/api/console/crm/accounts", headers=admin, params={"include_archived": True}).json()}
    assert next(t for t in client.get("/api/console/tenants", headers=admin).json() if t["id"] == customer["id"])["archived"] is True
    refused = client.post("/api/v1/enroll", json={"hostname": "NEW-PC", "osVersion": "Windows 11", "serialNumber": "Z1"}, headers={"X-Fenrir-Token": token})
    assert refused.status_code == 403
    client.post(f"/api/console/tenants/{customer['id']}/archive", headers=admin, json={"archived": False})
    assert customer["id"] in {a["id"] for a in client.get("/api/console/crm/accounts", headers=admin).json()}
    assert client.post("/api/v1/enroll", json={"hostname": "NEW-PC", "osVersion": "Windows 11", "serialNumber": "Z1"},
                       headers={"X-Fenrir-Token": token}).status_code == 200


def test_delete_removes_one_customer_completely_and_nothing_else(client, admin):
    gone, kept = make(client, admin, "Leaving Ltd"), make(client, admin, "Staying Ltd")
    gone_device, _ = populate(client, admin, gone, "G1")
    kept_device, kept_ticket = populate(client, admin, kept, "K1")

    preview = client.get(f"/api/console/tenants/{gone['id']}/deletion", headers=admin).json()
    labels = {r["label"]: r["count"] for r in preview["summary"]}
    assert preview["blockers"] == [] and preview["liveDevices"] == 1
    assert labels["Devices"] == 1 and labels["Tickets"] == 1 and labels["Contacts"] == 1 and labels["Customer portal users"] == 1

    url = f"/api/console/tenants/{gone['id']}"
    assert client.request("DELETE", url, headers=admin, json={"confirmName": "Leaving Ltd"}).status_code == 403  # needs fresh sign-in
    proof = stepup(client, admin)
    assert client.request("DELETE", url, headers=proof, json={"confirmName": "Leaving"}).status_code == 422
    done = client.request("DELETE", url, headers=proof, json={"confirmName": "Leaving Ltd"})
    assert done.status_code == 200, done.text
    assert done.json()["total"] >= 4

    # The agent is cut off at once.
    assert client.get(f"/api/v1/devices/{gone_device['deviceId']}/commands/pending", headers=gone_device["headers"]).status_code in (401, 403, 404)
    with database.session_factory()() as db:
        assert db.get(Tenant, gone["id"]) is None
        assert db.query(Device).filter_by(tenant_id=gone["id"]).count() == 0
        assert db.query(Ticket).filter_by(account_tenant_id=gone["id"]).count() == 0
        assert db.query(Contact).filter_by(account_tenant_id=gone["id"]).count() == 0
        assert db.query(User).filter_by(tenant_id=gone["id"]).count() == 0
        # The other customer is untouched, and the audit trail about the deleted one is kept.
        assert db.query(Device).filter_by(tenant_id=kept["id"]).count() == 1
        assert db.get(Ticket, kept_ticket["id"]) is not None
        assert db.query(AuditLog).filter_by(tenant_id=gone["id"], action="tenant.deleted").count() == 1
        assert db.query(AuditLog).filter_by(tenant_id=gone["id"]).count() > 1
    assert client.get(f"/api/v1/devices/{kept_device['deviceId']}/commands/pending", headers=kept_device["headers"]).status_code == 200
    assert client.get("/api/console/audit/verify", headers=admin).json()["valid"] is True


def test_what_cannot_be_deleted_and_who_cannot_delete(client, admin):
    me = client.get("/api/console/auth/me", headers=admin).json()
    msp = next(t for t in client.get("/api/console/tenants", headers=admin).json() if t["kind"] == "msp")
    blocked = client.get(f"/api/console/tenants/{msp['id']}/deletion", headers=admin).json()["blockers"]
    assert any("MSP" in b for b in blocked) and me
    parent = make(client, admin, "Reseller")
    client.post("/api/console/tenants", headers=admin, json={"name": "Reseller child", "parentId": parent["id"]})
    assert any("sub-customer" in b for b in client.get(f"/api/console/tenants/{parent['id']}/deletion", headers=admin).json()["blockers"])
    assert client.request("DELETE", f"/api/console/tenants/{parent['id']}", headers=stepup(client, admin),
                          json={"confirmName": "Reseller"}).status_code == 409

    victim, other = make(client, admin, "Victim"), make(client, admin, "Other MSP customer")
    client.post("/api/console/users", headers=admin, json={"tenantId": other["id"], "email": "boss@other.example",
                                                           "password": ADMIN_PASSWORD, "role": "tenant_admin"})
    outsider = login(client, "boss@other.example")
    assert client.get(f"/api/console/tenants/{victim['id']}/deletion", headers=outsider).status_code in (403, 404)
    assert client.post(f"/api/console/tenants/{victim['id']}/archive", headers=outsider, json={}).status_code in (403, 404)


def test_export_contains_the_customers_data_and_no_secrets(client, admin):
    import io
    import json
    import zipfile

    leaving = make(client, admin, "Exported Ltd")
    other = make(client, admin, "Other Ltd")
    populate(client, admin, leaving, "EXP1")
    populate(client, admin, other, "OTH1")
    url = f"/api/console/tenants/{leaving['id']}/export"
    assert client.get(url, headers=admin).status_code == 403  # needs fresh sign-in
    response = client.get(url, headers=stepup(client, admin))
    assert response.status_code == 200, response.text
    archive = zipfile.ZipFile(io.BytesIO(response.content))
    names = set(archive.namelist())
    assert {"README.json", "tenants.json", "devices.json", "psa_tickets.json", "audit_log.json"} <= names
    devices = json.loads(archive.read("devices.json"))
    assert [d["serial_number"] for d in devices] == ["EXP1"]  # this customer only
    everything = b"".join(archive.read(n) for n in names if n != "README.json")  # the README names what was left out
    assert b"OTH1" not in everything
    assert b"api_key_hash" not in everything and b"password_hash" not in everything
    readme = json.loads(archive.read("README.json"))
    assert readme["customer"]["name"] == "Exported Ltd" and "api_key_hash" in readme["omittedSecretColumns"]["devices"]
    actions = [e["action"] for e in client.get("/api/console/audit", headers=admin).json()]
    assert "tenant.exported" in actions
