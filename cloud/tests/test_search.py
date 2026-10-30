"""Ctrl+K search: one box across devices, customers, tickets, staff, contacts, vulnerabilities and scripts, in scope."""

from conftest import enroll, login
from fenrir_cloud import db as database
from fenrir_cloud.models import Contact, Script, Ticket, Vulnerability


def _search(client, headers, q):
    reply = client.get("/api/console/search", headers=headers, params={"q": q})
    assert reply.status_code == 200, reply.text
    return reply.json()["results"]


def _add(*rows):
    with database.session_factory()() as db:
        for row in rows:
            db.add(row)
        db.commit()


def test_one_box_finds_every_kind(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="ACME-RECEPTION")
    _add(Ticket(number=4242, tenant_id=tenant["parentId"], account_tenant_id=tenant["id"], subject="Reception printer offline"),
         Contact(tenant_id=tenant["parentId"], account_tenant_id=tenant["id"], name="Rita Reception", email="rita@acme.example"),
         Vulnerability(tenant_id=tenant["id"], device_id=device["deviceId"], vuln_id="CVE-2024-3094", package="xz", known_exploited=True),
         Script(tenant_id=tenant["id"], name="Reset reception kiosk", body="Restart-Computer"))
    kinds = {r["kind"]: r for r in _search(client, admin, "reception")}
    assert set(kinds) >= {"device", "ticket", "contact", "script"}
    assert kinds["device"]["link"] == f"/devices/{device['deviceId']}" and "Acme Dental" in kinds["device"]["subtitle"]
    assert _search(client, admin, "#4242")[0]["title"] == "#4242 Reception printer offline"
    cve = _search(client, admin, "cve-2024-3094")[0]
    assert cve["kind"] == "vulnerability" and cve["subtitle"] == "1 device · known exploited"
    assert _search(client, admin, "acme den")[0] == {"kind": "company", "id": tenant["id"], "title": "Acme Dental",
                                                     "subtitle": "Customer", "link": f"/companies/{tenant['id']}"}
    assert any(r["kind"] == "user" for r in _search(client, admin, "admin@fenrir"))


def test_short_and_wildcard_queries_match_nothing_extra(client, admin, tenant):
    enroll(client, admin, tenant, hostname="ACME-PC")
    assert _search(client, admin, "a") == []
    assert _search(client, admin, "%%") == [] and _search(client, admin, "__") == []


def test_search_stays_inside_the_callers_customers(client, admin, tenant):
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    enroll(client, admin, other, hostname="OTHER-SECRET-PC", serial="SN-9")
    enroll(client, admin, tenant, hostname="ACME-SECRET-PC")
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "tech@acme.example",
                                                           "password": "acme-password-123", "role": "tenant_analyst"})
    viewer = login(client, "tech@acme.example", "acme-password-123")
    titles = [r["title"] for r in _search(client, viewer, "secret")]
    assert titles == ["ACME-SECRET-PC"]
    assert not any(r["kind"] == "user" for r in _search(client, viewer, "admin@fenrir"))  # staff need user management rights
