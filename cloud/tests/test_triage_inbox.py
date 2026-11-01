"""The triage inbox: one list across modules, duplicates collapsed, owner/SLA/snooze/dismiss, tickets and time."""

from datetime import timedelta

import pytest

from conftest import enroll, login
from fenrir_cloud import db as database
from fenrir_cloud.models import (Alert, DevicePatch, ElevationRequest, GrcEvidence, GrcRequirementState, Job, M365StandardRun,
                                 MonitorCondition, Ticket, TimeEntry, utcnow)
from test_documentation_vault import stepup


def _add(*rows):
    with database.session_factory()() as db:
        for row in rows:
            db.add(row)
        db.commit()


def _items(client, headers, **params):
    reply = client.get("/api/console/triage/items", headers=headers, params=params)
    assert reply.status_code == 200, reply.text
    return reply.json()


def _item(client, headers, kind, **params):
    return next((i for i in _items(client, headers, **params)["items"] if i["kind"] == kind), None)


@pytest.fixture()
def fleet(client, admin, tenant):
    return [enroll(client, admin, tenant, hostname=f"ACME-PC-{n}", serial=f"SN-{n}") for n in range(3)]


def _monitor_alerts(tenant, fleet, severity="high", age=timedelta(0)):
    monitor = MonitorCondition(tenant_id=tenant["id"], name="Disk space low", metric="disk.free_percent", operator="<", threshold=10)
    _add(monitor)
    _add(*[Alert(tenant_id=tenant["id"], device_id=d["deviceId"], rule_id=f"monitor:{monitor.id}", severity=severity,
                 title=f"Disk space low: ACME-PC-{n} — 4% free", created_at=utcnow() - age) for n, d in enumerate(fleet)])
    return monitor


def test_the_same_monitor_on_many_devices_is_one_item(client, admin, tenant, fleet):
    _monitor_alerts(tenant, fleet)
    _add(Alert(tenant_id=tenant["id"], device_id=fleet[0]["deviceId"], rule_id="rule-x", title="Mimikatz", severity="critical"))
    body = _items(client, admin)
    alerts = [i for i in body["items"] if i["kind"] == "alert"]
    assert len(alerts) == 2
    assert alerts[0]["title"] == "Mimikatz"  # the most severe first
    disk = alerts[1]
    assert disk["title"] == "Disk space low" and disk["count"] == 3 and disk["deviceCount"] == 3
    assert sorted(disk["hostnames"]) == ["ACME-PC-0", "ACME-PC-1", "ACME-PC-2"] and disk["customer"] == "Acme Dental"
    assert body["counts"]["byKind"]["alert"] == 2 and body["counts"]["unassigned"] >= 2
    detail = client.get("/api/console/triage/item", headers=admin, params={"key": disk["key"]}).json()
    assert [d["hostname"] for d in detail["devices"]] == ["ACME-PC-0", "ACME-PC-1", "ACME-PC-2"]


def test_owner_snooze_and_done_act_on_the_alerts_themselves(client, admin, tenant, fleet):
    _monitor_alerts(tenant, fleet)
    key = _item(client, admin, "alert")["key"]
    assert client.post("/api/console/triage/assign", headers=admin, json={"keys": [key], "owner": "nobody@example.com"}).status_code == 400
    assert client.post("/api/console/triage/assign", headers=admin, json={"keys": [key], "owner": "me"}).json()["owner"] == "admin@fenrir.local"
    assert _item(client, admin, "alert", view="mine")["owner"] == "admin@fenrir.local"
    alerts = client.get("/api/console/alerts", headers=admin).json()
    assert {a["assignee"] for a in alerts} == {"admin@fenrir.local"}  # the Alerts page agrees

    assert client.post("/api/console/triage/snooze", headers=admin, json={"keys": [key], "minutes": 60}).status_code == 200
    assert _item(client, admin, "alert") is None and _item(client, admin, "alert", snoozed="only")["snoozedUntil"]
    assert client.get("/api/console/alerts", headers=admin).json() == []
    client.post("/api/console/triage/snooze", headers=admin, json={"keys": [key], "minutes": 0})
    assert _item(client, admin, "alert") is not None

    assert client.post("/api/console/triage/dismiss", headers=admin, json={"keys": [key]}).status_code == 200
    assert _item(client, admin, "alert") is None
    assert {a["status"] for a in client.get("/api/console/alerts", headers=admin, params={"snoozed": "all"}).json()} == {"resolved"}


def test_a_dismissed_failure_comes_back_when_another_device_fails(client, admin, tenant, fleet):
    def failed(device):
        return DevicePatch(device_id=device["deviceId"], tenant_id=tenant["id"], patch_key="KB5034441", title="2024-01 Security Update",
                           classification="security", status="failed", error="0x80070643")
    _add(failed(fleet[0]), failed(fleet[1]))
    item = _item(client, admin, "patch")
    assert item["count"] == 2 and item["severity"] == "high" and "0x80070643" in item["summary"]
    client.post("/api/console/triage/dismiss", headers=admin, json={"keys": [item["key"]]})
    assert _item(client, admin, "patch") is None
    done = _item(client, admin, "patch", snoozed="only")
    assert done["dismissed"] is True
    client.post("/api/console/triage/snooze", headers=admin, json={"keys": [done["key"]], "minutes": 0})  # changed my mind
    assert _item(client, admin, "patch")["count"] == 2
    client.post("/api/console/triage/dismiss", headers=admin, json={"keys": [item["key"]]})
    _add(failed(fleet[2]))
    assert _item(client, admin, "patch")["count"] == 3


def test_one_click_ticket_and_billed_time(client, admin, tenant, fleet):
    _monitor_alerts(tenant, fleet, severity="critical")
    key = _item(client, admin, "alert")["key"]
    first = client.post("/api/console/triage/ticket", headers=admin, json={"key": key}).json()["tickets"][0]
    assert first["created"] is True
    again = client.post("/api/console/triage/ticket", headers=admin, json={"key": key}).json()["tickets"][0]
    assert again == {**first, "created": False}  # the same open ticket, not a second one
    with database.session_factory()() as db:
        ticket = db.get(Ticket, first["id"])
        assert ticket.priority == "P1" and "ACME-PC-2" in ticket.description and ticket.account_tenant_id == tenant["id"]
    logged = client.post("/api/console/triage/time", headers=admin, json={"key": key, "minutes": 30, "notes": "Cleared temp files"})
    assert logged.status_code == 200, logged.text
    assert logged.json()["ticket"]["id"] == first["id"] and logged.json()["hours"] == 0.5
    with database.session_factory()() as db:
        assert db.get(TimeEntry, logged.json()["entryId"]).ticket_id == first["id"]
    assert _item(client, admin, "alert")["ticketId"] == first["id"]


def test_decisions_and_tickets_are_not_dismissed_from_the_inbox(client, admin, tenant, fleet):
    _add(ElevationRequest(tenant_id=tenant["id"], device_id=fleet[0]["deviceId"], user="ACME\\jo", user_sid="S-1-5-21-1",
                          reason="Install the printer driver"))
    item = _item(client, admin, "elevation")
    assert item["title"] == "Admin rights requested by ACME\\jo" and item["hostnames"] == ["ACME-PC-0"] and not item["canDismiss"]
    refused = client.post("/api/console/triage/dismiss", headers=admin, json={"keys": [item["key"]]})
    assert refused.status_code == 400 and "own page" in refused.json()["detail"]


def test_unowned_tickets_show_until_someone_else_has_them(client, admin, tenant):
    created = client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "Printer jammed"})
    assert created.status_code == 200, created.text
    item = _item(client, admin, "ticket")
    assert item and item["title"].endswith("Printer jammed") and item["owner"] is None
    client.post("/api/console/users", headers=admin, json={"email": "tech@fenrir.local", "name": "Tech",
                                                           "password": "a-long-enough-password", "role": "technician"})
    assert client.post("/api/console/triage/assign", headers=admin, json={"keys": [item["key"]], "owner": "tech@fenrir.local"}).status_code == 200
    with database.session_factory()() as db:
        assert db.get(Ticket, created.json()["id"]).assignee == "tech@fenrir.local"
    assert _item(client, admin, "ticket") is None  # on time and owned: the service board has it
    tech = login(client, "tech@fenrir.local", "a-long-enough-password")
    assert _item(client, tech, "ticket", view="mine")["owner"] == "tech@fenrir.local"


def test_sla_is_per_severity_and_configurable(client, admin, tenant, fleet):
    _monitor_alerts(tenant, fleet, severity="critical", age=timedelta(hours=2))
    item = _item(client, admin, "alert")
    assert item["breached"] is True and _items(client, admin)["counts"]["breached"] >= 1
    assert client.put("/api/console/triage/settings", headers=admin, json={"slaHours": {"critical": 0}}).status_code == 400
    saved = client.put("/api/console/triage/settings", headers=admin, json={"slaHours": {"critical": 3}})
    assert saved.status_code == 200 and saved.json()["slaHours"]["critical"] == 3
    assert _item(client, admin, "alert")["breached"] is False
    # One setting for the whole MSP: a customer's own administrator cannot change it.
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "ops@acme.example",
                                                           "password": "acme-password-123", "role": "tenant_admin"})
    ops = login(client, "ops@acme.example", "acme-password-123")
    assert client.put("/api/console/triage/settings", headers=ops, json={"slaHours": {"critical": 9}}).status_code == 403


def test_compliance_and_microsoft_365_work_appears_with_its_own_owner(client, admin, tenant):
    past, soon = utcnow() - timedelta(days=2), utcnow() + timedelta(days=5)
    _add(GrcRequirementState(tenant_id=tenant["id"], framework_key="cyber-essentials", requirement_id="CE-1.1", due_date=past),
         GrcRequirementState(tenant_id=tenant["id"], framework_key="cyber-essentials", requirement_id="CE-2.3", due_date=past),
         GrcEvidence(tenant_id=tenant["id"], title="Firewall review", valid_until=soon),
         M365StandardRun(tenant_id=tenant["id"], connection_id="m365_x", standard="disable-legacy-auth", action="evaluate",
                         status="drifted", details={"message": "Legacy authentication is allowed"}))
    body = _items(client, admin)
    grc = next(i for i in body["items"] if i["kind"] == "grc")
    assert grc["count"] == 2 and grc["breached"] is True and grc["link"].endswith("/cyber-essentials")
    assert next(i for i in body["items"] if i["kind"] == "evidence")["title"] == "1 evidence items expire within 14 days"
    m365 = next(i for i in body["items"] if i["kind"] == "m365")
    assert m365["summary"] == "Legacy authentication is allowed"
    evidence = next(i for i in body["items"] if i["kind"] == "evidence")
    together = client.post("/api/console/triage/assign", headers=admin, json={"keys": [m365["key"], grc["key"], evidence["key"]], "owner": "me"})
    assert together.json()["updated"] == 3
    assert {i["kind"] for i in _items(client, admin, view="mine")["items"]} >= {"m365", "grc", "evidence"}


def test_failed_jobs_name_the_devices_that_failed(client, admin, tenant, fleet):
    from fenrir_cloud.models import Command
    commands = [Command(tenant_id=tenant["id"], device_id=d["deviceId"], type="script.run", status=s, issued_by="admin@fenrir.local")
                for d, s in zip(fleet, ("failed", "completed", "failed"))]
    _add(*commands)
    _add(Job(tenant_id=tenant["id"], name="Clear temp", status="partial", finished_at=utcnow(),
             command_ids={c.device_id: c.id for c in commands}))
    item = _item(client, admin, "job")
    assert item["title"] == "Job failed: Clear temp" and sorted(item["hostnames"]) == ["ACME-PC-0", "ACME-PC-2"]


def test_another_customers_items_are_out_of_scope(client, admin, tenant, fleet):
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    _monitor_alerts(tenant, fleet)
    _add(Alert(tenant_id=other["id"], rule_id="rule-y", title="Other customer's alert", severity="high"))
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "ops@acme.example",
                                                           "password": "acme-password-123", "role": "tenant_admin"})
    ops = login(client, "ops@acme.example", "acme-password-123")
    titles = [i["title"] for i in _items(client, ops)["items"]]
    assert "Disk space low" in titles and "Other customer's alert" not in titles
    hidden = f"alert:{other['id']}:rule-y"
    assert client.post("/api/console/triage/dismiss", headers=ops, json={"keys": [hidden]}).status_code == 404
    assert client.get("/api/console/triage/item", headers=ops, params={"key": hidden}).status_code == 404
