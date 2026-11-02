from datetime import datetime, timedelta

from conftest import enroll, login

from fenrir_cloud import db as database, mailer, psa
from fenrir_cloud.models import Ticket, utcnow


def test_tickets_land_on_boards_with_matrix_priority_and_sla(client, admin, tenant):
    meta = client.get("/api/console/psa/meta", headers=admin).json()
    boards = {b["name"]: b for b in meta["boards"]}
    assert {"Service Desk", "Projects", "Security Operations", "Monitoring Alerts"} <= set(boards)
    statuses = [s["name"] for s in boards["Service Desk"]["statuses"]]
    assert statuses[0] == "New" and "Waiting Customer" in statuses
    ticket = client.post("/api/console/tickets", headers=admin, json={
        "accountTenantId": tenant["id"], "subject": "Whole office offline", "impact": "High", "urgency": "High",
        "type": "Incident", "subtype": "Network", "item": "Internet"}).json()
    assert ticket["priority"] == "P1" and ticket["status"] == "New" and ticket["boardId"] == boards["Service Desk"]["id"]
    assert ticket["respondDueAt"] and ticket["slaDueAt"]
    bad = client.patch(f"/api/console/tickets/{ticket['id']}", headers=admin, json={"status": "Bogus"})
    assert bad.status_code == 400
    moved = client.patch(f"/api/console/tickets/{ticket['id']}", headers=admin, json={"status": "In Progress", "impact": "Low"}).json()
    assert moved["status"] == "In Progress" and moved["priority"] == "P3" and moved["respondedAt"]
    detail = client.get(f"/api/console/tickets/{ticket['id']}", headers=admin).json()
    assert any("Status changed from New to In Progress" in c["text"] for c in detail["comments"])
    active = client.get("/api/console/tickets", headers=admin, params={"status": "active"}).json()
    assert [t["number"] for t in active] == [ticket["number"]]
    client.patch(f"/api/console/tickets/{ticket['id']}", headers=admin, json={"status": "Closed"})
    assert client.get("/api/console/tickets", headers=admin, params={"status": "active"}).json() == []


def test_business_hours_sla_skips_nights_and_weekends():
    bh = {"days": [0, 1, 2, 3, 4], "start": 9, "end": 17, "tz": "UTC"}
    friday_4pm = datetime(2026, 10, 23, 16, 0)
    # 1h on Friday, then the remaining 3h on Monday from 09:00.
    assert psa.add_business_hours(friday_4pm, 4, bh) == datetime(2026, 10, 26, 12, 0)
    saturday = datetime(2026, 10, 24, 10, 0)
    assert psa.add_business_hours(saturday, 2, bh) == datetime(2026, 10, 26, 11, 0)
    assert psa.add_business_hours(friday_4pm, 4, {**bh, "allHours": True}) == datetime(2026, 10, 23, 20, 0)


def test_time_entries_agreement_coverage_and_invoice(client, admin, tenant):
    for i in range(2):
        enroll(client, admin, tenant, hostname=f"WS-{i}", serial=f"S{i}")
    enroll(client, admin, tenant, hostname="SRV-01", os_version="Windows Server 2022", serial="SV")
    agreement = client.post("/api/console/billing/contracts", headers=admin, json={
        "accountTenantId": tenant["id"], "name": "Acme managed", "agreementType": "Managed Services", "pricePerDevice": 10,
        "hourlyRate": 90, "includedHours": 1, "coveredWorkTypes": ["Remote Support"], "coversAfterHours": False,
        "additions": [{"product": "Server backup", "unitPrice": 25, "autoCount": "devices:server"}]}).json()
    ticket = client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "New laptop"}).json()
    assert ticket["agreementId"] == agreement["id"]
    entries = [
        {"ticketId": ticket["id"], "hours": 1.6, "workType": "Remote Support", "notes": "Set up profile"},
        {"ticketId": ticket["id"], "hours": 2, "workType": "Onsite Support", "notes": "Delivered and installed"},
        {"ticketId": ticket["id"], "hours": 1, "workType": "After Hours"},
        {"ticketId": ticket["id"], "hours": 3, "workType": "Remote Support", "billable": "No Charge"},
    ]
    for entry in entries:
        response = client.post("/api/console/psa/time", headers=admin, json=entry)
        assert response.status_code == 200, response.text
    first = client.get("/api/console/psa/time", headers=admin, params={"ticket_id": ticket["id"]}).json()
    assert {e["hoursBilled"] for e in first} >= {1.75, 2.0}
    assert sum(1 for e in first if e["covered"]) == 2  # both Remote Support entries
    invoice = client.post("/api/console/billing/invoices/generate", headers=admin, json={}).json()["created"]
    lines = {l["description"]: l for l in next(i for i in invoice if i["accountTenantId"] == tenant["id"])["lines"]}
    assert lines["Protected endpoints (complete)"]["quantity"] == 3
    assert lines["Server backup"]["quantity"] == 1
    assert lines["Support time beyond allowance (hours)"]["quantity"] == 0.75  # 1.75 covered - 1 included
    assert lines["Time & materials: Onsite Support (hours)"]["quantity"] == 2
    assert lines["Time & materials: After Hours (hours)"]["unitPrice"] == 135
    billed = client.get("/api/console/psa/time", headers=admin, params={"ticket_id": ticket["id"]}).json()
    assert {e["status"] for e in billed if e["billable"] == "Billable"} == {"Billed"}
    assert client.patch(f"/api/console/psa/time/{billed[0]['id']}", headers=admin, json={"hours": 9}).status_code in {200, 409}


def test_timesheet_submit_and_approve(client, admin, tenant):
    ticket = client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "Printer"}).json()
    monday = (utcnow() - timedelta(days=utcnow().weekday())).replace(hour=10, minute=0, second=0, microsecond=0)
    client.post("/api/console/psa/time", headers=admin, json={"ticketId": ticket["id"], "startedAt": monday.isoformat(),
                                                             "endedAt": (monday + timedelta(minutes=45)).isoformat()})
    week = monday.date().isoformat()
    assert client.post("/api/console/psa/timesheets/submit", headers=admin, json={"weekStart": week}).json()["submitted"] == 1
    sheets = client.get("/api/console/psa/timesheets", headers=admin, params={"weekStart": week}).json()
    assert sheets[0]["total"] == 0.75 and sheets[0]["days"][0] == 0.75 and sheets[0]["statuses"] == {"Submitted": 1}
    approved = client.post("/api/console/psa/timesheets/approve", headers=admin, json={"weekStart": week, "member": "admin@fenrir.local"})
    assert approved.json() == {"approved": 1}


def test_workflow_rules_on_create_and_idle(client, admin, tenant):
    boards = client.get("/api/console/psa/boards", headers=admin).json()
    desk = next(b for b in boards if b["name"] == "Service Desk")
    client.post("/api/console/psa/workflows", headers=admin, json={
        "name": "Security tickets to Sam", "boardId": desk["id"], "trigger": "ticket.created",
        "conditions": [{"field": "subject", "op": "contains", "value": "phish"}],
        "actions": [{"type": "assign", "member": "sam@palmertech.test"}, {"type": "set", "field": "priority", "value": "P2"},
                    {"type": "note", "text": "Auto-routed to security", "kind": "internal"}]})
    client.post("/api/console/psa/workflows", headers=admin, json={
        "name": "Close waiting tickets", "trigger": "ticket.idle", "idleHours": 72,
        "conditions": [{"field": "status", "op": "equals", "value": "Waiting Customer"}],
        "actions": [{"type": "set", "field": "status", "value": "Closed"},
                    {"type": "note", "text": "Closed after 3 days without a reply.", "kind": "discussion"}]})
    phish = client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "Possible phishing email"}).json()
    assert phish["assignee"] == "sam@palmertech.test" and phish["priority"] == "P2"
    other = client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "Mouse broken"}).json()
    assert other["assignee"] == ""
    client.patch(f"/api/console/tickets/{other['id']}", headers=admin, json={"status": "Waiting Customer"})
    session = database.session_factory()()
    try:
        assert psa.timed_workflows(session) == 0
        row = session.get(Ticket, other["id"])
        row.status_changed_at = utcnow() - timedelta(hours=80)
        session.commit()
        assert psa.timed_workflows(session) == 1
        assert psa.timed_workflows(session) == 0
        session.commit()
    finally:
        session.close()
    closed = client.get(f"/api/console/tickets/{other['id']}", headers=admin).json()
    assert closed["status"] == "Closed" and closed["closed"]


def test_email_to_ticket_and_threaded_reply(client, admin, tenant):
    client.post("/api/console/crm/contacts", headers=admin, json={"accountTenantId": tenant["id"], "name": "Jo Bloggs",
                                                                   "email": "jo@acmedental.test"})
    rotated = client.post("/api/console/psa/inbound-token", headers=admin).json()
    assert client.post(rotated["url"].replace(rotated["token"], "wrong"), json={}).status_code == 401
    mailer.OUTBOX.clear()
    created = client.post(rotated["url"], json={"from": "Jo@AcmeDental.test", "fromName": "Jo Bloggs", "to": "help@palmertech.test",
                                                 "subject": "Scanner not working", "text": "The scanner says offline.",
                                                 "messageId": "<abc@mail.test>"}).json()
    assert created["action"] == "created"
    ticket = client.get(f"/api/console/tickets/{created['ticketId']}", headers=admin).json()
    assert ticket["accountTenantId"] == tenant["id"] and ticket["source"] == "email" and ticket["contactEmail"] == "jo@acmedental.test"
    ack = mailer.OUTBOX[-1]
    assert ack["to"] == "jo@acmedental.test" and f"[Ticket #{ticket['number']}]" in ack["subject"]
    # Staff reply emails the contact.
    client.patch(f"/api/console/tickets/{ticket['id']}", headers=admin, json={"comment": "Can you restart it?", "emailContact": True,
                                                                              "status": "Waiting Customer"})
    assert mailer.OUTBOX[-1]["body"].startswith("Update on ticket")
    reply = client.post(rotated["url"], json={"from": "jo@acmedental.test", "subject": f"RE: [Ticket #{ticket['number']}] Scanner not working",
                                               "text": "Restarted, works now.\n\nOn Tue, Support wrote:\n> Can you restart it?"}).json()
    assert reply == {"action": "updated", "ticketId": ticket["id"], "number": ticket["number"]}
    updated = client.get(f"/api/console/tickets/{ticket['id']}", headers=admin).json()
    assert updated["status"] == "Customer Responded"
    assert updated["comments"][-2]["text"] == "Restarted, works now." or any(c["text"] == "Restarted, works now." for c in updated["comments"])
    auto = client.post(rotated["url"], json={"from": "jo@acmedental.test", "subject": "Out of office", "text": "Away",
                                              "autoSubmitted": "auto-replied"}).json()
    assert auto["action"] == "ignored"
    unknown = client.post(rotated["url"], json={"from": "someone@unknown.test", "subject": "Hello", "text": "Hi"}).json()
    stranger = client.get(f"/api/console/tickets/{unknown['ticketId']}", headers=admin).json()
    assert stranger["accountTenantId"] != tenant["id"]


def test_raw_rfc822_inbound(client, admin, tenant):
    rotated = client.post("/api/console/psa/inbound-token", headers=admin).json()
    raw = (b"From: Pat <pat@acme.test>\r\nTo: help@msp.test\r\nSubject: VPN down\r\nMessage-ID: <x1@acme.test>\r\n"
           b"Content-Type: text/plain\r\n\r\nCannot connect to the VPN since this morning.\r\n")
    result = client.post(rotated["url"], content=raw, headers={"Content-Type": "message/rfc822"}).json()
    assert result["action"] == "created"
    ticket = client.get(f"/api/console/tickets/{result['ticketId']}", headers=admin).json()
    assert ticket["subject"] == "VPN down" and "Cannot connect" in ticket["description"]


def test_client_portal_isolation(client, admin, tenant):
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Globex", "template": "balanced"}).json()
    client.post("/api/console/users", headers=admin, json={"email": "jo@acme.test", "password": "a-long-password-3", "name": "Jo",
                                                           "role": "client", "tenantId": tenant["id"]})
    portal = login(client, "jo@acme.test", "a-long-password-3")
    assert client.get("/api/console/tickets", headers=portal).status_code == 403
    assert client.get("/api/console/devices", headers=portal).status_code == 403
    me = client.get("/api/console/auth/me", headers=portal).json()
    assert me["permissions"] == ["portal"]
    mine = client.post("/api/portal/tickets", headers=portal, json={"subject": "Email not syncing", "urgency": "High", "impact": "Medium"}).json()
    assert mine["priority"] == "P2"
    client.post("/api/console/tickets", headers=admin, json={"accountTenantId": other["id"], "subject": "Globex secret"})
    client.patch(f"/api/console/tickets/{mine['id']}", headers=admin, json={"comment": "Customer is VIP", "internal": True})
    client.patch(f"/api/console/tickets/{mine['id']}", headers=admin, json={"comment": "Looking now", "kind": "discussion"})
    listed = client.get("/api/portal/tickets", headers=portal).json()
    assert [t["subject"] for t in listed] == ["Email not syncing"]
    notes = [n["text"] for n in listed[0]["notes"]]
    assert "Looking now" in notes and "Customer is VIP" not in notes
    replied = client.post(f"/api/portal/tickets/{mine['id']}/reply", headers=portal, json={"text": "Thanks!", "close": True}).json()
    assert replied["status"] == "Closed"
    secret = client.get("/api/console/tickets", headers=admin, params={"q": "Globex"}).json()[0]
    assert client.get(f"/api/portal/tickets/{secret['id']}", headers=portal).status_code == 404
    client.post("/api/console/psa/kb", headers=admin, json={"title": "Reset your password", "body": "Go to...", "public": True})
    client.post("/api/console/psa/kb", headers=admin, json={"title": "Internal runbook", "body": "Admin creds...", "public": False})
    assert [a["title"] for a in client.get("/api/portal/kb", headers=portal).json()] == ["Reset your password"]


def test_dispatch_schedule_and_conflicts(client, admin, tenant):
    ticket = client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "Install printer"}).json()
    start = datetime(2026, 10, 26, 9, 0)
    first = client.post("/api/console/psa/schedule", headers=admin, json={
        "ticketId": ticket["id"], "member": "eng@palmertech.test", "startAt": start.isoformat(),
        "endAt": (start + timedelta(hours=2)).isoformat(), "kind": "Onsite"}).json()
    assert first["conflict"] is False
    clash = client.post("/api/console/psa/schedule", headers=admin, json={
        "member": "eng@palmertech.test", "title": "Team meeting", "startAt": (start + timedelta(hours=1)).isoformat(),
        "endAt": (start + timedelta(hours=3)).isoformat(), "kind": "Meeting"}).json()
    assert clash["conflict"] is True
    detail = client.get(f"/api/console/tickets/{ticket['id']}", headers=admin).json()
    assert detail["status"] == "Scheduled" and detail["assignee"] == "eng@palmertech.test" and detail["schedule"]
    day = client.get("/api/console/psa/schedule", headers=admin, params={"start": "2026-10-26T00:00:00", "end": "2026-10-27T00:00:00"}).json()
    assert [e["kind"] for e in day] == ["Onsite", "Meeting"] and day[0]["ticketNumber"] == ticket["number"]
    moved = client.patch(f"/api/console/psa/schedule/{clash['id']}", headers=admin, json={"startAt": "2026-10-26T13:00:00",
                                                                                          "endAt": "2026-10-26T14:00:00"})
    assert moved.status_code == 200


def test_configurations_sync_quotes_and_merge(client, admin, tenant, device):
    # Enrollment now syncs a customer-scoped CMDB asset automatically.
    automatically_created = client.get("/api/console/psa/configurations", headers=admin,
                                       params={"accountTenantId": tenant["id"]}).json()
    assert len(automatically_created) == 1
    synced = client.post("/api/console/psa/configurations/sync", headers=admin, json={}).json()
    assert synced == {"created": 0, "updated": 1}
    assert client.post("/api/console/psa/configurations/sync", headers=admin, json={}).json() == {"created": 0, "updated": 1}
    configs = client.get("/api/console/psa/configurations", headers=admin, params={"accountTenantId": tenant["id"]}).json()
    assert configs[0]["deviceId"] == device["deviceId"] and configs[0]["type"] == "Workstation"
    product = client.post("/api/console/psa/products", headers=admin, json={"sku": "M365-BP", "description": "Microsoft 365 Business Premium",
                                                                           "price": 18.1, "cost": 16.4, "recurring": True}).json()
    quote = client.post("/api/console/psa/quotes", headers=admin, json={
        "accountTenantId": tenant["id"], "title": "Office refresh",
        "lines": [{"productId": product["id"], "quantity": 10}, {"description": "Migration labour", "quantity": 6, "unitPrice": 85}]}).json()
    assert quote["monthlyTotal"] == 181.0 and quote["oneOffTotal"] == 510.0
    page = client.get(f"/api/console/psa/quotes/{quote['id']}/print", headers=admin)
    assert page.status_code == 200 and "Microsoft 365 Business Premium" in page.text
    a = client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "Wi-Fi slow"}).json()
    b = client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "Wi-Fi slow (dupe)"}).json()
    client.post("/api/console/psa/time", headers=admin, json={"ticketId": b["id"], "hours": 0.5})
    merged = client.post(f"/api/console/tickets/{b['id']}/merge", headers=admin, json={"intoTicketId": a["id"]}).json()
    assert merged["timeMinutes"] == 30
    child = client.get(f"/api/console/tickets/{b['id']}", headers=admin).json()
    assert child["status"] == "Closed" and child["parentId"] == a["id"]
    assert client.get(f"/api/console/tickets/{a['id']}", headers=admin).json()["children"][0]["number"] == b["number"]
    company = client.get(f"/api/console/psa/companies/{tenant['id']}", headers=admin).json()
    assert len(company["configurations"]) == 1 and len(company["tickets"]) == 2
    tasks = client.post(f"/api/console/tickets/{a['id']}/tasks", headers=admin, json={"add": "Check AP firmware"}).json()
    tasks = client.post(f"/api/console/tickets/{a['id']}/tasks", headers=admin, json={"toggle": 0}).json()
    assert tasks[0]["done"] is True


def test_round_robin_assignment(client, admin, tenant):
    desk = next(b for b in client.get("/api/console/psa/boards", headers=admin).json() if b["name"] == "Service Desk")
    client.patch(f"/api/console/psa/boards/{desk['id']}", headers=admin,
                 json={"members": ["a@msp.test", "b@msp.test"], "autoAssign": "round_robin"})
    assignees = [client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": f"T{i}"}).json()["assignee"]
                 for i in range(3)]
    assert assignees == ["a@msp.test", "b@msp.test", "a@msp.test"]
    bad = client.patch(f"/api/console/psa/boards/{desk['id']}", headers=admin, json={"statuses": [{"name": "Open"}]})
    assert bad.status_code == 400
