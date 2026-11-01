from datetime import timedelta

from fenrir_cloud import db as database
from fenrir_cloud.models import Alert, AuditLog, utcnow
from sqlalchemy import select


def _alerts(tenant_id, device_id, count=3):
    with database.session_factory()() as db:
        rows = [Alert(tenant_id=tenant_id, device_id=device_id, rule_id="test-rule", title=f"Suspicious thing {i}", severity="high",
                      mitre=[], event_ids=[], details={}) for i in range(count)]
        db.add_all(rows)
        db.commit()
        return [r.id for r in rows]


def test_alerts_can_be_assigned_acknowledged_and_snoozed(client, admin, tenant, device):
    first, second, third = _alerts(tenant["id"], device["deviceId"])
    base = "/api/console/alerts"

    taken = client.patch(f"{base}/{first}", headers=admin, json={"acknowledge": True}).json()
    assert taken["assignee"] == "admin@fenrir.local" and taken["status"] == "triaged" and taken["acknowledgedBy"] == "admin@fenrir.local"
    assert client.patch(f"{base}/{second}", headers=admin, json={"assignee": "nobody@elsewhere.test"}).status_code == 400
    assert client.patch(f"{base}/{third}", headers=admin, json={"snoozeMinutes": 2}).status_code == 400  # too short

    mine = client.get(base, headers=admin, params={"assignee": "me"}).json()
    assert [a["id"] for a in mine] == [first]
    unassigned = {a["id"] for a in client.get(base, headers=admin, params={"assignee": "unassigned"}).json()}
    assert unassigned == {second, third}

    client.patch(f"{base}/{third}", headers=admin, json={"snoozeMinutes": 60})
    visible = {a["id"] for a in client.get(base, headers=admin).json()}
    assert third not in visible and {first, second} <= visible  # snoozed alerts leave the queue
    assert [a["id"] for a in client.get(base, headers=admin, params={"snoozed": "only"}).json()] == [third]
    with database.session_factory()() as db:  # the snooze runs out
        db.get(Alert, third).snoozed_until = utcnow() - timedelta(minutes=1)
        db.commit()
    assert third in {a["id"] for a in client.get(base, headers=admin).json()}

    result = client.post(f"{base}/bulk", headers=admin, json={"ids": [second, third], "assignee": "me", "status": "resolved"}).json()
    assert result["updated"] == 2
    rows = {a["id"]: a for a in client.get(base, headers=admin, params={"snoozed": "all"}).json()}
    assert rows[second]["status"] == rows[third]["status"] == "resolved" and rows[second]["assignee"] == "admin@fenrir.local"
    with database.session_factory()() as db:
        actions = db.execute(select(AuditLog).where(AuditLog.action == "alert.updated")).scalars().all()
        assert len(actions) == 4 and any((a.details or {}).get("snoozedMinutes") == 60 for a in actions)


def test_customer_users_cannot_triage_other_customers_alerts(client, admin, tenant, device):
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    client.post("/api/console/users", headers=admin, json={"tenantId": other["id"], "email": "tech@other.test",
                                                            "password": "long-password-123", "role": "tenant_admin"})
    from conftest import login

    outsider = login(client, "tech@other.test", "long-password-123")
    [alert] = _alerts(tenant["id"], device["deviceId"], 1)
    assert client.post("/api/console/alerts/bulk", headers=outsider, json={"ids": [alert], "status": "resolved"}).status_code in (403, 404)
    assert client.patch(f"/api/console/alerts/{alert}", headers=outsider, json={"snoozeMinutes": 60}).status_code in (403, 404)


def test_my_work_lists_the_technicians_queue(client, admin, tenant, device):
    tickets = "/api/console/tickets"
    mine = client.post(tickets, headers=admin, json={"accountTenantId": tenant["id"], "subject": "Printer jammed", "assignee": "admin@fenrir.local"}).json()
    other = client.post(tickets, headers=admin, json={"accountTenantId": tenant["id"], "subject": "New starter"}).json()
    with database.session_factory()() as db:
        from fenrir_cloud.models import Ticket

        db.get(Ticket, other["id"]).sla_due_at = utcnow() - timedelta(hours=1)  # past SLA
        db.commit()
    first, second = _alerts(tenant["id"], device["deviceId"], 2)
    client.patch(f"/api/console/alerts/{first}", headers=admin, json={"acknowledge": True})

    work = client.get("/api/console/my-work", headers=admin).json()
    assert [t["id"] for t in work["tickets"]["mine"]] == [mine["id"]] and work["tickets"]["mineCount"] == 1
    assert other["id"] in [t["id"] for t in work["tickets"]["breached"]] and work["tickets"]["breached"][0]["breached"]
    assert [a["id"] for a in work["alerts"]["mine"]] == [first] and work["alerts"]["urgentUnowned"] == 1  # the other high alert
    assert work["jobs"]["failedCount"] == 0 and work["decisions"] == {"approvals": 0, "adminRequests": 0}
