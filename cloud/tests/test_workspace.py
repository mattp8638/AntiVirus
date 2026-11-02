"""FLOW-09: one customer's workspace links open tickets, devices needing attention, alerts, urgent vulnerabilities and
recent actions, and never shows another customer's records."""
from datetime import timedelta

from conftest import enroll

from fenrir_cloud import services
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import Alert, Device, Vulnerability, utcnow


def test_workspace_brings_one_customers_work_together(client, admin, tenant):
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd"}).json()
    pc = enroll(client, admin, tenant, hostname="ACME-PC", serial="W1")
    old = enroll(client, admin, tenant, hostname="ACME-OLD", serial="W2")
    theirs = enroll(client, admin, other, hostname="OTHER-PC", serial="W3")
    with session_factory()() as db:
        db.get(Device, old["deviceId"]).last_seen_at = utcnow() - timedelta(days=12)
        db.add(Alert(tenant_id=tenant["id"], device_id=pc["deviceId"], rule_id="r", title="Suspicious PowerShell", severity="high", status="new"))
        db.add(Alert(tenant_id=other["id"], device_id=theirs["deviceId"], rule_id="r", title="Not ours", severity="high", status="new"))
        db.add(Vulnerability(tenant_id=tenant["id"], device_id=pc["deviceId"], vuln_id="CVE-2024-9999", package="chrome",
                             severity="high", known_exploited=True, status="open"))
        services.open_ticket(db, tenant["id"], "Printer offline", "", device_id=pc["deviceId"])
        services.open_ticket(db, other["id"], "Not our ticket", "")
        db.commit()
    data = client.get(f"/api/console/workspace/{tenant['id']}", headers=admin).json()
    assert data["tickets"]["open"] == 1 and data["tickets"]["items"][0]["subject"] == "Printer offline"
    assert data["tickets"]["items"][0]["device"] == "ACME-PC"
    assert [a["title"] for a in data["alerts"]["items"]] == ["Suspicious PowerShell"]
    assert data["devices"]["total"] == 2 and data["devices"]["attention"][0]["hostname"] == "ACME-OLD"
    assert data["vulnerabilities"]["urgent"][0]["vulnId"] == "CVE-2024-9999" and data["vulnerabilities"]["byPriority"]["P1"] == 1
    assert data["onboarding"]["total"] > 0 and isinstance(data["recent"], list)
    assert "Not our ticket" not in str(data) and "OTHER-PC" not in str(data)
