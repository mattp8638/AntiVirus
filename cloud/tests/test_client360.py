"""Client 360: one health score per customer from every module, its trend, and the monthly and quarterly reports."""

from datetime import timedelta

from conftest import enroll, login
from fenrir_cloud import client360, db as database
from fenrir_cloud.models import (Alert, BackupPlan, BackupRun, ClientHealthSnapshot, ClientReport, Contract, Device, DevicePatch,
                                 Invoice, M365Connection, Tenant, Ticket, Vulnerability, utcnow)


def _add(*rows):
    with database.session_factory()() as db:
        for row in rows:
            db.add(row)
        db.commit()


def _health(client, headers, tenant):
    reply = client.get(f"/api/console/clients/{tenant['id']}/health", headers=headers)
    assert reply.status_code == 200, reply.text
    body = reply.json()
    return body, {p["key"]: p for p in body["parts"]}


def test_parts_without_data_are_not_set_up_rather_than_perfect(client, admin, tenant):
    body, parts = _health(client, admin, tenant)
    assert parts["backup"]["score"] is None and parts["backup"]["value"] == "No backup monitoring set up"
    assert parts["identity"]["value"] == "Microsoft 365 not connected" and parts["devices"]["status"] == "none"
    assert body["measured"] < body["of"]


def test_one_score_from_devices_protection_backup_identity_vulnerabilities_service_and_account(client, admin, tenant):
    pcs = [enroll(client, admin, tenant, hostname=f"ACME-PC-{n}", serial=f"SN-{n}") for n in range(4)]
    now = utcnow()
    with database.session_factory()() as db:
        old = db.get(Device, pcs[3]["deviceId"])
        old.last_seen_at = now - timedelta(days=10)  # one laptop not seen for 10 days
        db.get(Device, pcs[2]["deviceId"]).health_state = "degraded"
        db.commit()
    plan_ok = BackupPlan(tenant_id=tenant["id"], name="File server", provider="Veeam", rpo_hours=24)
    plan_late = BackupPlan(tenant_id=tenant["id"], name="Accounts PC", provider="Veeam", rpo_hours=24)
    _add(plan_ok, plan_late)
    _add(BackupRun(plan_id=plan_ok.id, tenant_id=tenant["id"], external_id="r1", status="success", completed_at=now - timedelta(hours=2),
                   recorded_by="ingest"),
         BackupRun(plan_id=plan_late.id, tenant_id=tenant["id"], external_id="r2", status="success", completed_at=now - timedelta(days=3),
                   recorded_by="ingest"),
         Alert(tenant_id=tenant["id"], device_id=pcs[0]["deviceId"], rule_id="r", title="Ransomware behaviour", severity="critical"),
         Vulnerability(tenant_id=tenant["id"], device_id=pcs[1]["deviceId"], vuln_id="CVE-2023-4863", package="libwebp",
                       severity="high", known_exploited=True),
         M365Connection(tenant_id=tenant["id"], name="Acme", directory_id="d" * 36, client_id="c" * 36, credentials_envelope={},
                        snapshot={"insights": {"mfa": {"percent": 80, "notRegistered": 2, "adminsWithoutMfa": []},
                                               "secureScore": {"percent": 60, "current": 30, "max": 50}}}),
         Ticket(number=1001, tenant_id=tenant["parentId"] or tenant["id"], account_tenant_id=tenant["id"], subject="Printer",
                resolved_at=now - timedelta(days=3), sla_due_at=now - timedelta(days=2), created_at=now - timedelta(days=4)),
         Contract(tenant_id=tenant["parentId"] or tenant["id"], account_tenant_id=tenant["id"], name="Managed", monthly_fee=1000,
                  end_date=(now + timedelta(days=40)).date().isoformat()),
         Invoice(number="INV-1", tenant_id=tenant["parentId"] or tenant["id"], account_tenant_id=tenant["id"], subtotal=1000,
                 total=1200, status="Paid", created_at=now - timedelta(days=10)))
    body, parts = _health(client, admin, tenant)
    assert parts["devices"]["score"] == 75 and parts["devices"]["stale"] == ["ACME-PC-3"]
    assert parts["protection"]["score"] == 65  # 3 of 4 healthy, less 10 for the open critical alert
    assert parts["backup"]["score"] == 50 and "Accounts PC" in parts["backup"]["detail"]
    assert parts["identity"]["score"] == 70 and parts["identity"]["value"] == "MFA 80% · Secure Score 60%"
    assert parts["vulnerabilities"]["score"] == 75 and parts["vulnerabilities"]["status"] == "warn"
    assert parts["service"]["score"] == 100
    assert parts["account"]["renewalSoon"] is True and parts["account"]["marginPercent"] is not None
    expected = sum(p["score"] * p["weight"] for p in body["parts"] if p["score"] is not None) / \
        sum(p["weight"] for p in body["parts"] if p["score"] is not None)
    assert body["score"] == round(expected) and body["status"] in ("good", "warn", "bad")


def test_money_is_only_shown_to_finance_staff_but_still_counts(client, admin, tenant):
    _add(Contract(tenant_id=tenant["parentId"] or tenant["id"], account_tenant_id=tenant["id"], name="Managed", monthly_fee=500),
         Invoice(number="INV-2", tenant_id=tenant["parentId"] or tenant["id"], account_tenant_id=tenant["id"], subtotal=500,
                 total=600, status="Paid"))
    _, parts = _health(client, admin, tenant)
    assert "margin" in parts["account"]["value"]
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "ops@acme.example",
                                                           "password": "acme-password-123", "role": "tenant_admin"})
    ops = login(client, "ops@acme.example", "acme-password-123")
    _, theirs = _health(client, ops, tenant)
    assert "margin" not in theirs["account"]["value"] and "marginPercent" not in theirs["account"]
    assert theirs["account"]["score"] == parts["account"]["score"]


def test_daily_snapshot_and_monthly_report_are_made_once(client, admin, tenant):
    with database.session_factory()() as db:
        db.get(Tenant, tenant["id"]).created_at = utcnow() - timedelta(days=90)
        db.commit()
        first = client360.tick(db)
        again = client360.tick(db)
        assert first["snapshots"] >= 1 and first["reports"] >= 1 and again == {"snapshots": 0, "reports": 0}
        assert db.query(ClientHealthSnapshot).filter_by(tenant_id=tenant["id"]).count() == 1
        report = db.query(ClientReport).filter_by(tenant_id=tenant["id"], kind="monthly").one()
        assert "What we did for you in" in report.html
    body, _ = _health(client, admin, tenant)
    assert len(body["trend"]) == 1
    assert tenant["id"] in client.get("/api/console/clients/health", headers=admin).json()
    listed = client.get(f"/api/console/clients/{tenant['id']}/reports", headers=admin).json()
    assert listed[0]["kind"] == "monthly" and listed[0]["createdBy"] == "system"
    saved = client.get(f"/api/console/clients/{tenant['id']}/reports/{listed[0]['id']}.html", headers=admin)
    assert saved.status_code == 200 and "What we did for you" in saved.text


def test_the_reports_describe_the_work_done_and_what_to_do_next(client, admin, tenant):
    device = enroll(client, admin, tenant)
    now = utcnow()
    last_month = (now.replace(day=1) - timedelta(days=1)).replace(day=15)
    _add(Ticket(number=1002, tenant_id=tenant["parentId"] or tenant["id"], account_tenant_id=tenant["id"], subject="Email",
                created_at=last_month, resolved_at=last_month + timedelta(hours=2), sla_due_at=last_month + timedelta(hours=8)),
         DevicePatch(device_id=device["deviceId"], tenant_id=tenant["id"], patch_key="KB1", status="installed", installed_at=last_month))
    monthly = client.get(f"/api/console/clients/{tenant['id']}/reports/monthly.html", headers=admin)
    assert monthly.status_code == 200
    assert "Support requests resolved" in monthly.text and "Updates installed" in monthly.text and "100% of them" in monthly.text
    quarterly = client.get(f"/api/console/clients/{tenant['id']}/reports/quarterly.html", headers=admin, params={"quarter": "2026-Q3"})
    assert quarterly.status_code == 200 and "Quarterly review: Q3 2026" in quarterly.text and "Recommended next steps" in quarterly.text
    assert client.get(f"/api/console/clients/{tenant['id']}/reports/quarterly.html", headers=admin,
                      params={"quarter": "2026-Q9"}).status_code == 400
    kept = client.post(f"/api/console/clients/{tenant['id']}/reports", headers=admin, json={"kind": "quarterly", "period": "2026-Q3"})
    assert kept.status_code == 200 and kept.json()["period"] == "2026-Q3"


def test_another_customers_health_and_reports_are_out_of_scope(client, admin, tenant):
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "ops@acme.example",
                                                           "password": "acme-password-123", "role": "tenant_admin"})
    ops = login(client, "ops@acme.example", "acme-password-123")
    assert client.get(f"/api/console/clients/{other['id']}/health", headers=ops).status_code == 404
    assert client.get(f"/api/console/clients/{other['id']}/reports/monthly.html", headers=ops).status_code == 404
    assert client.get(f"/api/console/clients/{tenant['id']}/health", headers=ops).status_code == 200
