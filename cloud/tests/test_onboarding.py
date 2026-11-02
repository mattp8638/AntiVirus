"""FLOW-01: customer onboarding is one checklist computed from real state: resumable, with real failures and no
duplicate customers."""
from datetime import timedelta

from conftest import enroll

from fenrir_cloud.db import session_factory
from fenrir_cloud.models import BackupPlan, BackupRun, Contact, Contract, M365Connection, Site, utcnow


def steps(client, admin, tenant):
    response = client.get(f"/api/console/onboarding/{tenant['id']}", headers=admin)
    assert response.status_code == 200, response.text
    data = response.json()
    return data, {s["key"]: s for s in data["steps"]}


def test_checklist_follows_real_state_and_reports_failures(client, admin, tenant):
    data, by_key = steps(client, admin, tenant)
    assert not data["ready"] and by_key["details"]["status"] == "todo" and by_key["agents"]["status"] == "todo"
    assert by_key["policy"]["status"] == "done"  # every customer starts with its own default policy

    with session_factory()() as db:
        db.add(Contact(tenant_id=tenant["id"], account_tenant_id=tenant["id"], name="Jo Bloggs", email="jo@acme.example", is_primary=True))
        db.add(Site(tenant_id=tenant["id"], account_tenant_id=tenant["id"], name="Head office"))
        db.add(Contract(tenant_id=tenant["id"], account_tenant_id=tenant["id"], name="Managed IT", plan="complete", active=True))
        plan = BackupPlan(tenant_id=tenant["id"], name="Server image", provider="Veeam")
        db.add(plan)
        db.flush()
        db.add(BackupRun(plan_id=plan.id, tenant_id=tenant["id"], external_id="r1", status="failed", completed_at=utcnow(), recorded_by="test"))
        db.add(M365Connection(tenant_id=tenant["id"], name="Acme 365", directory_id="d", client_id="c", credentials_envelope={},
                              snapshot={}, status="error", last_error="AADSTS7000215: Invalid client secret provided."))
        db.commit()
    device = enroll(client, admin, tenant)

    data, by_key = steps(client, admin, tenant)
    assert by_key["details"]["status"] == "done" and "Jo Bloggs" in by_key["details"]["detail"]
    assert by_key["agreement"]["status"] == "done"
    assert by_key["backup"]["status"] == "failed" and "failed" in by_key["backup"]["detail"]
    assert by_key["m365"]["status"] == "failed" and "AADSTS7000215" in by_key["m365"]["detail"]
    assert by_key["agents"]["status"] in ("done", "todo")  # approved immediately, or waiting for approval
    assert data["failed"] == 2 and not data["ready"]

    summary = client.get("/api/console/onboarding", headers=admin).json()
    row = next(r for r in summary if r["tenantId"] == tenant["id"])
    assert row["failed"] == 2 and row["next"]
    assert device["deviceId"]


def test_a_second_customer_with_the_same_name_is_refused(client, admin, tenant):
    response = client.post("/api/console/tenants", headers=admin, json={"name": f"  {tenant['name'].upper()} "})
    assert response.status_code == 400 and "already exists" in response.json()["detail"]
