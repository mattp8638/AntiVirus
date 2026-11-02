"""CORE-01 (background jobs): running every scheduled and hourly job, with a row of data in every customer-owned table
for two customers, never makes anything that points across customers.

The API matrix (test_scope_matrix.py) proves a request cannot reach another customer's data. This proves the same for
the work nobody requests: schedules, automations, self-healing, patching, Microsoft 365 and GRC syncs, retention.
"""
from sqlalchemy import inspect, select

from conftest import enroll
from test_scope_matrix import _seed_every_table, _tenant_tables

from fenrir_cloud import config, db as database, main
from fenrir_cloud.deps import tenant_subtree
from fenrir_cloud.models import Command, Device, Job, ScheduledTask, Tenant


def _block_network(monkeypatch):
    """Background jobs must not reach real providers from a test: every outbound HTTP call fails."""
    import httpx

    def refuse(*args, **kwargs):
        raise httpx.ConnectError("network disabled in tests")

    monkeypatch.setattr(httpx.Client, "send", refuse)
    monkeypatch.setattr(httpx.AsyncClient, "send", refuse)


def _violations(db) -> list[str]:
    tenants = {t.id: t for t in db.execute(select(Tenant)).scalars()}
    subtree = {tid: tenant_subtree(db, tid) for tid in tenants}
    device_tenant = dict(db.execute(select(Device.id, Device.tenant_id)).all())
    found = []
    for cls in _tenant_tables():
        columns = cls.__table__.c
        if "device_id" not in columns or "tenant_id" not in columns:
            continue
        for row in db.execute(select(cls)).scalars():
            owner, device = row.tenant_id, row.device_id
            if device not in device_tenant or owner not in subtree:
                continue
            # A row may belong to the device's customer, or to an MSP above it (tickets, invoices about the device).
            if device_tenant[device] not in subtree[owner]:
                key = inspect(row).identity
                found.append(f"{cls.__tablename__} {key[0] if key else '?'}: owned by {owner}, about a device of {device_tenant[device]}")
    for job in db.execute(select(Job)).scalars():
        for device_id in (job.command_ids or {}):
            if device_id in device_tenant and device_tenant[device_id] not in subtree.get(job.tenant_id, set()):
                found.append(f"job {job.id} ({job.name}) of {job.tenant_id} queued work on a device of {device_tenant[device_id]}")
    return found


def test_background_jobs_never_act_across_customers(client, admin, tenant, monkeypatch):
    _block_network(monkeypatch)
    bravo = client.post("/api/console/tenants", headers=admin, json={"name": "Bravo Dental", "template": "balanced"}).json()
    alpha_device = enroll(client, admin, tenant, hostname="ALPHA-PC", serial="A-1")
    bravo_device = enroll(client, admin, bravo, hostname="BRAVO-PC", serial="B-1")
    # Generic rows in every customer table for both customers (schedules, conditions, policies, monitors...), plus a
    # real Alpha schedule that names Bravo's customer and device as targets, as a malicious Alpha admin might.
    _seed_every_table(tenant["id"], alpha_device["deviceId"])
    _seed_every_table(bravo["id"], bravo_device["deviceId"])
    with database.session_factory()() as db:
        db.add(ScheduledTask(tenant_id=tenant["id"], name="Alpha everything", enabled=True, targets={"tenantIds": [tenant["id"], bravo["id"]], "deviceIds": [bravo_device["deviceId"]]},
                             actions=[{"type": "command", "command": "inventory.refresh"}], next_run_at=main.utcnow()))
        db.commit()
        before = _violations(db)
    assert before == [], before  # the seed itself is clean

    settings = config.get_settings()
    ran = []
    with database.session_factory()() as db:
        for name, _every, job in main._scheduled_jobs():
            main._run_job(db, name, job)
            ran.append(name)
        for name, job in main._maintenance_jobs(settings):
            main._run_job(db, name, job)
            ran.append(name)
    assert "rmm" in ran and "telemetry.retention" in ran

    with database.session_factory()() as db:
        problems = _violations(db)
        # The schedule ran, and only on Alpha's device.
        commands = db.execute(select(Command).where(Command.type == "inventory.refresh")).scalars().all()
    assert problems == [], "\n".join(problems)
    assert commands and {c.device_id for c in commands} == {alpha_device["deviceId"]}
