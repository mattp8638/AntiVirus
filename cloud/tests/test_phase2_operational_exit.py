from datetime import timedelta

from fenrir_cloud import db as database, rmm
from fenrir_cloud.models import Command, utcnow
"""Phase 2 exit-gate regressions. Each test represents a real MSP workflow contract.

These tests run the cloud API with a simulated device. A physical Windows/Linux
agent and reboot/connectivity validation are separate, REQUIRED release gates.
"""
from conftest import enroll


def _cmd(client, device, status="completed", result=None):
    [item] = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending",
                        headers=device["headers"]).json()["items"]
    path = f"/api/v1/devices/{device['deviceId']}/commands/{item['id']}/complete"
    return item, path, client.post(path, headers=device["headers"],
                                   json={"status": status, "resultJson": result or {"exitCode": 0}})


def test_command_completion_is_idempotent_and_cancelled_work_cannot_complete(client, admin, tenant, device):
    issued = client.post(f"/api/console/devices/{device['deviceId']}/commands",
                         headers=admin, json={"type": "inventory.refresh"})
    assert issued.status_code == 200, issued.text
    command, url, first = _cmd(client, device)
    assert first.status_code == 200 and first.json()["status"] == "completed"
    again = client.post(url, headers=device["headers"],
                        json={"status": "completed", "resultJson": {"exitCode": 0}})
    assert again.status_code == 200 and again.json()["duplicate"] is True
    conflicting = client.post(url, headers=device["headers"], json={"status": "failed"})
    assert conflicting.status_code == 409

    second = client.post(f"/api/console/devices/{device['deviceId']}/commands",
                         headers=admin, json={"type": "inventory.refresh"})
    assert second.status_code == 200, second.text
    # Cancel before the endpoint collects the work.
    job = client.post("/api/console/rmm/jobs", headers=admin,
                      json={"commandType": "scan.targeted", "targetPath": "C:\\Users\\Public",
                            "targets": {"deviceIds": [device["deviceId"]]}})
    assert job.status_code == 200, job.text
    cancelled = client.post(f"/api/console/rmm/jobs/{job.json()['id']}/cancel", headers=admin)
    assert cancelled.status_code == 200
    assert cancelled.json()["cancelledPending"] == 1
    cancelled_id = next(iter(job.json()["commandIds"].values()))
    late = client.post(f"/api/v1/devices/{device['deviceId']}/commands/{cancelled_id}/complete",
                       headers=device["headers"], json={"status": "completed"})
    assert late.status_code == 409


def test_cancel_dispatched_work_remains_in_progress_until_actual_result(client, admin, tenant, device):
    job = client.post("/api/console/rmm/jobs", headers=admin, json={
        "commandType": "inventory.refresh",
        "targets": {"deviceIds": [device["deviceId"]]}
    })
    assert job.status_code == 200, job.text
    [pending] = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending",
                           headers=device["headers"]).json()["items"]
    cancelled = client.post(f"/api/console/rmm/jobs/{job.json()['id']}/cancel", headers=admin)
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["alreadyDispatched"] == 1
    assert cancelled.json()["cancellationComplete"] is False
    assert cancelled.json()["status"] == "running"
    completion = client.post(
        f"/api/v1/devices/{device['deviceId']}/commands/{pending['id']}/complete",
        headers=device["headers"], json={"status": "completed", "resultJson": {"exitCode": 0}})
    assert completion.status_code == 200, completion.text
    detail = client.get(f"/api/console/rmm/jobs/{job.json()['id']}", headers=admin).json()
    assert detail["status"] == "completed" and detail["summary"]["completed"] == 1


def test_monitor_ticket_recovery_keeps_assigned_work_open_for_review(client, admin, tenant, device):
    condition = client.post("/api/console/rmm/conditions", headers=admin, json={
        "name": "Phase 2 disk monitor", "metric": "disk_free_percent", "operator": "<",
        "threshold": 10, "durationMinutes": 0, "severity": "high",
        "tenantId": tenant["id"], "actions": [{"type": "ticket"}]})
    assert condition.status_code == 200, condition.text
    def beat(free):
        return client.post(f"/api/v1/devices/{device['deviceId']}/heartbeat",
                           headers=device["headers"], json={"healthState": "healthy",
                           "metrics": {"disks": [{"mount": "C:", "totalGb": 100,
                                                 "freeGb": free, "freePercent": free}]}})
    assert beat(3).status_code == 200
    ticket = next(t for t in client.get("/api/console/tickets", headers=admin).json()
                  if t["source"] == "rmm")
    assert ticket["deviceId"] == device["deviceId"] and ticket["accountTenantId"] == tenant["id"]
    assigned = client.patch(f"/api/console/tickets/{ticket['id']}", headers=admin,
                            json={"assignee": "technician@example.test", "status": "In Progress"})
    assert assigned.status_code == 200, assigned.text
    assert beat(55).status_code == 200
    detail = client.get(f"/api/console/tickets/{ticket['id']}", headers=admin).json()
    assert detail["status"] == "In Progress" and detail["assignee"] == "technician@example.test"
    assert any("recovered" in str(n.get("text", "")).lower() for n in detail["comments"])
    resolved = client.patch(f"/api/console/tickets/{ticket['id']}",
                            headers=admin, json={"status": "Resolved", "comment": "Verified recovery"})
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "Resolved"


def test_cmdb_rejects_cross_customer_devices_and_duplicate_assets(client, admin, tenant, device):
    another = client.post("/api/console/tenants", headers=admin, json={"name": "Other Company"}).json()
    other_device = enroll(client, admin, another, hostname="OTHER-WS", serial="P2-OTHER-001")
    base = "/api/console/psa/configurations"
    bad = client.post(base, headers=admin, json={"accountTenantId": tenant["id"],
                        "name": "Wrong customer", "deviceId": other_device["deviceId"]})
    assert bad.status_code == 422
    existing = client.get(base, headers=admin, params={"accountTenantId": tenant["id"]}).json()
    assert len(existing) == 1 and existing[0]["deviceId"] == device["deviceId"]
    duplicate = client.post(base, headers=admin, json={"accountTenantId": tenant["id"],
                              "name": "Same machine twice", "deviceId": device["deviceId"]})
    assert duplicate.status_code == 409
    updated = client.patch(f"{base}/{existing[0]['id']}", headers=admin,
                           json={"deviceId": other_device["deviceId"]})
    assert updated.status_code == 422
    assert client.get(f"{base}", headers=admin, params={"accountTenantId":tenant["id"]}).json()[0]["deviceId"] == device["deviceId"]


def test_remote_ticket_must_match_device_customer_and_device_binding(client, admin, tenant, device):
    other = client.post("/api/console/tenants", headers=admin,
                        json={"name": "Other Remote Customer"}).json()
    other_ticket = client.post("/api/console/tickets", headers=admin, json={
        "accountTenantId": other["id"], "subject": "Remote support for other customer"}).json()
    bad = client.post("/api/console/remote/sessions", headers=admin, json={
        "deviceId": device["deviceId"], "ticketId": other_ticket["id"]})
    assert bad.status_code == 422
    ticket = client.post("/api/console/tickets", headers=admin,
                         json={"accountTenantId": tenant["id"], "subject": "Valid remote support"}).json()
    good = client.post("/api/console/remote/sessions", headers=admin, json={
        "deviceId": device["deviceId"], "ticketId": ticket["id"]})
    assert good.status_code == 200, good.text


def test_monitor_ticket_contains_verified_remediation_job_outcome(client, admin, tenant, device):
    """Actions may be configured before the ticket; job remains linked."""
    rule = client.post("/api/console/rmm/conditions", headers=admin, json={
        "name": "Disk action trace", "tenantId": tenant["id"],
        "metric": "disk_free_percent", "operator": "<", "threshold": 10,
        "durationMinutes": 0, "actions": [
            {"type": "command", "command": "inventory.refresh"},
            {"type": "ticket"},
        ],
    })
    assert rule.status_code == 200, rule.text
    beat = client.post(f"/api/v1/devices/{device['deviceId']}/heartbeat", headers=device["headers"], json={
        "metrics": {"disks": [{"mount": "C:", "totalGb": 100, "freeGb": 2, "freePercent": 2}]}})
    assert beat.status_code == 200, beat.text
    tickets = client.get("/api/console/tickets", headers=admin).json()
    ticket = next(t for t in tickets if t["source"] == "rmm")
    detail = client.get(f"/api/console/tickets/{ticket['id']}", headers=admin).json()
    assert len(detail["rmmJobs"]) == 1
    job = detail["rmmJobs"][0]
    assert job["ticketId"] == ticket["id"]
    [command] = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending",
                           headers=device["headers"]).json()["items"]
    assert command["type"] == "inventory.refresh"
    completed = client.post(f"/api/v1/devices/{device['deviceId']}/commands/{command['id']}/complete",
                            headers=device["headers"], json={"status": "completed", "resultJson": {"exitCode": 0}})
    assert completed.status_code == 200, completed.text
    refreshed = client.get(f"/api/console/tickets/{ticket['id']}", headers=admin).json()
    assert refreshed["rmmJobs"][0]["status"] == "completed"
    assert refreshed["rmmJobs"][0]["summary"]["completed"] == 1


def test_approved_device_updates_asset_automatically_from_heartbeat(client, admin, tenant, device):
    endpoint = "/api/console/psa/configurations"
    before = client.get(endpoint, headers=admin, params={"accountTenantId": tenant["id"]}).json()
    assert len(before) == 1
    original_id = before[0]["id"]
    response = client.post(f"/api/v1/devices/{device['deviceId']}/heartbeat",
                           headers=device["headers"], json={"metrics": {
                           "manufacturer": "Lenovo", "model": "ThinkPad Test",
                           "cpuPercent": 11, "memoryPercent": 17}})
    assert response.status_code == 200, response.text
    after = client.get(endpoint, headers=admin, params={"accountTenantId": tenant["id"]}).json()
    assert len(after) == 1
    assert after[0]["id"] == original_id
    assert after[0]["manufacturer"] == "Lenovo"
    assert after[0]["model"] == "ThinkPad Test"


def test_stale_undelivered_commands_expire_but_dispatched_work_remains_reconcilable(client, admin, tenant, device):
    job = client.post("/api/console/rmm/jobs", headers=admin, json={
        "commandType": "inventory.refresh", "targets": {"deviceIds": [device["deviceId"]]}})
    assert job.status_code == 200, job.text
    command_id = next(iter(job.json()["commandIds"].values()))
    session = database.session_factory()()
    try:
        command = session.get(Command, command_id)
        command.created_at = utcnow() - timedelta(days=9)
        session.commit()
        assert rmm.expire_stale_queued_commands(session) == 1
        session.commit()
    finally:
        session.close()
    detail = client.get(f"/api/console/rmm/jobs/{job.json()['id']}", headers=admin).json()
    assert detail["status"] == "failed" and detail["summary"]["expired"] == 1
    assert client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending",
                      headers=device["headers"]).json()["items"] == []

    job2 = client.post("/api/console/rmm/jobs", headers=admin, json={
        "commandType": "inventory.refresh", "targets": {"deviceIds": [device["deviceId"]]}})
    assert job2.status_code == 200
    [dispatched] = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending",
                              headers=device["headers"]).json()["items"]
    session = database.session_factory()()
    try:
        command = session.get(Command, dispatched["id"])
        command.created_at = utcnow() - timedelta(days=9)
        session.commit()
        assert rmm.expire_stale_queued_commands(session) == 0
        session.commit()
    finally:
        session.close()
    assert client.get(f"/api/console/rmm/jobs/{job2.json()['id']}", headers=admin).json()["status"] == "running"


def test_nonzero_exit_is_a_failure_and_same_result_can_be_retried(client, admin, tenant, device):
    command = client.post(f"/api/console/devices/{device['deviceId']}/commands",
                          headers=admin, json={"type": "scan.targeted",
                          "targetPath": "C:\\Users\\Public"})
    assert command.status_code == 200
    polled = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending",
                        headers=device["headers"]).json()["items"][0]
    url = f"/api/v1/devices/{device['deviceId']}/commands/{polled['id']}/complete"
    malformed = client.post(url, headers=device["headers"],
                            json={"status": "completed", "resultJson": "not valid JSON"})
    assert malformed.status_code == 422
    invalid = client.post(url, headers=device["headers"],
                          json={"status": "completed", "resultJson": [1, 2]})
    assert invalid.status_code == 422
    payload = {"status": "completed", "resultJson": {"exitCode": 1603, "stderr": "Installer failed"}}
    failed = client.post(url, headers=device["headers"], json=payload)
    assert failed.status_code == 200 and failed.json()["status"] == "failed"
    retry = client.post(url, headers=device["headers"], json=payload)
    assert retry.status_code == 200 and retry.json()["duplicate"] is True


def test_scheduler_lock_is_available_and_postgres_prevents_concurrent_owners(client):
    from concurrent.futures import ThreadPoolExecutor
    from fenrir_cloud.main import _scheduler_lease
    from fenrir_cloud import db as database

    with _scheduler_lease() as owner:
        assert owner is True
        if database.engine().dialect.name == "postgresql":
            with ThreadPoolExecutor(max_workers=1) as pool:
                other = pool.submit(lambda: _check_secondary_scheduler_lease()).result(timeout=10)
            assert other is False


def _check_secondary_scheduler_lease():
    from fenrir_cloud.main import _scheduler_lease
    with _scheduler_lease() as acquired:
        return acquired


def test_reassigned_technician_cannot_read_old_customer_job_outputs(client, admin, tenant, device):
    """Creator attribution does not grant permanent rights after tenant removal."""
    from conftest import login
    from fenrir_cloud.models import User

    other = client.post("/api/console/tenants", headers=admin,
                        json={"name": "New MSP service assignment"}).json()
    created = client.post("/api/console/users", headers=admin, json={
        "email": "transferred.technician@example.test", "password": "test-long-password-02",
        "name": "Transferred technician", "role": "tenant_admin",
        "tenantId": tenant["id"]})
    assert created.status_code == 200, created.text
    engineer = login(client, "transferred.technician@example.test", "test-long-password-02")
    queued = client.post("/api/console/rmm/jobs", headers=engineer, json={
        "commandType": "inventory.refresh", "targets": {
            "deviceIds": [device["deviceId"]]}})
    assert queued.status_code == 200, queued.text
    job_id = queued.json()["id"]
    session = database.session_factory()()
    try:
        member = session.get(User, created.json()["id"])
        member.tenant_id = other["id"]
        session.commit()
    finally:
        session.close()
    assert client.get(f"/api/console/rmm/jobs/{job_id}", headers=engineer).status_code == 404
    exposed = client.get("/api/console/rmm/jobs", headers=engineer)
    assert exposed.status_code == 200
    assert job_id not in [j["id"] for j in exposed.json()]


def test_device_retirement_revokes_agent_key_cancels_work_and_preserves_asset(client, admin, tenant, device):
    identity = device["deviceId"]
    new_customer = client.post("/api/console/tenants", headers=admin,
                               json={"name": "Device destination"}).json()
    move = client.patch(f"/api/console/devices/{identity}", headers=admin,
                        json={"tenantId": new_customer["id"]})
    assert move.status_code == 409
    unsafe = client.patch(f"/api/console/devices/{identity}", headers=admin,
                          json={"approved": False})
    assert unsafe.status_code == 409

    job = client.post("/api/console/rmm/jobs", headers=admin,
                      json={"commandType": "inventory.refresh", "targets": {"deviceIds": [identity]}})
    assert job.status_code == 200, job.text
    retired = client.delete(f"/api/console/devices/{identity}", headers=admin)
    assert retired.status_code == 200, retired.text
    heartbeat = client.post(f"/api/v1/devices/{identity}/heartbeat",
                            headers=device["headers"], json={"healthState": "healthy"})
    assert heartbeat.status_code == 401
    completed = client.get(f"/api/console/rmm/jobs/{job.json()['id']}", headers=admin).json()
    assert completed["status"] == "cancelled"
    assets = client.get("/api/console/psa/configurations", headers=admin,
                        params={"accountTenantId": tenant["id"]}).json()
    assert len(assets) == 1 and assets[0]["status"] == "Retired"
    assert assets[0]["deviceId"] == identity


def test_device_retirement_waits_for_command_reconciliation(client, admin, tenant, device):
    job = client.post("/api/console/rmm/jobs", headers=admin,
                      json={"commandType": "inventory.refresh", "targets": {"deviceIds": [device["deviceId"]]}})
    assert job.status_code == 200
    [running] = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending",
                           headers=device["headers"]).json()["items"]
    blocked = client.delete(f"/api/console/devices/{device['deviceId']}", headers=admin)
    assert blocked.status_code == 409
    still_online = client.post(f"/api/v1/devices/{device['deviceId']}/heartbeat",
                               headers=device["headers"], json={"healthState": "healthy"})
    assert still_online.status_code == 200
    completed = client.post(f"/api/v1/devices/{device['deviceId']}/commands/{running['id']}/complete",
                            headers=device["headers"], json={"status": "completed", "resultJson": {}})
    assert completed.status_code == 200
    assert client.delete(f"/api/console/devices/{device['deviceId']}", headers=admin).status_code == 200
