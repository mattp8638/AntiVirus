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
    valid = client.post(base, headers=admin, json={"accountTenantId": tenant["id"],
                          "name": "My workstation", "deviceId": device["deviceId"]})
    assert valid.status_code == 200, valid.text
    duplicate = client.post(base, headers=admin, json={"accountTenantId": tenant["id"],
                              "name": "Same machine twice", "deviceId": device["deviceId"]})
    assert duplicate.status_code == 409
    updated = client.patch(f"{base}/{valid.json()['id']}", headers=admin,
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
