"""Stop acknowledgement, decommissioning with in-flight work and narrowly scoped retired credentials."""
from datetime import timedelta

from sqlalchemy import inspect, text

from conftest import enroll
from fenrir_cloud import db as database
from fenrir_cloud.models import Command, Device, utcnow


def job(client, admin, device):
    reply = client.post("/api/console/rmm/jobs", headers=admin, json={
        "name": "Cancellable work", "commandType": "patch.scan", "targets": {"deviceIds": [device["deviceId"]]}})
    assert reply.status_code == 200, reply.text
    return reply.json()


def poll(client, device):
    reply = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"])
    assert reply.status_code == 200, reply.text
    return reply.json()["items"]


def test_cancel_pending_never_dispatches_and_is_idempotent(client, admin, device):
    work = job(client, admin, device)
    cid = work["commandIds"][device["deviceId"]]
    url = f"/api/console/commands/{cid}/cancel"
    first = client.post(url, headers=admin)
    assert first.status_code == 200 and first.json()["status"] == "cancelled"
    assert first.json()["result"]["cancelledBeforeExecution"] is True
    assert client.post(url, headers=admin).status_code == 200
    assert poll(client, device) == []
    assert client.get(f"/api/console/rmm/jobs/{work['id']}", headers=admin).json()["status"] == "cancelled"


def test_dispatched_stop_waits_for_agent_ack_and_survives_result_retries(client, admin, device):
    work = job(client, admin, device)
    [command] = poll(client, device)
    cid, did = command["id"], device["deviceId"]
    stopped = client.post(f"/api/console/rmm/jobs/{work['id']}/cancel", headers=admin)
    assert stopped.status_code == 200, stopped.text
    assert stopped.json()["status"] == "cancelling" and not stopped.json()["cancellationComplete"]
    # Old agents must not receive a cancelling command as new work.
    assert poll(client, device) == []
    replay = client.get(f"/api/v1/devices/{did}/commands/pending?include_cancelling=true", headers=device["headers"])
    assert [c["id"] for c in replay.json()["items"]] == [cid]
    state = client.get(f"/api/v1/devices/{did}/commands/{cid}/state", headers=device["headers"]).json()
    assert state["cancelRequested"] is True and state["status"] == "cancelling"
    done = f"/api/v1/devices/{did}/commands/{cid}/complete"
    body = {"status": "cancelled", "resultJson": {"exitCode": -1, "cancelled": True}}
    acknowledged = client.post(done, headers=device["headers"], json=body)
    assert acknowledged.status_code == 200 and acknowledged.json()["status"] == "cancelled"
    duplicate = client.post(done, headers=device["headers"], json=body)
    assert duplicate.status_code == 200 and duplicate.json()["duplicate"]
    detail = client.get(f"/api/console/rmm/jobs/{work['id']}", headers=admin).json()
    assert detail["status"] == "cancelled" and detail["results"][0]["result"]["stopConfirmed"]


def test_decommission_stops_work_and_sessions_without_blocking_removal(client, admin, device):
    work = job(client, admin, device)
    [running] = poll(client, device)
    queued = client.post(f"/api/console/devices/{device['deviceId']}/commands", headers=admin, json={"type": "inventory.refresh"}).json()
    session = client.post("/api/console/remote/sessions", headers=admin, json={"deviceId": device["deviceId"]})
    assert session.status_code == 200, session.text
    base = f"/api/console/devices/{device['deviceId']}"
    removed = client.delete(base, headers=admin)
    assert removed.status_code == 200, removed.text
    assert removed.json()["stopRequested"] == 1 and removed.json()["sessionsEnded"] == 1
    assert device["deviceId"] not in {d["id"] for d in client.get("/api/console/devices", headers=admin).json()}
    detail = client.get(base, headers=admin).json()
    assert detail["device"]["retired"]
    statuses = {c["id"]: c["status"] for c in detail["commands"]}
    assert statuses[running["id"]] == "cancelling" and statuses[queued["id"]] == "cancelled"
    assert "cancelApiKeyHash" not in str(detail)
    remote = client.get(f"/api/console/remote/sessions/{session.json()['id']}", headers=admin).json()
    assert remote["status"] == "ended"
    # Revocation is immediate, but the agent can acknowledge this one stop.
    agent = f"/api/v1/devices/{device['deviceId']}"
    assert client.get(agent + "/commands/pending", headers=device["headers"]).status_code == 401
    assert client.post(agent + "/heartbeat", headers=device["headers"], json={}).status_code == 401
    assert client.get(agent + f"/commands/{running['id']}/state", headers=device["headers"]).json()["cancelRequested"]
    ack = client.post(agent + f"/commands/{running['id']}/complete", headers=device["headers"], json={"status": "cancelled"})
    assert ack.status_code == 200, ack.text
    assert client.get(f"/api/console/rmm/jobs/{work['id']}", headers=admin).json()["status"] == "cancelled"
    assert client.delete(base, headers=admin).status_code == 200


def test_retired_stop_grant_is_command_scoped_and_expires(client, admin, tenant, device):
    work = job(client, admin, device)
    [running] = poll(client, device)
    other = enroll(client, admin, tenant, hostname="OTHER", serial="OTHER")
    client.delete(f"/api/console/devices/{device['deviceId']}", headers=admin)
    path = f"/api/v1/devices/{device['deviceId']}/commands/{running['id']}/state"
    assert client.get(path, headers=other["headers"]).status_code == 401
    assert client.get(path.replace(device['deviceId'], other['deviceId']), headers=device["headers"]).status_code == 401
    assert client.get(path.replace(running['id'], "cmd_unknown"), headers=device["headers"]).status_code == 401
    with database.session_factory()() as db:
        command = db.get(Command, running["id"])
        command.cancel_requested_at = utcnow() - timedelta(days=8)
        db.commit()
    assert client.get(path, headers=device["headers"]).status_code == 401
    assert work["id"]


def test_remove_running_job_hides_activity_without_losing_stop_delivery(client, admin, device):
    work = job(client, admin, device)
    [running] = poll(client, device)
    removed = client.delete(f"/api/console/rmm/jobs/{work['id']}", headers=admin)
    assert removed.status_code == 200 and removed.json()["stopRequested"] == 1
    assert work["id"] not in {j["id"] for j in client.get("/api/console/rmm/jobs", headers=admin).json()}
    assert client.get(f"/api/console/rmm/jobs/{work['id']}", headers=admin).json()["status"] == "cancelling"
    assert client.get(f"/api/v1/devices/{device['deviceId']}/commands/{running['id']}/state", headers=device["headers"]).json()["cancelRequested"]


def test_delete_schedule_stops_its_jobs_but_preserves_unrelated_work(client, admin, tenant, device):
    unrelated = job(client, admin, device)
    schedule = client.post("/api/console/rmm/tasks", headers=admin, json={
        "tenantId": tenant["id"], "name": "Stop this schedule", "schedule": {"type": "daily", "at": "02:00"},
        "targets": {"deviceIds": [device["deviceId"]]}, "actions": [{"type": "command", "command": "patch.scan"}]}).json()
    jobs = client.post(f"/api/console/rmm/tasks/{schedule['id']}/run", headers=admin).json()
    poll(client, device)
    removed = client.delete(f"/api/console/rmm/tasks/{schedule['id']}", headers=admin)
    assert removed.status_code == 200, removed.text
    assert client.get(f"/api/console/rmm/jobs/{jobs[0]['id']}", headers=admin).json()["status"] == "cancelling"
    assert client.get(f"/api/console/rmm/jobs/{unrelated['id']}", headers=admin).json()["status"] == "running"
    assert schedule["id"] not in {s["id"] for s in client.get("/api/console/rmm/tasks", headers=admin).json()}
    assert client.post(f"/api/console/rmm/tasks/{schedule['id']}/run", headers=admin).status_code == 404


def test_upgrade_adds_cancellation_fields_without_rewriting_running_commands(client, admin, device):
    work = job(client, admin, device)
    [running] = poll(client, device)
    with database.engine().begin() as conn:
        for name in ("cancel_requested_at", "cancel_requested_by", "cancel_api_key_hash"):
            conn.execute(text(f"ALTER TABLE commands DROP COLUMN {name}"))
        conn.execute(text("DELETE FROM schema_migrations WHERE version=30"))
    assert database.migrate(database.engine()) == [30]
    names = {c["name"] for c in inspect(database.engine()).get_columns("commands")}
    assert {"cancel_requested_at", "cancel_requested_by", "cancel_api_key_hash"} <= names
    with database.session_factory()() as db:
        assert db.get(Command, running["id"]).status == "dispatched"
    assert client.delete(f"/api/console/devices/{device['deviceId']}", headers=admin).status_code == 200
    assert database.migrate(database.engine()) == []
