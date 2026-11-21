"""Device backup (fenrir-backup-agent): enrolment, jobs, repositories, the ransomware guard and restores."""

import base64
import uuid

from conftest import ADMIN_PASSWORD, enroll

from fenrir_cloud import backup as bk

SEALED = {"v": 1, "epk": "A" * 43 + "=", "nonce": "B" * 16, "ct": "C" * 40}
CAPS = ["backup_system", "backup_disks", "verify", "restore_vhdx", "restore_disk", "boot_kvm"]


def link(client, admin, tenant, **extra):
    r = client.post("/api/console/backup/enrollments", headers=admin, json={"tenantId": tenant["id"], **extra})
    assert r.status_code == 200, r.text
    return r.json()


def agent_enroll(client, token, machine="m-1", key=None, role="server"):
    key = key or base64.b64encode(b"k" * 32).decode()
    r = client.post("/backup/api/agent/enroll", json={
        "protocol": 1, "token": token, "hostname": machine.upper(), "machine_id": machine, "role": role,
        "os": {"family": "windows", "name": "Windows Server", "version": "2022", "arch": "x86_64"},
        "agent_version": "0.1.0", "public_key": key})
    assert r.status_code == 200, r.text
    body = r.json()
    return body["agent_id"], {"Authorization": f"Bearer {body['agent_token']}"}


def heartbeat(client, h, running=None, caps=CAPS):
    r = client.post("/backup/api/agent/heartbeat", headers=h, json={
        "inventory": {"hostname": "M-1", "os": {"family": "windows"}, "agent_version": "0.1.0", "capabilities": caps},
        "running_job": running})
    assert r.status_code == 200, r.text
    return r.json()


def finish(client, h, job_id, state="succeeded", **extra):
    r = client.post(f"/backup/api/agent/jobs/{job_id}/update", headers=h, json={"state": state, **extra})
    assert r.status_code == 200, r.text


def ready_repo(client, admin, tenant, agent_id, h):
    repo_uuid = str(uuid.uuid4())
    r = client.post("/api/console/backup/repositories", headers=admin, json={
        "name": "Office NAS", "path": "D:\\Backups", "repoUuid": repo_uuid, "initAgentId": agent_id,
        "access": [{"agentId": agent_id, "sealed": SEALED}]})
    assert r.status_code == 200, r.text
    jobs = heartbeat(client, h)["jobs"]
    assert jobs[0]["kind"] == {"type": "init_repository"}
    assert jobs[0]["repository"]["sealed_secret"] == SEALED
    finish(client, h, jobs[0]["id"], repo_uuid=repo_uuid)
    return r.json()["id"]


def image(machine="m-1", total=1000, new=30, raw=30 * 1024, stored=12 * 1024, t=0):
    return {"image_id": str(uuid.uuid4()), "machine_id": machine, "hostname": machine.upper(), "created": "",
            "created_unix": 1_790_000_000 + t, "kind": "system", "consistency": "vss", "captured_bytes": 10 << 30,
            "stored_new_bytes": stored, "disks": [], "chunks_total": total, "chunks_new": new, "bytes_new_raw": raw}


def test_enrol_backup_and_ransomware_hold(client, admin, tenant):
    e = link(client, admin, tenant, role="server")
    assert "windows" in e["links"] and e["links"]["windows"]["setupFile"] == "Fenrir-Backup-Setup.exe"
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)
    machines = client.get("/api/console/backup/agents", headers=admin).json()
    assert [m["id"] for m in machines] == [agent_id] and machines[0]["online"]
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    assert client.get("/api/console/backup/repositories", headers=admin).json()[0]["status"] == "ready"

    plan = client.post("/api/console/backup/plans", headers=admin, json={
        "name": "Nightly", "agentId": agent_id, "repositoryId": repo_id, "job": {"type": "backup_system"},
        "schedule": {"type": "daily", "time": "02:00", "days": []}, "retention": {"keep_last": 3}})
    assert plan.status_code == 200, plan.text
    plan_id = plan.json()["id"]

    # Six normal backups build a baseline; each queues retention afterwards.
    for i in range(6):
        assert client.post(f"/api/console/backup/plans/{plan_id}/run", headers=admin).status_code == 200
        job = heartbeat(client, h)["jobs"][0]
        assert job["kind"]["type"] == "backup_system"
        finish(client, h, job["id"], images=[image(t=i)])
        ret = heartbeat(client, h)["jobs"][0]
        assert ret["kind"] == {"type": "apply_retention", "machine_ids": ["m-1"], "retention": {
            "keep_last": 3, "keep_daily": 0, "keep_weekly": 0, "keep_monthly": 0, "keep_yearly": 0}, "dry_run": False}
        finish(client, h, ret["id"])

    # Then most of the disk changes and nothing compresses: hold, alert, and retention waits.
    client.post(f"/api/console/backup/plans/{plan_id}/run", headers=admin)
    job = heartbeat(client, h)["jobs"][0]
    finish(client, h, job["id"], images=[image(new=800, raw=800 * 1024, stored=799 * 1024, t=10)])
    repo = client.get("/api/console/backup/repositories", headers=admin).json()[0]
    assert repo["hold"] and "ransomware" in repo["holdReason"] and repo["anomalies"] == 1
    assert heartbeat(client, h)["jobs"] == []  # the queued retention is held back
    alerts = client.get("/api/console/alerts", headers=admin).json()
    items = alerts["items"] if isinstance(alerts, dict) else alerts
    assert any(a["ruleId"] == bk.RULE_RANSOMWARE for a in items)

    # Releasing the hold needs a fresh password check.
    r = client.post(f"/api/console/backup/repositories/{repo_id}/hold", headers=admin, json={"hold": False})
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    step = {**admin, "X-Fenrir-Reauth": client.post("/api/console/auth/reauth", headers=admin,
                                                    json={"password": ADMIN_PASSWORD}).json()["reauthToken"]}
    assert client.post(f"/api/console/backup/repositories/{repo_id}/hold", headers=step, json={"hold": False}).status_code == 200
    assert heartbeat(client, h)["jobs"][0]["kind"]["type"] == "apply_retention"


def test_disk_restore_needs_typed_confirmation_and_reauth(client, admin, tenant):
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)
    ready_repo(client, admin, tenant, agent_id, h)
    client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                json={"kind": {"type": "backup_system"}, "repositoryId": client.get(
                    "/api/console/backup/repositories", headers=admin).json()[0]["id"]})
    job = heartbeat(client, h)["jobs"][0]
    im = image()
    finish(client, h, job["id"], images=[im])
    target = {"type": "disk", "device": r"\\.\PhysicalDrive1", "disk": 0, "confirm": r"\\.\PhysicalDrive1"}
    body = {"imageId": im["image_id"], "agentId": agent_id, "target": target}
    assert client.post("/api/console/backup/restores", headers=admin, json=body).json()["detail"] == "reauth_required"
    step = {**admin, "X-Fenrir-Reauth": client.post("/api/console/auth/reauth", headers=admin,
                                                    json={"password": ADMIN_PASSWORD}).json()["reauthToken"]}
    wrong = {**body, "target": {**target, "confirm": "PhysicalDrive1"}}
    assert client.post("/api/console/backup/restores", headers=step, json=wrong).status_code == 400
    assert client.post("/api/console/backup/restores", headers=step, json=body).status_code == 200
    spec = heartbeat(client, h)["jobs"][0]
    assert spec["kind"]["type"] == "restore" and spec["kind"]["target"]["confirm"] == target["device"]


def test_tenants_are_isolated_and_reenrol_with_new_key_drops_access(client, admin, tenant):
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    other = client.post("/api/console/tenants", json={"name": "Other Ltd", "template": "balanced"}, headers=admin).json()
    assert client.get(f"/api/console/backup/agents?tenantId={other['id']}", headers=admin).json() == []
    # A reinstall with a new key keeps the machine but its sealed secrets are useless: access is removed.
    again, h2 = agent_enroll(client, e["token"], key=base64.b64encode(b"n" * 32).decode())
    assert again == agent_id
    assert client.get("/api/console/backup/repositories", headers=admin).json()[0]["agents"] == []
    r = client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                    json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
    assert r.status_code == 400 and "no access" in r.json()["detail"]
    # The old token stopped working.
    assert client.post("/backup/api/agent/heartbeat", headers=h, json={"inventory": {}}).status_code == 401


def test_enrolment_link_bound_to_device(client, admin, tenant):
    dev = enroll(client, admin, tenant)
    e = link(client, admin, tenant, deviceId=dev["deviceId"], role="workstation")
    agent_id, h = agent_enroll(client, e["token"], role="workstation")
    rows = client.get(f"/api/console/backup/agents?deviceId={dev['deviceId']}", headers=admin).json()
    assert [r["id"] for r in rows] == [agent_id] and rows[0]["role"] == "workstation"
    revoked = client.delete(f"/api/console/backup/enrollments/{e['id']}", headers=admin)
    assert revoked.status_code == 200
    r = client.post("/backup/api/agent/enroll", json={"protocol": 1, "token": e["token"], "hostname": "X", "machine_id": "x",
                                                      "role": "server", "os": {}, "agent_version": "",
                                                      "public_key": base64.b64encode(b"z" * 32).decode()})
    assert r.status_code == 403


def test_schedule_and_anomaly_rules():
    daily = {"type": "daily", "time": "02:30", "days": [0], "utc_offset_minutes": 60}
    bk.validate_schedule(daily)
    t = bk.next_after(daily, 1_795_219_200)  # 2026-11-19 00:00 UTC, a Thursday
    assert t is not None and (t // 86_400 + 3) % 7 == 0 and (t + 3600) % 86_400 == 2 * 3600 + 1800
    assert bk.next_after({"type": "interval", "hours": 6}, 100) == 100 + 6 * 3600
    normal = [bk.ChangeStats(1000, 30, 30, 12)] * 6
    assert bk.evaluate_anomaly(normal, bk.ChangeStats(1000, 40, 40, 16)) is None
    assert bk.evaluate_anomaly(normal, bk.ChangeStats(1000, 700, 700, 699))
    assert bk.evaluate_anomaly([], bk.ChangeStats(1000, 1000, 1000, 1000)) is None  # first backup
    assert bk.evaluate_anomaly(normal, bk.ChangeStats(10, 5, 5, 5)) is None  # too little to judge


def test_install_script_and_setup_exe(client, admin, tenant, tmp_path, monkeypatch):
    monkeypatch.setenv("FENRIR_BACKUP_AGENTS_DIR", str(tmp_path))
    e = link(client, admin, tenant)
    assert client.get(f"/backup/install/{e['token']}/linux").status_code == 503
    for t in bk.ALL_TARGETS.values():
        (tmp_path / t.triple).mkdir(exist_ok=True)
        (tmp_path / t.triple / t.file).write_bytes(b"MZ-agent-" + t.triple.encode())
    script = client.get(f"/backup/install/{e['token']}/linux").text
    assert "SERVER='https://fenrir.test/backup'" in script and e["token"] in script
    exe = client.get(f"/backup/install/{e['token']}/hyperv/Fenrir-Backup-Setup-HyperV.exe").content
    assert exe.startswith(b"MZ-agent-") and exe.endswith(b"FENRIR-SETUP-V1\0") and b'"role":"hyperv"' in exe
    assert client.get("/backup/install/not-a-token/windows").status_code == 404
    # Self-update: an agent running another build is offered the server's.
    _, h = agent_enroll(client, e["token"])
    r = client.post("/backup/api/agent/heartbeat", headers=h, json={"inventory": {
        "agent_target": "x86_64-unknown-linux-gnu", "agent_sha256": "00", "capabilities": []}}).json()
    assert r["update"]["path"] == "/agent/x86_64-unknown-linux-musl/fenrir-backup-agent"
    assert client.get(r["update"]["path"].replace("/agent", "/backup/agent"), headers=h).content.startswith(b"MZ-agent-")


def test_enable_backup_pushes_installer_through_fenrir_agent(client, admin, tenant, tmp_path, monkeypatch):
    monkeypatch.setenv("FENRIR_BACKUP_AGENTS_DIR", str(tmp_path))
    dev = enroll(client, admin, tenant)
    assert client.post(f"/api/console/backup/devices/{dev['deviceId']}/install", headers=admin, json={}).status_code == 400
    t = bk.WIN[0]
    (tmp_path / t.triple).mkdir()
    (tmp_path / t.triple / t.file).write_bytes(b"MZ")
    r = client.post(f"/api/console/backup/devices/{dev['deviceId']}/install", headers=admin, json={"role": "server"})
    assert r.status_code == 200, r.text
    import json
    cmds = client.get(f"/api/v1/devices/{dev['deviceId']}/commands/pending", headers=dev["headers"]).json()
    script = next(c for c in cmds["items"] if c["type"] == "script.run")
    payload = json.loads(script["payloadJson"])
    body = payload["body"]
    assert payload["language"] == "powershell" and "FenrirBackupAgent" in body
    token = body.split("$Token  = '")[1].split("'")[0] if "$Token  = '" in body else None
    assert token, body[:400]
    agent_id, _ = agent_enroll(client, token)
    assert client.get(f"/api/console/backup/agents?deviceId={dev['deviceId']}", headers=admin).json()[0]["id"] == agent_id
    # The pushed link is single use.
    r = client.post("/backup/api/agent/enroll", json={"protocol": 1, "token": token, "hostname": "X", "machine_id": "x2",
                                                      "role": "server", "os": {}, "agent_version": "",
                                                      "public_key": base64.b64encode(b"z" * 32).decode()})
    assert r.status_code == 403


def test_scheduler_ticks_queue_due_plans_and_raise_overdue(client, admin, tenant):
    from datetime import timedelta

    from fenrir_cloud.db import session_factory
    from fenrir_cloud.models import Alert, BackupJob, ImageBackupPlan, utcnow

    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    plan_id = client.post("/api/console/backup/plans", headers=admin, json={
        "name": "Hourly", "agentId": agent_id, "repositoryId": repo_id, "job": {"type": "backup_system"},
        "schedule": {"type": "interval", "hours": 1}}).json()["id"]
    with session_factory()() as db:
        plan = db.get(ImageBackupPlan, plan_id)
        plan.next_run_at = utcnow() - timedelta(minutes=1)
        plan.created_at = utcnow() - timedelta(days=4)
        db.commit()
        bk.tick(db)
        bk.tick(db)  # still running: no second job
        assert db.query(BackupJob).filter(BackupJob.plan_id == plan_id).count() == 1
        bk.hourly(db)
        assert any(a.rule_id == bk.RULE_OVERDUE for a in db.query(Alert).all())
        bk.hourly(db)  # deduplicated
        assert sum(a.rule_id == bk.RULE_OVERDUE for a in db.query(Alert).all()) == 1
