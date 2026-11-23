"""Device backup (fenrir-backup-agent): enrolment, jobs, repositories, the ransomware guard and restores."""

import base64

import pytest
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


def heartbeat(client, h, running=None, caps=CAPS, **inventory):
    r = client.post("/backup/api/agent/heartbeat", headers=h, json={
        "inventory": {"hostname": "M-1", "os": {"family": "windows"}, "agent_version": "0.1.0", "capabilities": caps,
                      **inventory},
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
            "keep_last": 3, "keep_hourly": 0, "keep_daily": 0, "keep_weekly": 0, "keep_monthly": 0, "keep_yearly": 0},
        "dry_run": False}
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
    disks = [{"path": r"\\.\PhysicalDrive0", "size": 1 << 40, "model": "", "system": True},
             {"path": r"\\.\PhysicalDrive1", "size": 1 << 40, "model": "", "system": False}]
    heartbeat(client, h, disks=disks)
    ready_repo(client, admin, tenant, agent_id, h)
    client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                json={"kind": {"type": "backup_system"}, "repositoryId": client.get(
                    "/api/console/backup/repositories", headers=admin).json()[0]["id"]})
    job = heartbeat(client, h)["jobs"][0]
    im = image()
    # Application-aware (VSS component mode): the agent lists the writers' components; unknown fields are dropped.
    im["applications"] = [{"writer": "SqlServerWriter", "component": "SQL01\\sales", "caption": "sales",
                           "included": True, "evil": "x" * 10_000},
                          {"writer": "Exchange", "component": "Mailbox", "included": False, "note": "on D:"}]
    finish(client, h, job["id"], images=[im])
    listed = client.get("/api/console/backup/images", headers=admin).json()
    apps = next(i for i in listed if i["imageId"] == im["image_id"])["applications"]
    assert [a["writer"] for a in apps] == ["SqlServerWriter", "Exchange"] and "evil" not in apps[0]
    assert apps[0]["included"] is True and apps[1]["note"] == "on D:"
    heartbeat(client, h, disks=disks)
    target = {"type": "disk", "device": r"\\.\PhysicalDrive1", "disk": 0, "confirm": r"\\.\PhysicalDrive1"}
    body = {"imageId": im["image_id"], "agentId": agent_id, "target": target}
    assert client.post("/api/console/backup/restores", headers=admin, json=body).json()["detail"] == "reauth_required"
    step = {**admin, "X-Fenrir-Reauth": client.post("/api/console/auth/reauth", headers=admin,
                                                    json={"password": ADMIN_PASSWORD}).json()["reauthToken"]}
    wrong = {**body, "target": {**target, "confirm": "PhysicalDrive1"}}
    assert client.post("/api/console/backup/restores", headers=step, json=wrong).status_code == 400
    system = {**body, "target": {"type": "disk", "device": r"\\.\PhysicalDrive0", "disk": 0, "confirm": r"\\.\PhysicalDrive0"}}
    assert "in use" in client.post("/api/console/backup/restores", headers=step, json=system).json()["detail"]
    assert client.post("/api/console/backup/restores", headers=step, json=body).status_code == 200
    spec = heartbeat(client, h)["jobs"][0]
    assert spec["kind"]["type"] == "restore" and spec["kind"]["target"]["confirm"] == target["device"]
    # Use the whole disk is on unless turned off (phase-5-grow-clone).
    assert spec["kind"]["target"]["grow"] is True


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
    # Frequent backups: minutes, from 5 minutes; hourly retention.
    assert bk.next_after({"type": "interval", "hours": 0, "minutes": 15}, 100) == 100 + 900
    bk.validate_schedule({"type": "interval", "hours": 0, "minutes": 5})
    for bad in ({"type": "interval", "hours": 0, "minutes": 4}, {"type": "interval", "hours": 1, "minutes": 60},
                {"type": "interval", "hours": 0}):
        with pytest.raises(ValueError):
            bk.validate_schedule(bad)
    assert bk.validate_retention({"keep_hourly": 24})["keep_hourly"] == 24
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


def test_browse_and_restore_files(client, admin, tenant):
    from datetime import timedelta

    from fenrir_cloud.db import session_factory
    from fenrir_cloud.models import BackupJob, utcnow

    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    caps = CAPS + ["restore_files"]
    heartbeat(client, h, caps=caps)
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
    job = heartbeat(client, h, caps=caps)["jobs"][0]
    im = image()
    finish(client, h, job["id"], images=[im])
    assert heartbeat(client, h, caps=caps)["poll_seconds"] == bk.POLL_SECONDS

    # Volumes, then a folder; the machine polls every second meanwhile.
    r = client.post(f"/api/console/backup/images/{im['image_id']}/browse", headers=admin, json={})
    assert r.status_code == 200 and r.json()["agentId"] == agent_id, r.text
    hb = heartbeat(client, h, caps=caps)
    assert hb["poll_seconds"] == 1
    spec = hb["jobs"][0]
    assert spec["kind"] == {"type": "browse_files", "image_id": im["image_id"], "volume": None, "path": "/"}
    assert spec["repository"]["sealed_secret"] == SEALED
    finish(client, h, spec["id"], result={"volumes": [{"disk": 0, "partition": 3, "filesystem": "ntfs", "browsable": True}]})
    r = client.post(f"/api/console/backup/images/{im['image_id']}/browse", headers=admin,
                    json={"disk": 0, "partition": 3, "path": "/Users/anna"})
    spec = heartbeat(client, h, caps=caps)["jobs"][0]
    assert spec["kind"]["volume"] == {"disk": 0, "partition": 3} and spec["kind"]["path"] == "/Users/anna"
    finish(client, h, spec["id"], result={"listing": {"path": "/Users/anna", "entries": [{"name": "report.txt"}]}})
    assert client.get(f"/api/console/backup/jobs/{r.json()['id']}", headers=admin).json()["result"]["listing"]["entries"]
    assert client.post(f"/api/console/backup/images/{im['image_id']}/browse", headers=admin,
                       json={"disk": 0, "partition": 3, "path": "/Users/../Windows"}).status_code == 400
    heartbeat(client, h, caps=caps)  # drain the queue

    # Restore with "keep both" is ordinary; overwriting needs destructive rights and a password check.
    body = {"disk": 0, "partition": 3, "paths": ["/Users/anna/report.txt"], "target": "C:\\Restored", "conflict": "rename"}
    r = client.post(f"/api/console/backup/images/{im['image_id']}/restore-files", headers=admin, json=body)
    assert r.status_code == 200, r.text
    spec = heartbeat(client, h, caps=caps)["jobs"][0]
    assert spec["kind"] == {"type": "restore_files", "image_id": im["image_id"], "volume": {"disk": 0, "partition": 3},
                            "paths": ["/Users/anna/report.txt"], "target": "C:\\Restored", "keep_structure": True,
                            "conflict": "rename"}
    finish(client, h, spec["id"])
    over = client.post(f"/api/console/backup/images/{im['image_id']}/restore-files", headers=admin, json={**body, "conflict": "overwrite"})
    assert over.status_code == 403 and over.json()["detail"] == "reauth_required"

    # An agent without file restore is told to update.
    heartbeat(client, h, caps=CAPS)
    assert "too old" in client.post(f"/api/console/backup/images/{im['image_id']}/browse", headers=admin, json={}).json()["detail"]

    # File names in listings are dropped after a day; other results stay.
    with session_factory()() as db:
        for j in db.query(BackupJob).all():
            j.finished_at = utcnow() - timedelta(days=2)
        db.commit()
        assert bk.purge_listings(db) == 2
        kinds = {j.kind["type"]: j.result for j in db.query(BackupJob).all() if j.kind["type"] in ("browse_files",)}
        assert kinds == {"browse_files": None}


def _fake_builds(tmp_path, monkeypatch, which=None):
    """Fake security-agent release files and backup agent builds for installer tests."""
    from fenrir_cloud import deployment_installers as installers

    rel = tmp_path / "rel"
    rel.mkdir()
    monkeypatch.setattr(installers, "DOWNLOADS", rel)
    for arch in ("amd64", "arm64"):
        (rel / f"fenrir-agent-linux-{arch}").write_bytes(b"\x7fELF-fenrir-" + arch.encode())
        (rel / f"fenrir-agent-darwin-{arch}").write_bytes(b"\xcf\xfa-fenrir-" + arch.encode())
    agents = tmp_path / "backup-builds"
    monkeypatch.setenv("FENRIR_BACKUP_AGENTS_DIR", str(agents))
    for t in bk.ALL_TARGETS.values():
        if which is None or t.triple in which:
            (agents / t.triple).mkdir(parents=True, exist_ok=True)
            (agents / t.triple / t.file).write_bytes(b"backup-agent-" + t.triple.encode())
    return installers


def test_all_in_one_installers_carry_the_backup_agent(client, admin, tenant, tmp_path, monkeypatch):
    import shutil
    import subprocess

    installers = _fake_builds(tmp_path, monkeypatch, which={"x86_64-unknown-linux-musl", "aarch64-apple-darwin"})
    with_backup = client.post("/api/console/deploy-scripts", headers=admin, json={"tenantId": tenant["id"]}).json()
    assert with_backup["includeBackup"] is True
    sh = client.get("/api/v1/install/linux.sh", headers={"X-Fenrir-Token": with_backup["token"]}).text
    assert "install_fenrir_backup" in sh and '--server "${base%/}/backup" --token "$token" --role auto' in sh
    assert "fenrir-backup-agent.service" in sh
    assert hashlib_sha("backup-agent-x86_64-unknown-linux-musl") in sh
    assert "no backup agent for $(uname -m) yet" in sh  # no arm64 build on this server: skipped, not failed
    mac = client.get("/api/v1/install/macos.sh", headers={"X-Fenrir-Token": with_backup["token"]}).text
    assert "uk.fenrir-backup.agent" in mac and hashlib_sha("backup-agent-aarch64-apple-darwin") in mac
    if shutil.which("sh"):
        for script in (sh, mac):
            assert subprocess.run(["sh", "-n"], input=script, text=True).returncode == 0

    without = client.post("/api/console/deploy-scripts", headers=admin,
                          json={"tenantId": tenant["id"], "includeBackup": False}).json()
    assert without["includeBackup"] is False
    assert "install_fenrir_backup" not in client.get("/api/v1/install/linux.sh", headers={"X-Fenrir-Token": without["token"]}).text
    # Windows: setup reads "backup=off" from its embedded settings.
    (installers.DOWNLOADS / "windows").mkdir()
    import hashlib
    import json

    (installers.DOWNLOADS / "windows" / "FenrirSetup.exe").write_bytes(b"MZ-setup")
    (installers.DOWNLOADS / "windows" / "build.json").write_text(json.dumps({"sha256": hashlib.sha256(b"MZ-setup").hexdigest()}))
    tail = len(installers.WINDOWS_CONFIG_MAGIC) + 4
    on = client.get("/api/v1/install/windows.exe", headers={"X-Fenrir-Token": with_backup["token"]}).content
    off = client.get("/api/v1/install/windows.exe", headers={"X-Fenrir-Token": without["token"]}).content
    assert on.endswith(installers.WINDOWS_CONFIG_MAGIC) and not on[:-tail].endswith(b"backup=off")
    assert off[:-tail].endswith(b"\nbackup=off")


def hashlib_sha(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode()).hexdigest()


def test_bundled_backup_agent_enrols_with_the_deployment_token_and_links_to_its_device(client, admin, tenant):
    made = client.post("/api/console/deploy-scripts", headers=admin, json={"tenantId": tenant["id"]}).json()
    # The backup agent usually enrols first (it is installed in the same run); the device appears just after.
    agent_id, _ = agent_enroll(client, made["token"], machine="acme-ws-01")
    rows = client.get(f"/api/console/backup/agents?tenantId={tenant['id']}", headers=admin).json()
    assert [r["id"] for r in rows] == [agent_id] and rows[0]["deviceId"] is None
    dev = enroll(client, admin, tenant, hostname="ACME-WS-01")
    from fenrir_cloud.db import session_factory

    with session_factory()() as db:
        assert bk.link_devices(db) == 1
    assert client.get(f"/api/console/backup/agents?deviceId={dev['deviceId']}", headers=admin).json()[0]["id"] == agent_id
    # The deployment token is not used up by the backup agent.
    from fenrir_cloud.models import EnrollmentToken

    with session_factory()() as db:
        assert db.get(EnrollmentToken, made["id"]).uses <= 1

    # A deployment without backup refuses it; a revoked token too.
    off = client.post("/api/console/deploy-scripts", headers=admin, json={"tenantId": tenant["id"], "includeBackup": False}).json()
    body = {"protocol": 1, "token": off["token"], "hostname": "X", "machine_id": "x", "role": "server", "os": {},
            "agent_version": "", "public_key": base64.b64encode(b"q" * 32).decode()}
    assert client.post("/backup/api/agent/enroll", json=body).status_code == 409
    with session_factory()() as db:
        db.get(EnrollmentToken, made["id"]).revoked = True
        db.commit()
    assert client.post("/backup/api/agent/enroll", json={**body, "token": made["token"]}).status_code == 403


def test_agent_builds_download_without_an_agent_token(client, tmp_path, monkeypatch):
    """Installers fetch the agent before it has enrolled; the file is checked against its SHA-256."""
    monkeypatch.setenv("FENRIR_BACKUP_AGENTS_DIR", str(tmp_path))
    t = bk.ALL_TARGETS["x86_64-unknown-linux-musl"]
    (tmp_path / t.triple).mkdir()
    (tmp_path / t.triple / t.file).write_bytes(b"agent")
    assert client.get(f"/backup/agent/{t.triple}/{t.file}").content == b"agent"
    assert client.get("/backup/agent/x86_64-unknown-linux-musl/..%2f..%2fetc").content != b"agent"
    assert client.get("/backup/agent/x86_64-unknown-linux-musl/other").status_code == 404


def test_nas_gateway_routes_relays_and_keeps_retention_on_the_gateway(client, admin, tenant):
    import threading

    e = link(client, admin, tenant)
    gw_id, gw_h = agent_enroll(client, e["token"], machine="nas-gw")
    caps = CAPS + ["restore_files", "gateway"]
    hb = lambda h, **kw: client.post("/backup/api/agent/heartbeat", headers=h, json={"inventory": {"hostname": "x", "capabilities": caps, **kw}}).json()
    hb(gw_h, gateway_addresses=["192.168.1.20:8475"])
    repo_id = ready_repo(client, admin, tenant, gw_id, gw_h)
    hb(gw_h, gateway_addresses=["192.168.1.20:8475"])
    remote_id, remote_h = agent_enroll(client, e["token"], machine="laptop", key=base64.b64encode(b"r" * 32).decode())
    hb(remote_h)

    # Through the gateway needs a gateway first; the gateway must have direct access.
    r = client.post(f"/api/console/backup/repositories/{repo_id}/access", headers=admin,
                    json={"agentId": remote_id, "sealed": SEALED, "viaGateway": True})
    assert r.status_code == 400 and "gateway" in r.json()["detail"]
    assert client.post(f"/api/console/backup/repositories/{repo_id}/gateway", headers=admin,
                       json={"agentId": remote_id}).status_code == 400
    r = client.post(f"/api/console/backup/repositories/{repo_id}/gateway", headers=admin,
                    json={"agentId": gw_id, "port": 8475, "address": "backup.example.com:18475"})
    assert r.status_code == 200, r.text
    assert client.post(f"/api/console/backup/repositories/{repo_id}/access", headers=admin,
                       json={"agentId": remote_id, "sealed": SEALED, "viaGateway": True}).status_code == 200

    # The gateway learns what to serve and to whom; the client how to reach it.
    cfg = hb(gw_h, gateway_addresses=["192.168.1.20:8475"])["gateway"]
    assert cfg["listen_port"] == 8475
    assert cfg["repositories"][0]["repository_id"] == repo_id
    assert cfg["repositories"][0]["clients"] == [{"agent_id": remote_id, "public_key": base64.b64encode(b"r" * 32).decode()}]
    assert hb(remote_h)["gateway"] is None
    client.post(f"/api/console/backup/agents/{remote_id}/jobs", headers=admin,
                json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
    spec = hb(remote_h)["jobs"][0]
    assert spec["repository"]["gateway"] == {"agent_id": gw_id, "public_key": base64.b64encode(b"k" * 32).decode(),
                                             "addresses": ["backup.example.com:18475", "192.168.1.20:8475"], "relay": True}
    repo = [x for x in client.get("/api/console/backup/repositories", headers=admin).json() if x["id"] == repo_id][0]
    assert repo["gateway"]["name"] and repo["maintenanceAgentId"] == gw_id
    assert {a["id"]: a["viaGateway"] for a in repo["agents"]} == {gw_id: False, remote_id: True}

    # A plan backup by the client: retention runs on the gateway (the client cannot delete through it).
    plan = client.post("/api/console/backup/plans", headers=admin, json={
        "name": "Laptop", "agentId": remote_id, "repositoryId": repo_id, "job": {"type": "backup_system"},
        "schedule": {"type": "manual"}, "retention": {"keep_last": 2}}).json()["id"]
    finish(client, remote_h, spec["id"])
    client.post(f"/api/console/backup/plans/{plan}/run", headers=admin)
    job = hb(remote_h)["jobs"][0]
    finish(client, remote_h, job["id"], images=[image(machine="laptop")])
    assert hb(remote_h)["jobs"] == []
    assert hb(gw_h)["jobs"][0]["kind"]["type"] == "apply_retention"

    # Relay: the client's message reaches the gateway, the gateway's answer comes back, byte for byte.
    got = {}

    def send():
        got["r"] = client.post(f"/backup/api/agent/relay/{gw_id}", headers=remote_h, content=b"\x01sealed-request")

    t = threading.Thread(target=send)
    t.start()
    nxt = None
    for _ in range(10):
        nxt = client.get("/backup/api/agent/relay/next", headers=gw_h)
        if nxt.status_code == 200:
            break
    assert nxt.status_code == 200 and nxt.content == b"\x01sealed-request"
    assert client.post(f"/backup/api/agent/relay/reply/{nxt.headers['X-Relay-Id']}", headers=gw_h,
                       content=b"\x01sealed-answer").status_code == 204
    t.join(10)
    assert got["r"].status_code == 200 and got["r"].content == b"\x01sealed-answer"
    # Machines not routed through this gateway may not use it.
    other_id, other_h = agent_enroll(client, e["token"], machine="other", key=base64.b64encode(b"o" * 32).decode())
    assert client.post(f"/backup/api/agent/relay/{gw_id}", headers=other_h, content=b"x").status_code == 403
    # The gateway cannot be removed from under its clients.
    assert client.post(f"/api/console/backup/repositories/{repo_id}/gateway", headers=admin, json={}).status_code == 400
    assert client.delete(f"/api/console/backup/repositories/{repo_id}/access/{gw_id}", headers=admin).status_code == 400


def test_boot_test_on_a_hyperv_host_keeps_the_vm_when_asked(client, admin, tenant):
    e = link(client, admin, tenant)
    src_id, src_h = agent_enroll(client, e["token"], machine="pm-acer")
    heartbeat(client, src_h)
    repo_id = ready_repo(client, admin, tenant, src_id, src_h)
    client.post(f"/api/console/backup/agents/{src_id}/jobs", headers=admin, json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
    job = heartbeat(client, src_h)["jobs"][0]
    im = image(machine="pm-acer")
    finish(client, src_h, job["id"], images=[im])

    hv_id, hv_h = agent_enroll(client, e["token"], machine="hv01", key=base64.b64encode(b"h" * 32).decode())
    kept = {"session_id": str(uuid.uuid4()), "image_id": im["image_id"], "started_unix": 1_790_000_000, "vnc_port": 0, "forwards": {}}
    client.post("/backup/api/agent/heartbeat", headers=hv_h, json={"inventory": {
        "hostname": "HV01", "capabilities": ["boot_hyperv", "restore_hyperv"], "running_vms": [kept]}})
    hv = [a for a in client.get("/api/console/backup/agents", headers=admin).json() if a["id"] == hv_id][0]
    assert hv["runningVms"] == [{"sessionId": kept["session_id"], "imageId": im["image_id"], "startedUnix": 1_790_000_000, "vncPort": 0}]

    url = f"/api/console/backup/images/{im['image_id']}/boot-check"
    # Not given access yet: refused until it is (the console gives access first, in the same dialog).
    assert "no access" in client.post(url, headers=admin, json={"agentId": hv_id, "keepRunning": True}).json()["detail"]
    assert client.post(f"/api/console/backup/repositories/{repo_id}/access", headers=admin,
                       json={"agentId": hv_id, "sealed": SEALED}).status_code == 200
    assert client.post(url, headers=admin, json={"agentId": hv_id, "keepRunning": True, "directory": "relative"}).status_code == 400
    r = client.post(url, headers=admin, json={"agentId": hv_id, "keepRunning": True, "directory": "D:\\Fenrir checks"})
    assert r.status_code == 200, r.text
    spec = client.post("/backup/api/agent/heartbeat", headers=hv_h, json={"inventory": {
        "hostname": "HV01", "capabilities": ["boot_hyperv", "restore_hyperv"]}}).json()["jobs"][0]
    assert spec["kind"] == {"type": "boot_check", "image_id": im["image_id"], "keep_running": True, "memory_mb": None,
                            "cpus": None, "directory": "D:\\Fenrir checks"}


def test_recovery_media_is_personalised_and_enrols_recovery_sessions_only(client, admin, tenant, tmp_path, monkeypatch):
    """Recovery media (Fenrir-Backup phase 2): the ISO carries this server's settings in its placeholder block and
    nothing else changes; recovery links enrol recovery sessions only; their own medium is never a restore target;
    they raise no offline alerts and are removed after a week."""
    import json
    from datetime import timedelta

    from fenrir_cloud.db import session_factory
    from fenrir_cloud.models import BackupAgent, utcnow

    monkeypatch.setenv("FENRIR_BACKUP_AGENTS_DIR", str(tmp_path))
    (tmp_path / "recovery").mkdir()
    iso = bytes((i * 2654435761 >> 13) & 0xFF for i in range(3 << 20))
    at = (1 << 20) - 2048  # across a 1 MiB read boundary
    placeholder = bk.RECOVERY_MARKER + b" " * (4096 - len(bk.RECOVERY_MARKER))
    iso = iso[:at] + placeholder + iso[at + 4096:]
    (tmp_path / "recovery" / "fenrir-recovery.iso").write_bytes(iso)
    assert client.get("/api/console/backup/recovery-media", headers=admin).json() == {"available": True, "size": len(iso)}

    e = link(client, admin, tenant, role="recovery", days=30, label="stick")
    assert e["recovery"]["available"] is True and "links" not in e
    path = e["recovery"]["iso"].split("/backup/", 1)[1]
    got = client.get(f"/backup/{path}")
    assert got.status_code == 200
    body = got.content
    assert len(body) == len(iso) and body[:at] == iso[:at] and body[at + 4096:] == iso[at + 4096:]
    block = body[at:at + 4096]
    assert block.startswith(bk.RECOVERY_MARKER)
    cfg = json.loads(block[len(bk.RECOVERY_MARKER):].strip())
    assert cfg["token"] == e["token"] and cfg["server"].endswith("/backup") and list(cfg) == ["server", "pin", "token", "expires"]
    settings = client.get("/backup/" + e["recovery"]["settings"].split("/backup/", 1)[1]).json()
    assert settings == cfg

    # An ordinary link gives no recovery media; links and roles must match.
    normal = link(client, admin, tenant)
    assert client.get(f"/backup/recovery/{normal['token']}/fenrir-recovery.iso").status_code == 404
    key = base64.b64encode(b"r" * 32).decode()
    for token, role in ((e["token"], "server"), (normal["token"], "recovery")):
        r = client.post("/backup/api/agent/enroll", json={
            "protocol": 1, "token": token, "hostname": "recovery-abc", "machine_id": "recovery:abc", "role": role,
            "os": {"family": "linux"}, "agent_version": "0.1.0", "public_key": key})
        assert r.status_code == 403, r.text
    rid, rh = agent_enroll(client, e["token"], machine="recovery:abc", key=key, role="recovery")
    heartbeat(client, rh, caps=["restore_disk", "restore_files", "verify"], firmware="uefi", disks=[
        {"path": "/dev/sda", "size": 1 << 30, "model": "stick", "system": False, "in_use": True},
        {"path": "/dev/nvme0n1", "size": 1 << 40, "model": "new", "system": False}])

    # Its own boot medium is refused as a target.
    owner_id, oh = agent_enroll(client, normal["token"], machine="m-src")
    heartbeat(client, oh)
    repo = ready_repo(client, admin, tenant, owner_id, oh)
    client.post(f"/api/console/backup/agents/{owner_id}/jobs", headers=admin, json={"kind": {"type": "backup_system"}, "repositoryId": repo})
    job = heartbeat(client, oh)["jobs"][0]
    im = image(machine="m-src")
    finish(client, oh, job["id"], images=[im])
    assert client.post(f"/api/console/backup/repositories/{repo}/access", headers=admin,
                       json={"agentId": rid, "sealed": SEALED}).status_code == 200
    step = {**admin, "X-Fenrir-Reauth": client.post("/api/console/auth/reauth", headers=admin,
                                                    json={"password": ADMIN_PASSWORD}).json()["reauthToken"]}
    def restore(dev):
        return client.post("/api/console/backup/restores", headers=step, json={
            "imageId": im["image_id"], "agentId": rid, "target": {"type": "disk", "device": dev, "disk": 0, "confirm": dev}})
    assert "in use" in restore("/dev/sda").json()["detail"]
    assert restore("/dev/nvme0n1").status_code == 200

    # A week later: removed, and never an offline alert.
    with session_factory()() as db:
        a = db.get(BackupAgent, rid)
        a.last_seen_at = utcnow() - timedelta(days=8)
        db.commit()
        bk.check_health(db)
        db.commit()
        assert bk.expire_recovery_sessions(db) == 1
        assert db.get(BackupAgent, rid).revoked
    alerts = client.get("/api/console/alerts", headers=admin).json()
    rows = alerts.get("items", alerts) if isinstance(alerts, dict) else alerts
    assert not any("recovery-abc" in json.dumps(x).lower() and "offline" in json.dumps(x).lower() for x in rows)


def test_s3_repositories_with_object_lock(client, admin, tenant):
    """S3 repositories (Fenrir-Backup phase-4-storage): settings checked, sent with jobs (keys sealed per agent like a
    share sign-in), maintenance must run more often than the lock, no NAS gateway."""
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)
    s3 = {"endpoint": "https://s3.eu-west-2.amazonaws.com", "region": "eu-west-2", "lock_mode": "compliance", "lock_days": 30}

    def body(path, s3v, keys=True):
        return {"name": "Cloud", "path": path, "repoUuid": str(uuid.uuid4()), "initAgentId": agent_id,
                "share_auth": "password" if keys else "none", "share_user": "AKID", "s3": s3v,
                "access": [{"agentId": agent_id, "sealed": SEALED, "sealedShare": SEALED if keys else None}]}
    for path, s3v, keys, why in [
        ("s3://backups/office", None, True, "endpoint"),
        ("s3://Bad_Bucket/x", s3, True, "bucket name"),
        ("s3://backups/office", s3, False, "access key"),
        ("s3://backups/office", {**s3, "lock_days": 5}, True, "more often"),
        ("D:\\Backups", s3, True, "s3://"),
        ("azure://Bad--Name/x", s3, True, "container name"),
        ("azure://backups/x", {**s3, "endpoint": "ftp://x"}, True, "endpoint"),
    ]:
        r = client.post("/api/console/backup/repositories", headers=admin, json=body(path, s3v, keys))
        assert r.status_code == 400 and why in r.json()["detail"], (path, r.text)
    r = client.post("/api/console/backup/repositories", headers=admin, json=body("s3://backups/office", s3))
    assert r.status_code == 200, r.text
    repo = r.json()["id"]
    spec = heartbeat(client, h)["jobs"][0]
    assert spec["repository"]["path"] == "s3://backups/office"
    assert spec["repository"]["s3"] == {**s3, "path_style": False}
    assert spec["repository"]["sealed_share"] == SEALED
    finish(client, h, spec["id"], repo_uuid=str(uuid.uuid4()))
    listed = client.get("/api/console/backup/repositories", headers=admin).json()
    assert next(x for x in listed if x["id"] == repo)["s3"]["lock_days"] == 30

    m = f"/api/console/backup/repositories/{repo}/maintenance"
    assert client.post(m, headers=admin, json={"pruneEveryDays": 0}).status_code == 400
    assert client.post(m, headers=admin, json={"pruneEveryDays": 14}).status_code == 200
    r = client.post(f"/api/console/backup/repositories/{repo}/gateway", headers=admin, json={"agentId": agent_id, "port": 0})
    assert r.status_code == 400
    r = client.post(f"/api/console/backup/agents/{agent_id}/check-access", headers=admin,
                    json={"path": "s3://backups/new", "sealedShare": SEALED, "s3": s3})
    assert r.status_code == 200, r.text
    kind = heartbeat(client, h)["jobs"][0]["kind"]
    assert kind["type"] == "check_access" and kind["s3"]["lock_mode"] == "compliance"
    # Azure Blob: the same settings; the endpoint may carry the account (Azurite).
    azure = {**s3, "endpoint": "http://127.0.0.1:10000/devstoreaccount1"}
    r = client.post("/api/console/backup/repositories", headers=admin, json=body("azure://backups/office", azure))
    assert r.status_code == 200, r.text
