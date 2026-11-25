"""Device backup (fenrir-backup-agent): enrolment, jobs, repositories, the ransomware guard and restores."""

import base64

import pytest
import uuid

from conftest import ADMIN_PASSWORD, enroll, login

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


def reauth(client, admin):
    return client.post("/api/console/auth/reauth", headers=admin, json={"password": ADMIN_PASSWORD}).json()["reauthToken"]


def unlock(client, admin, h, repo_id, agent_id, caps=CAPS, base=None):
    """Unlock a repository's images for this session: password check, then the passphrase tried on a machine."""
    r = client.post(f"/api/console/backup/repositories/{repo_id}/unlock",
                    headers={**admin, "X-Fenrir-Reauth": reauth(client, admin)}, json={"agentId": agent_id, "sealed": SEALED})
    assert r.status_code == 200, r.text
    spec = next(j for j in heartbeat(client, h, caps=caps)["jobs"] if j["id"] == r.json()["id"])
    assert spec["kind"] == {"type": "list_images"} and spec["repository"]["sealed_secret"] == SEALED
    finish(client, h, spec["id"])
    out = client.get(f"/api/console/backup/unlock/{spec['id']}", headers=admin).json()
    assert out["state"] == "unlocked", out
    base = base or admin
    return {**base, "X-Fenrir-Unlock": ",".join(x for x in (base.get("X-Fenrir-Unlock"), out["token"]) if x)}


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
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
    job = heartbeat(client, h)["jobs"][0]
    im = image()
    # Application-aware (VSS component mode): the agent lists the writers' components; unknown fields are dropped.
    im["applications"] = [{"writer": "SqlServerWriter", "component": "SQL01\\sales", "caption": "sales",
                           "included": True, "evil": "x" * 10_000},
                          {"writer": "Exchange", "component": "Mailbox", "included": False, "note": "on D:"}]
    finish(client, h, job["id"], images=[im])
    # Locked until unlocked in this session: nothing listed, restores refused.
    assert client.get("/api/console/backup/images", headers=admin).json() == []
    locked = client.post("/api/console/backup/restores", headers=admin, json={"imageId": im["image_id"], "agentId": agent_id})
    assert locked.status_code == 403 and locked.json()["detail"] == "repository_locked"
    admin = unlock(client, admin, h, repo_id, agent_id)
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


def test_restore_as_files_for_qemu_virtualbox_or_vmware(client, admin, tenant):
    """Disk files and a VM definition for another hypervisor: only machines that report restore_vm_files, a known
    format, and a VM name safe for file names and scripts."""
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
    im = image()
    finish(client, h, heartbeat(client, h)["jobs"][0]["id"], images=[im])
    admin = unlock(client, admin, h, repo_id, agent_id)
    go = lambda target: client.post("/api/console/backup/restores", headers=admin,  # noqa: E731
                                    json={"imageId": im["image_id"], "agentId": agent_id, "target": target})
    target = {"type": "vm_files", "format": "qcow2", "name": "PM-ACER restored", "directory": "/srv/restores"}
    # An agent that does not report the capability (an older version) is refused.
    assert "cannot perform" in go(target).json()["detail"]
    heartbeat(client, h, caps=CAPS + ["restore_vm_files"])
    for bad_target in ({**target, "format": "ova"}, {**target, "name": "x; rm -rf /"}, {**target, "name": " lead"},
                       {**target, "directory": ""}):
        assert go(bad_target).status_code == 400, bad_target
    for fmt in ("qcow2", "vdi", "vmdk"):
        assert go({**target, "format": fmt}).status_code == 200
        spec = heartbeat(client, h, caps=CAPS + ["restore_vm_files"])["jobs"][0]
        assert spec["kind"]["target"] == {**target, "format": fmt}
        finish(client, h, spec["id"])


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
    admin = unlock(client, admin, h, repo_id, agent_id, caps=caps)

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
    admin = unlock(client, admin, src_h, repo_id, src_id)

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
    admin = unlock(client, admin, oh, repo, owner_id)
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


def test_offsite_copy_after_each_plan_backup(client, admin, tenant):
    """A plan's off-site copy (Fenrir-Backup offsite-copy.md): after each backup the machine copies the new images
    to the second repository, with both repositories' access sealed to it; the copies are listed there."""
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)
    local = ready_repo(client, admin, tenant, agent_id, h)
    offsite = ready_repo(client, admin, tenant, agent_id, h)
    body = {"name": "Nightly", "agentId": agent_id, "repositoryId": local, "job": {"type": "backup_system"},
            "schedule": {"type": "manual"}}
    assert client.post("/api/console/backup/plans", headers=admin, json={**body, "copyToRepositoryId": local}).status_code == 400
    r = client.post("/api/console/backup/plans", headers=admin, json={**body, "copyToRepositoryId": offsite})
    assert r.status_code == 200, r.text
    plan_id = r.json()["id"]
    assert client.get("/api/console/backup/plans", headers=admin).json()[0]["copyToRepositoryId"] == offsite

    assert client.post(f"/api/console/backup/plans/{plan_id}/run", headers=admin).status_code == 200
    job = heartbeat(client, h)["jobs"][0]
    im = image()
    finish(client, h, job["id"], images=[im])
    copy = heartbeat(client, h)["jobs"][0]
    assert copy["kind"] == {"type": "copy_images", "target_repository_id": offsite, "images": [im["image_id"]],
                            "full_verify": False}
    assert copy["repository"]["repository_id"] == local and copy["copy_target"]["repository_id"] == offsite
    assert copy["copy_target"]["sealed_secret"] == SEALED
    finish(client, h, copy["id"], images=[{**im, "image_id": str(uuid.uuid4())}])
    assert client.get(f"/api/console/backup/images?repositoryId={offsite}", headers=admin).status_code == 403
    admin = unlock(client, admin, h, offsite, agent_id)
    listed = client.get(f"/api/console/backup/images?repositoryId={offsite}", headers=admin).json()
    assert len(listed) == 1 and listed[0]["repositoryId"] == offsite

    r = client.patch(f"/api/console/backup/plans/{plan_id}", headers=admin, json={"copyToRepositoryId": None})
    assert r.status_code == 200
    assert client.get("/api/console/backup/plans", headers=admin).json()[0]["copyToRepositoryId"] is None


def test_move_from_fenrir_backup_existing_repository_and_plan_import(client, admin, tenant):
    """Moving from a standalone Fenrir-Backup server (backup/docs/design/migration.md): the repository is added as
    existing (the machine lists it and reports its ID), then the server's export recreates the plans."""
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)
    body = {"name": "Moved NAS", "path": "D:\\Backups", "existing": True, "initAgentId": agent_id,
            "access": [{"agentId": agent_id, "sealed": SEALED}]}
    r = client.post("/api/console/backup/repositories", headers=admin, json=body)
    assert r.status_code == 200, r.text
    repo_id = r.json()["id"]
    job = heartbeat(client, h)["jobs"][0]
    assert job["kind"] == {"type": "list_images"}, "nothing is created"
    real = str(uuid.uuid4())
    im = image()
    finish(client, h, job["id"], repo_uuid=real, images=[im])
    repo = next(x for x in client.get("/api/console/backup/repositories", headers=admin).json() if x["id"] == repo_id)
    assert repo["status"] == "ready"
    seen = unlock(client, admin, h, repo_id, agent_id)
    assert [i["imageId"] for i in client.get(f"/api/console/backup/images?repositoryId={repo_id}", headers=seen).json()] \
        == [im["image_id"]], "its history came with it"
    # The same repository again is refused.
    r2 = client.post("/api/console/backup/repositories", headers=admin, json=body).json()["id"]
    finish(client, h, heartbeat(client, h)["jobs"][0]["id"], repo_uuid=real, images=[])
    dup = next(x for x in client.get("/api/console/backup/repositories", headers=admin).json() if x["id"] == r2)
    assert dup["status"] == "failed" and "already registered" in (dup.get("statusMessage") or dup.get("status_message") or "")

    export = {"format": "fenrir-backup-export", "version": 1, "repositories": [], "plans": [
        {"name": "Nightly", "machine_id": "m-1", "hostname": "web01", "repo_uuid": real,
         "job": {"type": "backup_system", "settings": {}}, "schedule": {"type": "interval", "hours": 0, "minutes": 30},
         "retention": {"keep_hourly": 24, "keep_daily": 7}, "enabled": True, "copy_to_repo_uuid": None},
        {"name": "Elsewhere", "machine_id": "not-here", "hostname": "db02", "repo_uuid": real,
         "job": {"type": "backup_system"}, "schedule": {"type": "manual"}, "retention": None, "enabled": True},
    ]}
    assert client.post("/api/console/backup/import", headers=admin, json={"export": {"format": "x"}}).status_code == 400
    r = client.post("/api/console/backup/import", headers=admin, json={"export": export})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["created"] == ["Nightly"]
    assert out["skipped"][0]["name"] == "Elsewhere" and "not enrolled" in out["skipped"][0]["reason"]
    plan = client.get("/api/console/backup/plans", headers=admin).json()[0]
    assert plan["schedule"]["minutes"] == 30 and plan["retention"]["keep_hourly"] == 24 and plan["repositoryId"] == repo_id
    # Importing again does not duplicate it.
    assert client.post("/api/console/backup/import", headers=admin, json={"export": export}).json()["created"] == []


def test_backup_agent_links_by_hardware_serial_when_host_names_are_ambiguous(client, admin, tenant):
    """Two devices with the same host name: the backup agent's hardware serial decides which is its machine, and a
    firmware placeholder serial does not count."""
    from fenrir_cloud.db import session_factory
    from fenrir_cloud.models import BackupAgent, Device

    enroll(client, admin, tenant, hostname="SHOP-PC", serial="CN-0X35B")
    b = enroll(client, admin, tenant, hostname="SHOP-PC", serial="PF2ABCDE")
    with session_factory()() as db:
        assert sum(1 for d in db.query(Device).all() if (d.hostname or "").upper() == "SHOP-PC") == 2
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"], machine="shop-pc")
    heartbeat(client, h, hostname="SHOP-PC", hardware_serial="To Be Filled By O.E.M.")
    with session_factory()() as db:
        assert bk.matching_device(db, db.get(BackupAgent, agent_id)) is None, "same name twice, no real serial"
    heartbeat(client, h, hostname="SHOP-PC", hardware_serial="pf2abcde")
    with session_factory()() as db:
        agent = db.get(BackupAgent, agent_id)
        assert bk.matching_device(db, agent) == b["deviceId"]
        agent.device_id = None
        db.commit()
        assert bk.link_devices(db) == 1
        assert db.get(BackupAgent, agent_id).device_id == b["deviceId"]


def test_files_download_through_the_server_encrypted_for_the_browser(client, admin, tenant, tmp_path, monkeypatch):
    """Download to the browser (backup/docs/design/file-download.md): the machine uploads ciphertext in
    offset-checked parts; the browser fetches it once the job has finished."""
    monkeypatch.setattr(bk, "downloads_dir", lambda: tmp_path)
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    caps = CAPS + ["restore_files"]
    heartbeat(client, h, caps=caps)
    ready_repo(client, admin, tenant, agent_id, h)
    repo_id = client.get("/api/console/backup/repositories", headers=admin).json()[0]["id"]
    client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
    im = image()
    finish(client, h, heartbeat(client, h, caps=caps)["jobs"][0]["id"], images=[im])
    admin = unlock(client, admin, h, repo_id, agent_id, caps=caps)
    url = f"/api/console/backup/images/{im['image_id']}/download-files"
    body = {"disk": 0, "partition": 2, "paths": ["/Users/ann"]}
    assert client.post(url, headers=admin, json={**body, "recipient": "bm90IGEga2V5"}).status_code == 400
    recipient = base64.b64encode(b"\x01" * 32).decode()
    r = client.post(url, headers=admin, json={**body, "recipient": recipient})
    assert r.status_code == 200, r.text
    job_id = r.json()["id"]
    spec = heartbeat(client, h, caps=caps)["jobs"][0]
    assert spec["kind"]["type"] == "download_files" and spec["kind"]["recipient"] == recipient
    up = f"/backup/api/agent/jobs/{job_id}/download?offset="
    raw = {**h, "Content-Type": "application/octet-stream"}
    assert client.post(up + "0", headers=raw, content=b"a" * 100).status_code == 200
    assert client.post(up + "0", headers=raw, content=b"a" * 100).status_code == 200  # retried
    assert client.post(up + "500", headers=raw, content=b"b" * 10).status_code == 409  # gap
    assert client.post(up + "100", headers=raw, content=b"b" * 10).status_code == 200
    assert client.get(f"/api/console/backup/jobs/{job_id}/download", headers=admin).status_code == 409
    finish(client, h, job_id, result={"download": {}})
    got = client.get(f"/api/console/backup/jobs/{job_id}/download", headers=admin)
    assert got.status_code == 200 and got.content == b"a" * 100 + b"b" * 10
    assert client.post(up + "110", headers=raw, content=b"c").status_code == 409, "finished"
    assert bk.purge_downloads(0) == 1


def test_backups_are_listed_by_device_and_open_only_after_an_unlock(client, admin, tenant, monkeypatch):
    """Images & restore lists backed-up machines; a machine's images open after the repository passphrase (tried
    on a machine with access, sealed to it in the browser) and a password check from the last two minutes."""
    import time as _time

    from fenrir_cloud.db import session_factory
    from fenrir_cloud.models import BackupJob

    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    for t, vm in ((0, None), (10, None), (20, "Web VM")):
        client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                    json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
        finish(client, h, heartbeat(client, h)["jobs"][0]["id"], images=[{**image(t=t), "vm_name": vm}])

    devices = client.get("/api/console/backup/image-devices", headers=admin).json()
    assert sorted((d["name"], d["images"]) for d in devices) == [("M-1", 2), ("Web VM", 1)]
    host = next(d for d in devices if d["name"] == "M-1")
    assert host["repositories"] == [{"id": repo_id, "name": "Office NAS", "images": 2, "unlocked": False}]
    assert client.get("/api/console/backup/images", headers=admin).json() == []
    assert client.get(f"/api/console/backup/agents/{agent_id}", headers=admin).json()["imageCount"] == 3

    url = f"/api/console/backup/repositories/{repo_id}/unlock"
    body = {"agentId": agent_id, "sealed": SEALED}
    assert client.post(url, headers=admin, json=body).json()["detail"] == "reauth_required"
    # A password check from more than two minutes ago is not enough.
    step = {**admin, "X-Fenrir-Reauth": reauth(client, admin)}
    real = _time.time
    monkeypatch.setattr(_time, "time", lambda: real() + 180)
    assert client.post(url, headers=step, json=body).json()["detail"] == "reauth_required"
    monkeypatch.setattr(_time, "time", real)

    # A wrong passphrase: the machine cannot open the repository; nothing unlocks.
    job_id = client.post(url, headers={**admin, "X-Fenrir-Reauth": reauth(client, admin)}, json=body).json()["id"]
    assert client.get(f"/api/console/backup/unlock/{job_id}", headers=admin).json() == {"state": "pending"}
    finish(client, h, heartbeat(client, h)["jobs"][0]["id"], state="failed", error="the repository passphrase given to this machine is wrong")
    out = client.get(f"/api/console/backup/unlock/{job_id}", headers=admin).json()
    assert out["state"] == "failed" and "passphrase" in out["error"]
    with session_factory()() as db:
        assert db.get(BackupJob, job_id).kind["unlock"] == {"user": db.get(BackupJob, job_id).kind["unlock"]["user"]}, \
            "the sealed passphrase is dropped once checked"

    # The right one.
    opened = unlock(client, admin, h, repo_id, agent_id)
    mine = client.get("/api/console/backup/images", headers=opened, params={"device": host["key"]}).json()
    assert len(mine) == 2 and all(i["vmName"] is None for i in mine)
    assert mine[0]["created"] > mine[1]["created"], "newest first by default"
    # A machine's backups, oldest first, as the machine's page lists them.
    oldest = client.get("/api/console/backup/images", headers=opened,
                        params={"device": host["key"], "order": "asc"}).json()
    assert [i["imageId"] for i in oldest] == [i["imageId"] for i in reversed(mine)]
    assert client.get("/api/console/backup/images", headers=opened, params={"order": "sideways"}).status_code == 400
    assert next(d for d in client.get("/api/console/backup/image-devices", headers=opened).json()
                if d["name"] == "M-1")["repositories"][0]["unlocked"] is True
    # The unlock belongs to this sign-in: another session of the same person does not carry it.
    elsewhere = {**login(client), "X-Fenrir-Unlock": opened["X-Fenrir-Unlock"]}
    assert client.get("/api/console/backup/images", headers=elsewhere).json() == []


def test_dedup_group_repositories_share_storage_and_key(client, admin, tenant):
    """Dedup groups (backup/docs/design/dedup-groups.md): members live in <group>/repos/<id>; a new member takes
    the group's key from a member the creating machine can open; never across customers."""
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)

    def create(uuid_, dedup, path="D:\\Group", agent=agent_id):
        return client.post("/api/console/backup/repositories", headers=admin, json={
            "name": f"R {uuid_[:4]}", "path": path, "repoUuid": uuid_, "dedup": dedup, "initAgentId": agent,
            "access": [{"agentId": agent, "sealed": SEALED}]})

    a_uuid = str(uuid.uuid4())
    r = create(a_uuid, "new")
    assert r.status_code == 200, r.text
    a = r.json()["id"]
    spec = heartbeat(client, h)["jobs"][0]
    assert spec["kind"] == {"type": "init_repository"} and "group_source" not in spec
    assert spec["repository"]["path"] == f"D:\\Group\\repos\\{a_uuid}"
    finish(client, h, spec["id"], repo_uuid=a_uuid)
    listed = next(x for x in client.get("/api/console/backup/repositories", headers=admin).json() if x["id"] == a)
    assert listed["dedupGroup"] == "D:\\Group"

    b_uuid = str(uuid.uuid4())
    assert create(b_uuid, a, path="E:\\Elsewhere").status_code == 400, "members share the group's folder"
    r = create(b_uuid, a)
    assert r.status_code == 200, r.text
    spec = heartbeat(client, h)["jobs"][0]
    assert spec["repository"]["path"] == f"D:\\Group\\repos\\{b_uuid}"
    assert spec["group_source"]["repository_id"] == a and spec["group_source"]["sealed_secret"] == SEALED
    finish(client, h, spec["id"], repo_uuid=b_uuid)

    # A machine without access to A: the job fails with the reason.
    other_id, oh = agent_enroll(client, e["token"], machine="m-2", key=base64.b64encode(b"o" * 32).decode())
    heartbeat(client, oh)
    assert create(str(uuid.uuid4()), a, agent=other_id).status_code == 200
    assert heartbeat(client, oh)["jobs"] == []
    jobs = client.get("/api/console/backup/jobs", headers=admin).json()
    failed = next(j for j in jobs if j["agentId"] == other_id)
    assert failed["state"] == "failed" and "dedup group" in failed["error"]

    # Another customer's repository cannot be joined.
    other_tenant = client.post("/api/console/tenants", json={"name": "Other Co", "template": "balanced"}, headers=admin).json()
    e2 = link(client, admin, other_tenant)
    t2, h2 = agent_enroll(client, e2["token"], machine="m-3", key=base64.b64encode(b"t" * 32).decode())
    heartbeat(client, h2)
    assert create(str(uuid.uuid4()), a, agent=t2).status_code == 400


def test_msp_dashboard_across_customers(client, admin, tenant):
    """The MSP view: every customer's backup health, worst first, and the machines that need attention."""
    from fenrir_cloud.db import session_factory
    from fenrir_cloud.models import ImageBackupPlan

    e = link(client, admin, tenant)
    ok_id, ok_h = agent_enroll(client, e["token"], machine="good")
    heartbeat(client, ok_h)
    repo = ready_repo(client, admin, tenant, ok_id, ok_h)
    bad_id, bad_h = agent_enroll(client, e["token"], machine="bad", key=base64.b64encode(b"b" * 32).decode())
    heartbeat(client, bad_h)
    assert client.post(f"/api/console/backup/repositories/{repo}/access", headers=admin,
                       json={"agentId": bad_id, "sealed": SEALED}).status_code == 200
    plan = lambda agent: client.post("/api/console/backup/plans", headers=admin, json={
        "name": f"Nightly {agent[:4]}", "agentId": agent, "repositoryId": repo, "job": {"type": "backup_system"},
        "schedule": {"type": "daily", "time": "01:00"}}).json()["id"]
    good_plan, bad_plan = plan(ok_id), plan(bad_id)
    for pid, h, state in ((good_plan, ok_h, "succeeded"), (bad_plan, bad_h, "failed")):
        assert client.post(f"/api/console/backup/plans/{pid}/run", headers=admin).status_code == 200
        job = heartbeat(client, h)["jobs"][0]
        finish(client, h, job["id"], state=state, **({"images": [image(machine="good")]} if state == "succeeded" else {"error": "disk read error"}))
    # A third machine with no plan, in another customer.
    other = client.post("/api/console/tenants", json={"name": "Zeta Ltd", "template": "balanced"}, headers=admin).json()
    e2 = link(client, admin, other)
    lonely, h3 = agent_enroll(client, e2["token"], machine="lonely", key=base64.b64encode(b"z" * 32).decode())
    heartbeat(client, h3)

    d = client.get("/api/console/backup/msp", headers=admin).json()
    by = {c["name"]: c for c in d["customers"]}
    acme, zeta = by["Acme Dental"], by["Zeta Ltd"]
    assert (acme["machines"], acme["protected"], acme["failing"]) == (2, 1, 1)
    assert acme["status"] == "critical" and zeta["status"] == "warning" and zeta["unprotected"] == 1
    assert [c["name"] for c in d["customers"]][:2] == ["Acme Dental", "Zeta Ltd"], "worst first"
    kinds = [(a["kind"], a["agentId"]) for a in d["attention"]]
    assert ("failing", bad_id) in kinds and ("no_plan", lonely) in kinds
    assert kinds.index(("failing", bad_id)) < kinds.index(("no_plan", lonely))
    assert d["totals"]["machines"] == 3 and d["totals"]["customers"] == 2
    assert d["trend"][-1]["succeeded"] == 1 and d["trend"][-1]["failed"] == 1
    assert d["totals"]["successRate7d"] == 50

    # The good plan last succeeded 3 days ago: at risk (a daily plan is overdue after two days).
    from datetime import timedelta
    from fenrir_cloud.models import BackupJob, utcnow
    with session_factory()() as db:
        for j in db.query(BackupJob).filter(BackupJob.plan_id == good_plan):
            j.finished_at = utcnow() - timedelta(days=3)
        db.get(ImageBackupPlan, good_plan).created_at = utcnow() - timedelta(days=10)
        db.commit()
    d = client.get("/api/console/backup/msp", headers=admin).json()
    assert {c["name"]: c for c in d["customers"]}["Acme Dental"]["atRisk"] == 1
    assert any(a["kind"] == "overdue" and a["agentId"] == ok_id for a in d["attention"])


def test_local_recovery_partition_jobs_and_enrolment_code(client, admin, tenant):
    """Local recovery (backup/docs/design/local-recovery.md): typed confirmation and a password check to repartition,
    a recovery-only code sent with each build (the previous one revoked), rebuilt after an agent update."""
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    caps = CAPS + ["local_recovery"]
    heartbeat(client, h, caps=caps)
    url = f"/api/console/backup/agents/{agent_id}/local-recovery"
    step = {**admin, "X-Fenrir-Reauth": reauth(client, admin)}
    assert client.post(url, headers=admin, json={"action": "install", "confirm": "M-1"}).json()["detail"] == "reauth_required"
    assert client.post(url, headers=step, json={"action": "install", "confirm": "M-2"}).status_code == 400
    assert client.post(url, headers=step, json={"action": "refresh"}).status_code == 400, "nothing to rebuild yet"
    r = client.post(url, headers=step, json={"action": "install", "confirm": "m-1", "autoStart": True})
    assert r.status_code == 200, r.text
    spec = heartbeat(client, h, caps=caps)["jobs"][0]
    assert spec["kind"]["type"] == "local_recovery" and spec["kind"]["auto_start"] is True
    code = spec["recovery_settings"]
    assert code["server"] == "" and code["expires"] > 0
    pe = lambda tok, role: client.post("/backup/api/agent/enroll", json={
        "protocol": 1, "token": tok, "hostname": "MINWINPC", "machine_id": f"pe-{role}", "role": role,
        "os": {"family": "windows"}, "agent_version": "0.1.0", "public_key": base64.b64encode(b"p" * 32).decode()})
    assert pe(code["token"], "server").status_code == 403, "recovery sessions only"
    assert pe(code["token"], "recovery").status_code == 200
    finish(client, h, spec["id"])

    # Reported installed with an older agent inside: rebuilt by the scheduler, with a new code.
    lr = {"disk": 0, "partition": 5, "size": 1 << 30, "built_unix": 1_790_000_000, "agent_version": "0.0.9",
          "expires": code["expires"], "auto_start": True}
    heartbeat(client, h, caps=caps, local_recovery=lr)
    agent = next(a for a in client.get("/api/console/backup/agents", headers=admin).json() if a["id"] == agent_id)
    assert agent["localRecovery"]["partition"] == 5
    from fenrir_cloud.db import session_factory
    with session_factory()() as db:
        assert bk.refresh_local_recovery(db) == 1
        assert bk.refresh_local_recovery(db) == 0, "one at a time"
    spec = heartbeat(client, h, caps=caps, local_recovery=lr)["jobs"][0]
    assert spec["kind"]["action"] == "refresh" and spec["recovery_settings"]["token"] != code["token"]
    assert pe(code["token"], "recovery").status_code == 403, "the old code is revoked"
    finish(client, h, spec["id"])
    r = client.post(url, headers={**admin, "X-Fenrir-Reauth": reauth(client, admin)}, json={"action": "remove", "confirm": "M-1"})
    assert r.status_code == 200, r.text
    assert "recovery_settings" not in heartbeat(client, h, caps=caps, local_recovery=lr)["jobs"][0]


def test_dr_runbook_starts_groups_in_order_and_stops_test_vms(client, admin, tenant):
    """DR runbooks (backup/docs/design/dr-runbooks.md): group 2 starts once group 1 is up; recovery time per machine
    and overall; test VMs are stopped; a failover needs the name typed and a password check."""
    from fenrir_cloud.db import session_factory

    e = link(client, admin, tenant)
    db_id, dbh = agent_enroll(client, e["token"], machine="db01")
    heartbeat(client, dbh)
    repo = ready_repo(client, admin, tenant, db_id, dbh)
    web_id, webh = agent_enroll(client, e["token"], machine="web01", key=base64.b64encode(b"w" * 32).decode())
    heartbeat(client, webh)
    assert client.post(f"/api/console/backup/repositories/{repo}/access", headers=admin,
                       json={"agentId": web_id, "sealed": SEALED}).status_code == 200
    images = {}
    for aid, h, m in ((db_id, dbh, "db01"), (web_id, webh, "web01")):
        client.post(f"/api/console/backup/agents/{aid}/jobs", headers=admin,
                    json={"kind": {"type": "backup_system"}, "repositoryId": repo})
        im = image(machine=m)
        finish(client, h, heartbeat(client, h)["jobs"][0]["id"], images=[im])
        images[aid] = im["image_id"]
    host_id, hh = agent_enroll(client, e["token"], machine="kvm01", key=base64.b64encode(b"h" * 32).decode())
    caps = CAPS + ["boot_kvm"]
    heartbeat(client, hh, caps=caps)

    body = {"tenantId": tenant["id"], "name": "Office", "groups": [
        {"name": "Databases", "machines": [{"key": f"{db_id}|", "name": "db01", "hostAgentId": host_id}]},
        {"name": "Web", "machines": [{"key": f"{web_id}|", "name": "web01", "hostAgentId": host_id, "memoryMb": 2048}]}]}
    r = client.post("/api/console/backup/runbooks", headers=admin, json=body)
    assert r.status_code == 200, r.text
    rb = r.json()["id"]
    # The host cannot read the backups yet: the run fails at the first machine, the rest is skipped.
    run = client.post(f"/api/console/backup/runbooks/{rb}/run", headers=admin, json={"mode": "test"}).json()
    assert run["state"] == "failed" and "no access" in run["items"][0]["message"]
    assert run["items"][1]["state"] == "skipped"
    assert client.post(f"/api/console/backup/repositories/{repo}/access", headers=admin,
                       json={"agentId": host_id, "sealed": SEALED}).status_code == 200

    run = client.post(f"/api/console/backup/runbooks/{rb}/run", headers=admin, json={"mode": "test"}).json()
    assert [i["state"] for i in run["items"]] == ["starting", "pending"]
    assert client.post(f"/api/console/backup/runbooks/{rb}/run", headers=admin, json={"mode": "test"}).status_code == 400
    job = heartbeat(client, hh, caps=caps)["jobs"][0]
    assert job["kind"]["type"] == "boot_check" and job["kind"]["image_id"] == images[db_id] and job["kind"]["keep_running"]
    finish(client, hh, job["id"], boot_check={"image_id": images[db_id], "outcome": "verified", "method": "guest", "seconds": 40})
    with session_factory()() as db:
        bk.run_dr(db)
    job = heartbeat(client, hh, caps=caps)["jobs"][0]
    assert job["kind"]["image_id"] == images[web_id] and job["kind"]["memory_mb"] == 2048, "group 2 after group 1"
    finish(client, hh, job["id"], boot_check={"image_id": images[web_id], "outcome": "verified", "method": "guest", "seconds": 55})
    with session_factory()() as db:
        bk.run_dr(db)
    runs = client.get(f"/api/console/backup/runbooks/{rb}/runs", headers=admin).json()
    done = runs[0]
    assert done["state"] == "succeeded" and done["rtoSeconds"] is not None
    assert all(i["state"] == "up" for i in done["items"])

    # Stop: the VMs still running on the host are stopped.
    vms = [{"session_id": str(uuid.uuid4()), "image_id": images[a], "started_unix": 1, "vnc_port": 0, "forwards": {}}
           for a in (db_id, web_id)]
    heartbeat(client, hh, caps=caps, running_vms=vms)
    stopped = client.post(f"/api/console/backup/runs/{done['id']}/stop", headers=admin).json()
    assert stopped["vmsStopped"] is True
    jobs = heartbeat(client, hh, caps=caps, running_vms=vms)["jobs"]
    assert jobs and jobs[0]["kind"]["type"] == "stop_vm"

    # A failover: the runbook's name and a password check.
    assert client.post(f"/api/console/backup/runbooks/{rb}/run", headers=admin,
                       json={"mode": "failover", "confirm": "Office"}).json()["detail"] == "reauth_required"
    step = {**admin, "X-Fenrir-Reauth": reauth(client, admin)}
    assert client.post(f"/api/console/backup/runbooks/{rb}/run", headers=step, json={"mode": "failover", "confirm": "office"}).status_code == 400
    r = client.post(f"/api/console/backup/runbooks/{rb}/run", headers=step, json={"mode": "failover", "confirm": "Office"})
    assert r.status_code == 200 and r.json()["mode"] == "failover" and r.json()["stopAfterMinutes"] == 0


def test_kubernetes_and_saas_backups_keep_only_the_sealed_secret(client, admin, tenant):
    """Apps & clusters (backup/docs/design/saas.md, kubernetes.md): the secret arrives sealed for the machine that
    runs the jobs and is only forwarded; restores that overwrite need destructive rights, a password check and the
    cluster's or tenant's name typed."""
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    caps = CAPS + ["kubernetes", "saas"]
    heartbeat(client, h)
    repo = ready_repo(client, admin, tenant, agent_id, h)
    tenant_ = {"service": "salesforce", "tenant": "acme", "client_id": "key", "domain_url": "https://acme.my.salesforce.com"}
    body = {"name": "CRM", "agentId": agent_id, "repositoryId": repo, "schedule": {"type": "manual"},
            "job": {"type": "backup_saas", "tenant": tenant_, "sealed_secret": SEALED}}
    r = client.post("/api/console/backup/plans", headers=admin, json=body)
    assert r.status_code == 400 and "saas" in r.text, "the machine must report the capability"
    heartbeat(client, h, caps=caps)
    plain = {**body, "job": {**body["job"], "sealed_secret": "the-secret-in-clear"}}
    assert client.post("/api/console/backup/plans", headers=admin, json=plain).status_code == 400
    bad_url = {**body, "job": {**body["job"], "tenant": {**tenant_, "domain_url": "http://acme"}}}
    assert client.post("/api/console/backup/plans", headers=admin, json=bad_url).status_code == 400
    r = client.post("/api/console/backup/plans", headers=admin, json=body)
    assert r.status_code == 200, r.text
    assert client.post(f"/api/console/backup/plans/{r.json()['id']}/run", headers=admin).status_code == 200
    spec = heartbeat(client, h, caps=caps)["jobs"][0]
    assert spec["kind"]["type"] == "backup_saas" and spec["kind"]["sealed_secret"] == SEALED
    assert spec["kind"]["tenant"]["mail"] is True and spec["repository"]["sealed_secret"] == SEALED

    url = f"/api/console/backup/agents/{agent_id}/jobs"
    cluster = {"name": "prod", "api_server": "https://k8s.lan:6443", "namespaces": ["shop"]}
    restore = {"type": "restore_kubernetes", "image_id": str(uuid.uuid4()), "cluster": cluster, "sealed_token": SEALED,
               "namespaces": ["shop"], "rename_to": "shop-restored"}
    r = client.post(url, headers=admin, json={"repositoryId": repo, "kind": restore})
    assert r.status_code == 200, r.text
    bad_ns = {**restore, "cluster": {**cluster, "namespaces": ["Shop!"]}}
    assert client.post(url, headers=admin, json={"repositoryId": repo, "kind": bad_ns}).status_code == 400
    replace = {"repositoryId": repo, "kind": {**restore, "replace": True}, "confirm": "prod"}
    assert client.post(url, headers=admin, json=replace).json()["detail"] == "reauth_required"
    step = {**admin, "X-Fenrir-Reauth": reauth(client, admin)}
    assert client.post(url, headers=step, json={**replace, "confirm": "staging"}).status_code == 400
    assert client.post(url, headers=step, json=replace).status_code == 200


def test_backups_are_scanned_for_malware_and_infected_restores_need_acknowledging(client, admin, tenant):
    """A scan job carries the customer's detection content; findings are stored, alerted and shown; the last clean
    backup is reported; restoring infected files needs allowInfected; a plan can scan each new backup."""
    from fenrir_cloud.db import session_factory
    from fenrir_cloud.models import Alert

    bad_sha, good_sha = "ab" * 32, "cd" * 32
    assert client.post("/api/console/intel/indicators", headers=admin,
                       json={"values": [bad_sha], "verdict": "malicious"}).status_code == 200
    client.post("/api/console/intel/indicators", headers=admin, json={"values": [good_sha], "verdict": "malicious"})
    client.post("/api/console/intel/indicators", headers=admin, json={"values": [good_sha], "verdict": "allow"})
    client.post("/api/console/intel/yara", headers=admin,
                json={"name": "test.yar", "source": "rule T { strings: $a = \"x\" condition: $a }"})
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    caps = CAPS + ["scan_images"]
    heartbeat(client, h, caps=caps)
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    old, new = image(t=0), image(t=100)
    for im in (old, new):
        client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                    json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
        finish(client, h, heartbeat(client, h, caps=caps)["jobs"][0]["id"], images=[im])
    admin = unlock(client, admin, h, repo_id, agent_id, caps=caps)

    def scan(im, findings, **body):
        r = client.post(f"/api/console/backup/images/{im['image_id']}/scan", headers=admin, json=body)
        assert r.status_code == 200, r.text
        spec = next(j for j in heartbeat(client, h, caps=caps)["jobs"] if j["id"] == r.json()["id"])
        return spec, lambda: finish(client, h, spec["id"], state="warning" if findings else "succeeded", result={
            "image_id": im["image_id"], "scan": {"files_scanned": 120, "bytes_scanned": 9 << 20,
                                                 "volumes_scanned": ["C:\\"], "findings": findings,
                                                 "rule_errors": [], "rules_used": 1, "indicators_used": 1}})

    spec, done = scan(old, [])
    k = spec["kind"]
    assert k["type"] == "scan_image" and k["selection"] == "executables"
    assert bad_sha in k["indicators"] and good_sha not in k["indicators"], "allow-listed hashes are left out"
    assert [r["name"] for r in k["rules"]] == ["test.yar"]
    done()
    infected = [{"volume": "C:\\", "path": "/Users/anna/Downloads/invoice.exe", "size": 4096, "sha256": bad_sha,
                 "detections": [{"kind": "hash", "name": "SHA-256 indicator"}], "evil": "x" * 9999}]
    spec, done = scan(new, infected, allFiles=True)
    assert spec["kind"]["selection"] == "all"
    done()

    listed = {i["imageId"]: i for i in client.get("/api/console/backup/images", headers=admin).json()}
    assert listed[old["image_id"]]["lastScan"]["state"] == "clean"
    assert listed[new["image_id"]]["lastScan"] == {**listed[new["image_id"]]["lastScan"], "state": "infected", "findings": 1}
    dev = next(d for d in client.get("/api/console/backup/image-devices", headers=admin).json() if d["name"] == "M-1")
    assert dev["infected"] == 1 and dev["lastCleanCreated"] == old["created_unix"]
    scans = client.get(f"/api/console/backup/images/{new['image_id']}/scans", headers=admin).json()
    assert scans[0]["findings"][0]["path"].endswith("invoice.exe") and "evil" not in scans[0]["findings"][0]
    with session_factory()() as db:
        alert = db.query(Alert).filter(Alert.title.like("Malware found in a backup of%")).one()
        assert alert.severity == "critical"

    # Restoring the infected image needs acknowledging; restoring a clean file from it does not.
    body = {"imageId": new["image_id"], "agentId": agent_id, "target": {"type": "vhdx", "directory": "D:\\R"}}
    r = client.post("/api/console/backup/restores", headers=admin, json=body)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "image_infected"
    assert client.post("/api/console/backup/restores", headers=admin, json={**body, "allowInfected": True}).status_code == 200
    files = {"agentId": agent_id, "disk": 0, "partition": 1, "target": "D:\\R",
             "paths": ["/Users/anna/Documents/report.txt"]}
    for j in heartbeat(client, h, caps=caps + ["restore_files"])["jobs"]:
        finish(client, h, j["id"])  # the image restore above
    ok = client.post(f"/api/console/backup/images/{new['image_id']}/restore-files", headers=admin, json=files)
    assert ok.status_code == 200, ok.text
    blocked = client.post(f"/api/console/backup/images/{new['image_id']}/restore-files", headers=admin,
                          json={**files, "paths": ["/Users/anna"]})
    assert blocked.status_code == 409 and blocked.json()["detail"]["infected"] == ["/Users/anna/Downloads/invoice.exe"]

    # A plan that scans after each backup queues a scan for the new image on the same machine.
    for j in heartbeat(client, h, caps=caps + ["restore_files"])["jobs"]:
        finish(client, h, j["id"])  # the file restore
    r = client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                    json={"kind": {"type": "backup_system", "settings": {"scan_after_backup": True}}, "repositoryId": repo_id})
    assert r.status_code == 200, r.text
    third = image(t=200)
    jobs = heartbeat(client, h, caps=caps)["jobs"]
    finish(client, h, jobs[0]["id"], images=[third])
    queued = [j["kind"] for j in heartbeat(client, h, caps=caps)["jobs"]]
    assert any(k["type"] == "scan_image" and k["image_id"] == third["image_id"] for k in queued), queued


def test_folder_backups_list_under_the_machine_and_restore_files_only(client, admin, tenant):
    """A backup of chosen files and folders: validated paths, agents that report backup_files, listed with the
    machine's backups, restored with Browse files (also back where they were); no disk restore or boot test."""
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    caps = CAPS + ["backup_files", "restore_files"]
    heartbeat(client, h)
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    job = {"type": "backup_files", "paths": [r"C:\Users\anna\Documents", r"\\nas\share\Accounts"],
           "excludes": ["*.tmp", "node_modules"]}
    r = client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin, json={"kind": job, "repositoryId": repo_id})
    assert "cannot" in r.json()["detail"], "an agent without backup_files is refused"
    heartbeat(client, h, caps=caps)
    for bad_job in ({**job, "paths": []}, {**job, "paths": ["relative\\folder"]}):
        assert client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                           json={"kind": bad_job, "repositoryId": repo_id}).status_code == 400
    plan = client.post("/api/console/backup/plans", headers=admin, json={
        "name": "Documents hourly", "agentId": agent_id, "repositoryId": repo_id, "job": job,
        "schedule": {"type": "interval", "hours": 1}, "retention": {"keep_last": 24}})
    assert plan.status_code == 200, plan.text
    assert client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                       json={"kind": job, "repositoryId": repo_id}).status_code == 200
    spec = heartbeat(client, h, caps=caps)["jobs"][0]
    assert spec["kind"]["type"] == "backup_files" and spec["kind"]["excludes"] == ["*.tmp", "node_modules"]
    disks, files = image(t=0), {**image(machine="files:m-1", t=50), "hostname": "M-1"}
    finish(client, h, spec["id"], images=[files])
    client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
    finish(client, h, heartbeat(client, h, caps=caps)["jobs"][0]["id"], images=[disks])

    devices = client.get("/api/console/backup/image-devices", headers=admin).json()
    assert [(d["name"], d["images"]) for d in devices] == [("M-1", 2)], "listed with the machine's own backups"
    admin = unlock(client, admin, h, repo_id, agent_id, caps=caps)
    listed = {i["imageId"]: i for i in client.get("/api/console/backup/images", headers=admin).json()}
    assert listed[files["image_id"]]["source"] == "files" and listed[disks["image_id"]]["source"] == "disks"

    r = client.post("/api/console/backup/restores", headers=admin,
                    json={"imageId": files["image_id"], "agentId": agent_id, "target": {"type": "vhdx", "directory": "D:\\R"}})
    assert r.status_code == 400 and "Browse files" in r.json()["detail"]
    r = client.post(f"/api/console/backup/images/{files['image_id']}/boot-check", headers=admin, json={"agentId": agent_id})
    assert r.status_code == 400
    back = {"agentId": agent_id, "disk": 1, "partition": 1, "paths": ["/C:/Users/anna/Documents/report.docx"],
            "target": "@original"}
    assert client.post(f"/api/console/backup/images/{files['image_id']}/restore-files", headers=admin, json=back).status_code == 200
    assert client.post(f"/api/console/backup/images/{disks['image_id']}/restore-files", headers=admin,
                       json={**back, "partition": 2}).status_code == 400, "@original is for folder backups"


def test_search_across_a_machines_backups(client, admin, tenant):
    """Each new backup is indexed on the machine that took it; a search runs on a machine with access over the
    machine's unlocked backups (newest first) and its matches are dropped from the job record after a day."""
    from datetime import timedelta

    from fenrir_cloud import backup as bk
    from fenrir_cloud.db import session_factory
    from fenrir_cloud.models import BackupJob

    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    caps = CAPS + ["search_files"]
    heartbeat(client, h, caps=caps)
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    older, newer = image(t=0), image(t=100)
    for im in (older, newer):
        client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                    json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
        finish(client, h, heartbeat(client, h, caps=caps)["jobs"][0]["id"], images=[im])
        index = heartbeat(client, h, caps=caps)["jobs"][0]
        assert index["kind"] == {"type": "index_image", "image_id": im["image_id"]}
        finish(client, h, index["id"])

    dev = client.get("/api/console/backup/image-devices", headers=admin).json()[0]
    locked = client.post("/api/console/backup/search", headers=admin, json={"query": "budget", "device": dev["key"]})
    assert locked.status_code == 403
    admin = unlock(client, admin, h, repo_id, agent_id, caps=caps)
    assert client.post("/api/console/backup/search", headers=admin, json={"query": " ", "device": dev["key"]}).status_code == 400
    r = client.post("/api/console/backup/search", headers=admin, json={"query": "budget*.xlsx", "device": dev["key"]})
    assert r.status_code == 200, r.text
    [job] = r.json()["jobs"]
    spec = heartbeat(client, h, caps=caps)["jobs"][0]
    assert spec["id"] == job["id"] and spec["kind"]["type"] == "search_files"
    assert spec["kind"]["images"] == [newer["image_id"], older["image_id"]], "newest first"
    hit = {"image_id": newer["image_id"], "volume": {"label": "C:\\", "disk": 0, "partition": 3},
           "path": "/Users/anna/Documents/budget 2026.xlsx", "size": 51200, "modified": 1790000000, "folder": False}
    finish(client, h, job["id"], result={"query": "budget*.xlsx", "hits": [hit], "searched": 2, "not_indexed": [],
                                         "truncated": False})
    got = client.get(f"/api/console/backup/jobs/{job['id']}", headers=admin).json()
    assert got["result"]["hits"][0]["path"].endswith("budget 2026.xlsx")
    with session_factory()() as db:
        j = db.get(BackupJob, job["id"])
        j.finished_at = j.finished_at - bk.BROWSE_KEEP - timedelta(minutes=1)
        db.commit()
        assert bk.purge_listings(db) >= 1
        assert db.get(BackupJob, job["id"]).result is None, "matches are not kept beyond a day"


def test_one_sql_or_exchange_database_restores_on_its_own(client, admin, tenant):
    """A component whose files the image lists restores alone on a Windows machine; SQL Server databases can be
    attached under a new name; older images (no file lists) and other machines are refused."""
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    caps = CAPS + ["restore_apps"]
    heartbeat(client, h, caps=caps)
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
    im = image()
    im["applications"] = [
        {"writer": "SqlServerWriter", "component": "SQL01\\sales", "caption": "sales", "included": True, "file_sets": 2},
        {"writer": "Microsoft Exchange Writer", "component": "Microsoft Exchange Server\\DB01", "included": True,
         "file_sets": 3},
        {"writer": "SqlServerWriter", "component": "SQL01\\legacy", "included": True},
    ]
    finish(client, h, heartbeat(client, h, caps=caps)["jobs"][0]["id"], images=[im])
    admin = unlock(client, admin, h, repo_id, agent_id, caps=caps)
    apps = client.get("/api/console/backup/images", headers=admin).json()[0]["applications"]
    assert [a["fileSets"] for a in apps] == [2, 3, 0]
    url = f"/api/console/backup/images/{im['image_id']}/restore-app"
    body = {"agentId": agent_id, "component": "SQL01\\sales", "directory": "D:\\Restores", "attachAs": "sales_0901",
            "sqlInstance": "SQL01\\FINANCE"}
    for bad_body in ({**body, "component": "SQL01\\legacy"}, {**body, "component": "nope"},
                     {**body, "directory": "Restores"}, {**body, "sqlInstance": "x; DROP"},
                     {**body, "component": "Microsoft Exchange Server\\DB01"}):
        assert client.post(url, headers=admin, json=bad_body).status_code == 400, bad_body
    r = client.post(url, headers=admin, json=body)
    assert r.status_code == 200, r.text
    spec = heartbeat(client, h, caps=caps)["jobs"][0]["kind"]
    assert spec == {"type": "restore_application", "image_id": im["image_id"], "component": "SQL01\\sales",
                    "directory": "D:\\Restores", "attach_as": "sales_0901", "sql_instance": "SQL01\\FINANCE"}
    ex = {"agentId": agent_id, "component": "Microsoft Exchange Server\\DB01", "directory": "D:\\Restores"}
    assert client.post(url, headers=admin, json=ex).status_code == 200


def test_restore_to_azure_or_aws_and_keep_a_standby_vm(client, admin, tenant):
    """Cloud restores carry the location and keys sealed to the machine; a plan's standby VM is refreshed on its host
    after each backup, replacing the previous one; a standby host without access is refused and alerted."""
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    caps = CAPS + ["restore_cloud", "restore_hyperv", "restore_vm_files"]
    heartbeat(client, h, caps=caps)
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
    im = image()
    finish(client, h, heartbeat(client, h, caps=caps)["jobs"][0]["id"], images=[im])
    admin = unlock(client, admin, h, repo_id, agent_id, caps=caps)
    go = lambda target: client.post("/api/console/backup/restores", headers=admin,  # noqa: E731
                                    json={"imageId": im["image_id"], "agentId": agent_id, "target": target})
    az = {"type": "azure", "location": "azure://restores/pm-acer", "name": "pm-acer", "sealed": SEALED}
    for bad_target in ({**az, "location": "azure://UPPER"}, {**az, "name": "a b"}, {**az, "sealed": None},
                       {**az, "endpoint": "http://plain.example"}):
        assert go(bad_target).status_code == 400, bad_target
    assert go(az).status_code == 200
    spec = heartbeat(client, h, caps=caps)["jobs"][0]
    assert spec["kind"]["target"] == {**az, "endpoint": ""}
    finish(client, h, spec["id"])
    aws = {"type": "aws", "location": "s3://vm-import/dr", "region": "eu-west-2", "name": "pm-acer",
           "staging": "D:\\Staging", "sealed": SEALED}
    assert go({**aws, "staging": "relative"}).status_code == 400
    assert go(aws).status_code == 200
    finish(client, h, heartbeat(client, h, caps=caps)["jobs"][0]["id"])

    # A plan with a standby Hyper-V VM on the same machine (a Hyper-V host).
    plan = client.post("/api/console/backup/plans", headers=admin, json={
        "name": "Nightly", "agentId": agent_id, "repositoryId": repo_id, "job": {"type": "backup_system"},
        "schedule": {"type": "manual"}, "retention": {"keep_last": 7},
        "standby": {"agentId": agent_id, "type": "hyperv_vm", "name": "PM-ACER standby", "directory": "D:\\Standby"}})
    assert plan.status_code == 200, plan.text
    listed = next(p for p in client.get("/api/console/backup/plans", headers=admin).json() if p["id"] == plan.json()["id"])
    assert listed["standby"]["name"] == "PM-ACER standby"
    bad_sb = client.patch(f"/api/console/backup/plans/{plan.json()['id']}", headers=admin,
                          json={"standby": {"agentId": agent_id, "type": "vm_files", "format": "ova", "name": "x", "directory": "D:\\S"}})
    assert bad_sb.status_code == 400
    assert client.post(f"/api/console/backup/plans/{plan.json()['id']}/run", headers=admin).status_code == 200
    job = heartbeat(client, h, caps=caps)["jobs"][0]
    newer = image(t=500)
    finish(client, h, job["id"], images=[newer])
    queued = []
    for _ in range(6):
        jobs = heartbeat(client, h, caps=caps)["jobs"]
        if not jobs:
            break
        queued.append(jobs[0]["kind"])
        finish(client, h, jobs[0]["id"])
    standby = next(k for k in queued if k["type"] == "restore")
    assert standby["image_id"] == newer["image_id"]
    assert standby["target"] == {"type": "hyperv_vm", "name": "PM-ACER standby", "directory": "D:\\Standby",
                                 "replace": True, "switch": None, "start": False}


def test_backup_report_for_a_customer_and_its_schedule(client, admin, tenant):
    """The backup report shows machines (protected, failing, no plan), success rate, restore tests and malware scans,
    with next steps; it is a page and a PDF, and can be emailed on a schedule like the other reports."""
    from fenrir_cloud import mailer, reports
    from fenrir_cloud.db import session_factory

    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    caps = CAPS + ["scan_images"]
    heartbeat(client, h, caps=caps)
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    client.post("/api/console/backup/plans", headers=admin, json={
        "name": "Nightly", "agentId": agent_id, "repositoryId": repo_id, "job": {"type": "backup_system"},
        "schedule": {"type": "daily", "time": "01:00", "days": [], "utc_offset_minutes": 0}, "retention": {"keep_last": 7}})
    good, bad = image(t=0), image(t=10)
    for im in (good,):
        client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                    json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
        finish(client, h, heartbeat(client, h, caps=caps)["jobs"][0]["id"], images=[im])
    client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
    finish(client, h, heartbeat(client, h, caps=caps)["jobs"][0]["id"], state="failed", error="VSS writer timed out")

    with session_factory()() as db:
        from fenrir_cloud.models import Tenant
        t = db.get(Tenant, tenant["id"])
        data = reports.backup_data(db, t, 30)
        assert data["jobs"] == 2 and data["successRate"] == 50
        assert [m["status"] for m in data["machines"]] == ["failing"]
        assert data["failures"][0]["error"] == "VSS writer timed out"
        steps = reports.backup_recommendations(data)
        assert any("failing backups of M-1" in s for s in steps)
    page = client.get("/api/console/reports/backup.html", headers=admin, params={"tenant_id": tenant["id"], "days": 30})
    assert page.status_code == 200 and "Backup report" in page.text and "VSS writer timed out" in page.text
    pdf = client.get("/api/console/reports/backup.pdf", headers=admin, params={"tenant_id": tenant["id"], "days": 7})
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert client.get("/api/console/reports/backup.pdf", headers=admin,
                      params={"tenant_id": tenant["id"], "days": 12}).status_code == 400
    saved = client.put("/api/console/reports/schedules", headers=admin, params={"tenant_id": tenant["id"]},
                       json={"schedules": [{"kind": "backup", "every": "monthly", "to": ["it@acme.example"]}]})
    assert saved.status_code == 200, saved.text
    mailer.OUTBOX.clear()
    with session_factory()() as db:
        assert reports.send_schedules(db) == 1
    assert mailer.OUTBOX[-1]["subject"].startswith("Backup report") and mailer.OUTBOX[-1]["attachments"][0].endswith(".pdf")


def test_legal_hold_keeps_backups_from_retention(client, admin, tenant):
    """Held backups go to retention as `held`; an agent too old to honour holds gets no retention (alerted); releasing
    a hold needs a fresh password check; everything is audited."""
    from fenrir_cloud.db import session_factory
    from fenrir_cloud.models import Alert

    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)  # no legal_hold capability yet
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    plan = client.post("/api/console/backup/plans", headers=admin, json={
        "name": "Nightly", "agentId": agent_id, "repositoryId": repo_id, "job": {"type": "backup_system"},
        "schedule": {"type": "manual"}, "retention": {"keep_last": 1}}).json()["id"]

    def backup(t, caps=CAPS):
        assert client.post(f"/api/console/backup/plans/{plan}/run", headers=admin).status_code == 200
        im = image(t=t)
        finish(client, h, heartbeat(client, h, caps=caps)["jobs"][0]["id"], images=[im])
        return im

    first = backup(0)
    for j in heartbeat(client, h)["jobs"]:
        finish(client, h, j["id"])
    admin = unlock(client, admin, h, repo_id, agent_id)
    url = f"/api/console/backup/images/{first['image_id']}/legal-hold"
    assert client.post(url, headers=admin, json={"hold": True, "reason": ""}).status_code == 400
    r = client.post(url, headers=admin, json={"hold": True, "reason": "Matter 2026-114 (HR dispute)"})
    assert r.status_code == 200 and r.json()["legalHold"]["reason"].startswith("Matter")
    listed = client.get("/api/console/backup/images", headers=admin).json()
    assert next(i for i in listed if i["imageId"] == first["image_id"])["legalHold"]["by"]

    # An old agent: no retention while holds exist, and an alert says why.
    backup(100)
    assert not [j for j in heartbeat(client, h)["jobs"] if j["kind"]["type"] == "apply_retention"]
    with session_factory()() as db:
        assert db.query(Alert).filter(Alert.title.like("Retention skipped%")).count() == 1

    # An up-to-date agent gets the held list with retention.
    caps = CAPS + ["legal_hold"]
    backup(200, caps)
    kinds = []
    for _ in range(4):
        jobs = heartbeat(client, h, caps=caps)["jobs"]
        if not jobs:
            break
        kinds.append(jobs[0]["kind"])
        finish(client, h, jobs[0]["id"])
    ret = next(k for k in kinds if k["type"] == "apply_retention")
    assert ret["held"] == [first["image_id"]]

    # Releasing needs a fresh password check.
    assert client.post(url, headers=admin, json={"hold": False}).json()["detail"] == "reauth_required"
    step = {**admin, "X-Fenrir-Reauth": reauth(client, admin)}
    assert client.post(url, headers=step, json={"hold": False}).json()["legalHold"] is None
    dev = client.get("/api/console/backup/image-devices", headers=admin).json()[0]
    held = client.post("/api/console/backup/legal-hold/device", headers=admin,
                       json={"device": dev["key"], "reason": "Matter 2026-120"}).json()["held"]
    assert held == 3


def test_storage_is_checked_daily_and_a_failing_check_raises_an_alert(client, admin, tenant):
    """Credential and storage health: once a day a machine with access tests the repository's storage with the
    sign-in it was given; a failing check is shown on the repository and raises one alert, cleared when it passes."""
    from datetime import timedelta

    from fenrir_cloud.db import session_factory
    from fenrir_cloud.models import Alert, BackupJob, BackupRepository

    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    with session_factory()() as db:
        assert bk.check_storage(db) == 1
        assert bk.check_storage(db) == 0, "one check at a time, at most daily"
        db.commit()
    spec = heartbeat(client, h)["jobs"][0]
    assert spec["kind"]["type"] == "check_access" and spec["kind"]["path"] == "D:\\Backups"
    assert spec["kind"]["sealed_share"] is None
    finish(client, h, spec["id"], state="failed", error="access denied")
    repo = next(r for r in client.get("/api/console/backup/repositories", headers=admin).json() if r["id"] == repo_id)
    assert repo["storageError"] == "access denied" and repo["storageCheckedAt"]
    with session_factory()() as db:
        assert sum(a.rule_id == bk.RULE_STORAGE for a in db.query(Alert).all()) == 1
        # A day later it is checked again; this time it passes and the alert is resolved.
        r = db.get(BackupRepository, repo_id)
        r.storage_checked_at -= timedelta(days=2)
        for j in db.query(BackupJob).filter(BackupJob.requested_by == bk.STORAGE_CHECK_BY):
            j.created_at -= timedelta(days=2)
        db.commit()
        assert bk.check_storage(db) == 1
        db.commit()
    spec = heartbeat(client, h)["jobs"][0]
    finish(client, h, spec["id"])
    repo = next(r for r in client.get("/api/console/backup/repositories", headers=admin).json() if r["id"] == repo_id)
    assert repo["storageError"] is None
    with session_factory()() as db:
        open_ = [a for a in db.query(Alert).all() if a.rule_id == bk.RULE_STORAGE and a.status not in ("resolved", "closed")]
        assert not open_, [(a.status) for a in open_]


def test_offline_media_set_copies_go_to_the_attached_drive(client, admin, tenant):
    """Offline media rotation: drives of one media set are alternatives for a plan's copy; the machine copies to
    whichever is attached, the images are listed under that drive, and an overdue set raises an alert."""
    from fenrir_cloud.db import session_factory
    from fenrir_cloud.models import Alert

    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)
    local = ready_repo(client, admin, tenant, agent_id, h)
    drive_a = ready_repo(client, admin, tenant, agent_id, h)
    drive_b = ready_repo(client, admin, tenant, agent_id, h)
    for d in (drive_a, drive_b):
        r = client.post(f"/api/console/backup/repositories/{d}/media-set", headers=admin, json={"mediaSet": "Weekly USB"})
        assert r.status_code == 200, r.text
    assert next(r for r in client.get("/api/console/backup/repositories", headers=admin).json()
                if r["id"] == drive_a)["mediaSet"] == "Weekly USB"
    with session_factory()() as db:
        bk.check_media_rotation(db)
        db.commit()
        assert sum(a.rule_id == bk.RULE_MEDIA for a in db.query(Alert).all()) == 1
    plan = client.post("/api/console/backup/plans", headers=admin, json={
        "name": "Nightly", "agentId": agent_id, "repositoryId": local, "job": {"type": "backup_system"},
        "schedule": {"type": "manual"}, "copyToRepositoryId": drive_a}).json()["id"]
    assert client.post(f"/api/console/backup/plans/{plan}/run", headers=admin).status_code == 200
    job = heartbeat(client, h)["jobs"][0]
    im = image()
    finish(client, h, job["id"], images=[im])
    copy = heartbeat(client, h)["jobs"][0]
    assert copy["kind"]["type"] == "copy_images" and copy["kind"]["images"] == [], "copies everything the drive lacks"
    alts = copy.get("copy_alternatives") or []
    assert [a["repository_id"] for a in alts] == [drive_b]
    # Drive B was attached: the copies are recorded there.
    finish(client, h, copy["id"], result={"target_repository_id": drive_b},
           images=[{**im, "image_id": str(uuid.uuid4()), "created_unix": __import__("time").time().__int__()}])
    from fenrir_cloud.models import BackupImage
    with session_factory()() as db:
        assert db.query(BackupImage).filter(BackupImage.repository_id == drive_b).count() == 1
        assert db.query(BackupImage).filter(BackupImage.repository_id == drive_a).count() == 0
        bk.check_media_rotation(db)
        db.commit()
        open_ = [a for a in db.query(Alert).all() if a.rule_id == bk.RULE_MEDIA and a.status not in ("resolved", "closed")]
        assert not open_


def test_m365_sites_teams_directory_and_archive_tiers(client, admin, tenant):
    """SharePoint, Teams and Entra ID are opt-in for Microsoft 365 only; object storage can put backup data in an
    instant-read archive tier, and only those tiers are accepted."""
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    caps = CAPS + ["saas"]
    heartbeat(client, h, caps=caps)
    repo = ready_repo(client, admin, tenant, agent_id, h)
    heartbeat(client, h, caps=caps)
    t = {"service": "m365", "tenant": "contoso.onmicrosoft.com", "client_id": "app", "sites": True, "teams": True,
         "directory": True}
    r = client.post("/api/console/backup/plans", headers=admin, json={
        "name": "M365", "agentId": agent_id, "repositoryId": repo, "schedule": {"type": "manual"},
        "job": {"type": "backup_saas", "tenant": t, "sealed_secret": SEALED}})
    assert r.status_code == 200, r.text
    assert client.post(f"/api/console/backup/plans/{r.json()['id']}/run", headers=admin).status_code == 200
    spec = heartbeat(client, h, caps=caps)["jobs"][0]
    got = spec["kind"]["tenant"]
    assert got["sites"] is True and got["teams"] is True and got["directory"] is True
    finish(client, h, spec["id"])

    def s3_repo(cls):
        return client.post("/api/console/backup/repositories", headers=admin, json={
            "name": "Archive", "path": "s3://fenrir-archive/x", "repoUuid": str(uuid.uuid4()), "initAgentId": agent_id,
            "s3": {"endpoint": "https://s3.eu-west-2.amazonaws.com", "region": "eu-west-2", "path_style": False,
                   "lock_mode": None, "lock_days": 0, "storage_class": cls},
            "share_auth": "password", "share_user": "AKID",
            "access": [{"agentId": agent_id, "sealed": SEALED, "sealedShare": SEALED}]})
    assert s3_repo("DEEP_ARCHIVE").status_code == 400, "restores could not read a tier that needs a thaw"
    r = s3_repo("GLACIER_IR")
    assert r.status_code == 200, r.text
    spec = next(j for j in heartbeat(client, h, caps=caps)["jobs"] if j["kind"]["type"] == "init_repository")
    assert spec["repository"]["s3"]["storage_class"] == "GLACIER_IR"
