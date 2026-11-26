"""Backup status log and weekly restore tests, recorded in the ISMS (backup/docs/design/restore-tests.md)."""

import base64
import json
from datetime import timedelta

from test_device_backup import CAPS, SEALED, agent_enroll, finish, heartbeat, image, link, ready_repo, unlock
from test_grc_assurance import adopt

from fenrir_cloud import backup as bk
from fenrir_cloud import crypto, restore_tests
from fenrir_cloud import db as database
from fenrir_cloud.models import (Alert, AuditLog, BackupBootCheck, BackupJob, BackupRepository, GrcEvidence, GrcEvidenceLink,
                                 ImageBackupPlan, utcnow)

PNG = b"\x89PNG\r\n\x1a\n" + b"screen" * 20
URL = "/api/console/backup"


def backed_up(client, admin, tenant):
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)
    repo_id = ready_repo(client, admin, tenant, agent_id, h)
    client.post(f"{URL}/agents/{agent_id}/jobs", headers=admin, json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
    im = {**image(machine="pm-acer"), "created_unix": int(utcnow().timestamp()) - 3600}
    finish(client, h, heartbeat(client, h)["jobs"][0]["id"], images=[im])
    return agent_id, h, repo_id, im


def test_weekly_restore_test_is_isms_evidence_with_screenshot_and_vm_deletion(client, admin, tenant):
    adopt(client, admin, tenant, "iso-27001")
    agent_id, h, repo_id, im = backed_up(client, admin, tenant)
    today = utcnow().weekday()
    url = f"{URL}/repositories/{repo_id}/boot-verification"
    assert client.post(url, headers=admin, json={"agentId": agent_id, "everyDays": 7, "fullRestore": True,
                                                 "weekday": 7}).status_code == 400
    r = client.post(url, headers=admin, json={"agentId": agent_id, "everyDays": 7, "fullRestore": True, "weekday": (today + 1) % 7})
    assert r.status_code == 200, r.text
    with database.session_factory()() as db:
        assert bk.run_boot_checks(db) == 0  # another weekday
    client.post(url, headers=admin, json={"agentId": agent_id, "everyDays": 7, "fullRestore": True, "weekday": today})
    repo = next(x for x in client.get(f"{URL}/repositories", headers=admin).json() if x["id"] == repo_id)
    assert repo["bootFullRestore"] is True and repo["bootWeekday"] == today
    with database.session_factory()() as db:
        assert bk.run_boot_checks(db) == 1
    job = heartbeat(client, h)["jobs"][0]
    assert job["kind"]["type"] == "boot_check" and job["kind"]["full_restore"] is True and job["kind"]["keep_running"] is False

    finish(client, h, job["id"], boot_check={
        "image_id": im["image_id"], "outcome": "verified", "method": "SSH", "seconds": 48, "firmware": "uefi", "accel": "kvm",
        "message": "the guest's SSH service answered", "screenshot_png": base64.b64encode(PNG).decode(),
        "restore_test": {"format": "raw", "bytes_restored": 10 << 30, "restore_seconds": 300, "chunks_checked": 1000,
                         "mismatches": 0, "vm_removed": True, "removed_unix": 1_800_000_000}})

    log = client.get(f"{URL}/restore-tests", headers=admin, params={"tenantId": tenant["id"]}).json()
    assert len(log) == 1
    t = log[0]
    assert t["result"] == "passed" and t["vmDeleted"] and t["machine"] == "PM-ACER" and t["hasScreenshot"]
    assert t["restore"]["chunksChecked"] == 1000 and t["recoveryPoint"][:4] == str(utcnow().year)
    with database.session_factory()() as db:
        ev = db.get(GrcEvidence, t["evidenceId"])
        assert ev.kind == "file" and ev.content_type == "image/png" and ev.control_id == "FC-DRTEST"
        assert ev.data["vmDeleted"] is True and ev.data["vmDeletedAt"].startswith("2027-01-15")
        assert ev.data["screenshotSha256"] == ev.sha256
        links = {(l.framework_key, l.requirement_id) for l in db.query(GrcEvidenceLink).filter_by(evidence_id=ev.id)}
        assert {("iso-27001", "A.5.30"), ("iso-27001", "A.8.13")} <= links
        entry = db.query(AuditLog).filter_by(action="backup.restore_test").one()
        assert entry.details["evidence"] == ev.id and entry.details["vmDeleted"] is True and entry.hash
    # The screenshot is stored encrypted and downloads as the evidence file.
    got = client.get(f"/api/console/grc/evidence/{t['evidenceId']}/download", headers=admin)
    assert got.status_code == 200 and got.content == PNG
    # The ISMS signal passes: the backed-up machine passed a restore test this week.
    crosswalk = client.get("/api/console/grc-assurance/crosswalk", headers=admin, params={"tenant_id": tenant["id"]}).json()
    dr = next(c for c in crosswalk if c["id"] == "FC-DRTEST")
    assert dr["signals"][0]["passed"] is True, dr["signals"]


def test_a_test_vm_left_behind_or_a_mismatch_is_flagged(client, admin, tenant):
    agent_id, h, repo_id, im = backed_up(client, admin, tenant)
    admin = unlock(client, admin, h, repo_id, agent_id)
    url = f"{URL}/images/{im['image_id']}/boot-check"
    assert client.post(url, headers=admin, json={"agentId": agent_id, "keepRunning": True, "fullRestore": True}).status_code == 400
    assert client.post(url, headers=admin, json={"agentId": agent_id, "fullRestore": True}).status_code == 200
    job = heartbeat(client, h)["jobs"][0]
    assert job["kind"]["full_restore"] is True
    finish(client, h, job["id"], state="failed", error="restored disks did not read back", boot_check={
        "image_id": im["image_id"], "outcome": "failed", "method": "SSH", "seconds": 0, "message": "2 chunk(s) did not read back",
        "restore_test": {"format": "raw", "bytes_restored": 1, "chunks_checked": 10, "mismatches": 2, "vm_removed": False,
                         "removed_unix": 1_800_000_000, "removal_error": "access denied"}})
    t = client.get(f"{URL}/restore-tests", headers=admin).json()[0]
    assert t["result"] == "failed" and not t["vmDeleted"] and not t["hasScreenshot"]
    with database.session_factory()() as db:
        ev = db.get(GrcEvidence, t["evidenceId"])
        assert ev.kind == "automated" and "NOT deleted: access denied" in ev.description
        assert db.query(Alert).filter_by(rule_id=restore_tests.RULE_VM_LEFT).count() == 1
    crosswalk = client.get("/api/console/grc-assurance/crosswalk", headers=admin, params={"tenant_id": tenant["id"]}).json()
    assert next(c for c in crosswalk if c["id"] == "FC-DRTEST")["signals"][0]["passed"] is False


def test_every_backup_status_is_logged_and_filed_weekly(client, admin, tenant):
    adopt(client, admin, tenant, "iso-27001")
    agent_id, h, repo_id, im = backed_up(client, admin, tenant)
    client.post(f"{URL}/agents/{agent_id}/jobs", headers=admin, json={"kind": {"type": "backup_system"}, "repositoryId": repo_id})
    finish(client, h, heartbeat(client, h)["jobs"][0]["id"], state="failed", error="VSS snapshot failed")
    # A plan with no success for days is logged as missed, once.
    with database.session_factory()() as db:
        plan = ImageBackupPlan(tenant_id=tenant["id"], name="Nightly", agent_id=agent_id, repository_id=repo_id,
                               schedule={"type": "daily", "time": "01:00"}, job={"type": "backup_system"}, enabled=True)
        db.add(plan)
        db.commit()
        plan.created_at = utcnow() - timedelta(days=5)
        db.commit()
        bk.check_health(db)
        bk.check_health(db)
        assert db.query(AuditLog).filter_by(action="backup.job.missed").count() == 1
        outcomes = ("backup.job.succeeded", "backup.job.warning", "backup.job.failed", "backup.job.cancelled", "backup.job.missed")
        states = [a.action for a in db.query(AuditLog).filter(AuditLog.action.in_(outcomes)).order_by(AuditLog.seq)
                  if a.action == "backup.job.missed" or (a.details or {}).get("kind") == "backup_system"]
        assert states == ["backup.job.succeeded", "backup.job.failed", "backup.job.missed"]
        failed = db.query(AuditLog).filter_by(action="backup.job.failed").one()
        assert failed.target == "M-1" and failed.details["error"] == "VSS snapshot failed"

    log = client.get(f"{URL}/status-log", headers=admin, params={"tenantId": tenant["id"]}).json()
    assert [r["state"] for r in log] == ["succeeded", "failed", "missed"]
    with database.session_factory()() as db:
        assert restore_tests.weekly_backup_logs(db) == 1
        assert restore_tests.weekly_backup_logs(db) == 0  # once a week
        ev = db.query(GrcEvidence).filter(GrcEvidence.title.startswith("Backup log")).one()
        assert ev.control_id == "FC-BACKUP" and ev.data["counts"] == {"succeeded": 1, "failed": 1, "missed": 1}
        body = json.dumps(ev.data, sort_keys=True, separators=(",", ":"), default=str)
        import hashlib
        assert hashlib.sha256(body.encode()).hexdigest() == ev.sha256
        assert ("iso-27001", "A.8.13") in {(l.framework_key, l.requirement_id)
                                            for l in db.query(GrcEvidenceLink).filter_by(evidence_id=ev.id)}
        assert db.query(AuditLog).filter_by(action="backup.log_filed").count() == 1
