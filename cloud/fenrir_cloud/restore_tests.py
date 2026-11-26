"""Backup status log and scheduled restore tests, recorded in the ISMS (backup/docs/design/restore-tests.md).

* Every finished backup job, and every overdue plan, goes into the hash-chained audit log as ``backup.job.<state>``.
* Once a week the last seven days of backup statuses are filed as ISMS evidence for backup (FC-BACKUP).
* Every restore test (a boot check with ``full_restore``: the image restored in full, booted in an isolated VM, a
  screenshot taken, the VM deleted) is filed as ISMS evidence for DR testing (FC-DRTEST), with the screenshot as its
  encrypted file, and written to the audit log. Together these are the DR test log.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, crypto, grc_automation
from .models import (AuditLog, BackupAgent, BackupBootCheck, BackupImage, BackupJob, GrcEvidence, ImageBackupPlan, Tenant,
                     utcnow)

DR_SIGNAL = "dr-restore-test"
BACKUP_SIGNAL = "backup-protection"
BACKUP_LOG_TITLE = "Backup log"
RESTORE_TEST_TITLE = "DR restore test"
LOG_EVERY = timedelta(days=7)
# A machine counts as tested when it had a successful restore test within this time (weekly, with a day's slack).
TEST_FRESH = timedelta(days=8)
RULE_VM_LEFT = "backup.restore_test_vm_left"


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() + "Z" if d else None


def _unix(t: int) -> str:
    return datetime.fromtimestamp(t, timezone.utc).replace(tzinfo=None).isoformat() + "Z"


def _s(v, n: int) -> str:
    return str(v or "")[:n]


# --------------------------------------------------------------------------- backup status log


def record_backup_status(db: Session, job: BackupJob, agent: BackupAgent, images: int) -> None:
    """A finished backup job, whatever its outcome, into the tamper-evident audit log."""
    plan = db.get(ImageBackupPlan, job.plan_id) if job.plan_id else None
    seconds = int((job.finished_at - job.started_at).total_seconds()) if job.finished_at and job.started_at else None
    audit.record(db, f"backup-agent:{agent.id}", f"backup.job.{job.state}", agent.display_name or agent.hostname,
                 tenant_id=job.tenant_id, job=job.id, plan=plan.name if plan else None, kind=(job.kind or {}).get("type"),
                 images=images, seconds=seconds, error=_s(job.error, 500) or None,
                 warnings=len(job.warnings or []), requestedBy=job.requested_by)


def record_missed(db: Session, plan: ImageBackupPlan, agent: BackupAgent | None, last_ok: datetime | None) -> None:
    """A plan that has not succeeded for too long: logged once per episode (when its overdue alert is raised)."""
    audit.record(db, "system:backup", "backup.job.missed", (agent.display_name or agent.hostname) if agent else plan.name,
                 tenant_id=plan.tenant_id, plan=plan.name, planId=plan.id, lastSucceeded=_iso(last_ok))


def status_rows(db: Session, tenant_id: str, since: datetime) -> list[dict]:
    from .backup import is_backup

    agents = {a.id: a for a in db.execute(select(BackupAgent).where(BackupAgent.tenant_id == tenant_id)).scalars()}
    plans = {p.id: p.name for p in db.execute(select(ImageBackupPlan).where(ImageBackupPlan.tenant_id == tenant_id)).scalars()}
    rows = []
    for j in db.execute(select(BackupJob).where(BackupJob.tenant_id == tenant_id, BackupJob.finished_at >= since)
                        .order_by(BackupJob.finished_at)).scalars():
        if not is_backup(j.kind):
            continue
        a = agents.get(j.agent_id)
        rows.append({"finishedAt": _iso(j.finished_at), "machine": (a.display_name or a.hostname) if a else j.agent_id,
                     "plan": plans.get(j.plan_id or ""), "kind": (j.kind or {}).get("type"), "state": j.state,
                     "error": _s(j.error, 300) or None, "job": j.id})
    missed = db.execute(select(AuditLog).where(AuditLog.tenant_id == tenant_id,
                                                     AuditLog.action == "backup.job.missed",
                                                     AuditLog.at >= since)).scalars().all()
    for m in missed:
        rows.append({"finishedAt": _iso(m.at), "machine": m.target, "plan": (m.details or {}).get("plan"), "kind": None,
                     "state": "missed", "error": "no successful backup within the plan's interval", "job": None})
    rows.sort(key=lambda r: r["finishedAt"] or "")
    return rows


def weekly_backup_logs(db: Session) -> int:
    """File the past week's backup statuses as ISMS evidence, once a week per customer that has backups."""
    now = utcnow()
    filed = 0
    tenant_ids = set(db.execute(select(BackupJob.tenant_id).where(BackupJob.finished_at >= now - LOG_EVERY)).scalars())
    for tenant_id in sorted(tenant_ids):
        recent = db.execute(select(GrcEvidence).where(GrcEvidence.tenant_id == tenant_id,
                                                      GrcEvidence.title.startswith(BACKUP_LOG_TITLE),
                                                      GrcEvidence.created_at > now - LOG_EVERY + timedelta(hours=1))).first()
        if recent:
            continue
        since = now - LOG_EVERY
        rows = status_rows(db, tenant_id, since)
        if not rows:
            continue
        counts: dict[str, int] = {}
        for r in rows:
            counts[r["state"]] = counts.get(r["state"], 0) + 1
        lines = [f"{len(rows)} backup statuses from {since:%Y-%m-%d} to {now:%Y-%m-%d}: "
                 + ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))]
        lines += [f"{r['finishedAt'][:16]} {r['machine']}: {r['state']}" + (f" ({r['error']})" if r["error"] else "")
                  for r in rows if r["state"] not in ("succeeded",)][:50]
        ev = grc_automation.record_activity_evidence(
            db, tenant_id, BACKUP_SIGNAL, f"{BACKUP_LOG_TITLE} {since:%Y-%m-%d} to {now:%Y-%m-%d}", lines,
            {"from": _iso(since), "to": _iso(now), "counts": counts, "statuses": rows}, actor="system:backup")
        if ev is not None:
            audit.record(db, "system:backup", "backup.log_filed", ev.title, tenant_id=tenant_id, evidence=ev.id,
                         sha256=ev.sha256, statuses=len(rows))
            filed += 1
    db.commit()
    return filed


_last_tick: datetime | None = None


def tick(db: Session) -> None:
    """From the 30-second backup scheduler: file weekly backup logs, looked at hourly."""
    global _last_tick
    now = utcnow()
    if _last_tick is not None and now - _last_tick < timedelta(hours=1):
        return
    _last_tick = now
    weekly_backup_logs(db)


# --------------------------------------------------------------------------- restore tests


def clean_restore_test(v) -> dict | None:
    """The agent's restore-test facts, from known fields only."""
    if not isinstance(v, dict):
        return None
    num = lambda k: v[k] if isinstance(v.get(k), int) and not isinstance(v.get(k), bool) and v[k] >= 0 else 0  # noqa: E731
    return {"format": _s(v.get("format"), 10), "bytesRestored": num("bytes_restored"), "restoreSeconds": num("restore_seconds"),
            "chunksChecked": num("chunks_checked"), "mismatches": num("mismatches"), "vmRemoved": v.get("vm_removed") is True,
            "removedUnix": num("removed_unix"), "removalError": _s(v.get("removal_error"), 500)}


def record_restore_test(db: Session, job: BackupJob, agent: BackupAgent, check: BackupBootCheck) -> GrcEvidence | None:
    """File a finished restore test as ISMS evidence (DR testing), the screenshot as its encrypted file, and log it."""
    from .backup import raise_alert
    from .routers.grc_programme import _aad, _evidence_dir

    rt = check.restore_test or {}
    image = db.get(BackupImage, check.image_id)
    machine = (image.vm_name or image.hostname) if image else check.image_id
    host = agent.display_name or agent.hostname
    passed = check.outcome == "verified" and not rt.get("mismatches")
    shot_sha = hashlib.sha256(check.screenshot).hexdigest() if check.screenshot else None
    requested = job.created_at
    record = {
        "machine": machine, "machineId": image.machine_id if image else None, "image": check.image_id,
        "recoveryPoint": _unix(image.created_unix) if image else None,
        "host": host, "job": job.id, "requestedAt": _iso(requested), "finishedAt": _iso(job.finished_at),
        "rtoSeconds": int((job.finished_at - requested).total_seconds()) if job.finished_at and requested else None,
        "result": "passed" if passed else "failed", "boot": {"outcome": check.outcome, "method": check.method,
                                                             "seconds": check.seconds, "firmware": check.firmware,
                                                             "accel": check.accel, "message": check.message},
        "restore": rt, "vmDeleted": bool(rt.get("vmRemoved")),
        "vmDeletedAt": _unix(rt["removedUnix"]) if rt.get("removedUnix") else None,
        "screenshotSha256": shot_sha,
    }
    lines = [f"{machine}: restore test {record['result']} on {host}",
             f"recovery point {record['recoveryPoint'] or 'unknown'}; boot {check.outcome} by {check.method} in {check.seconds}s",
             f"{rt.get('bytesRestored', 0)} bytes restored as {rt.get('format') or '?'} in {rt.get('restoreSeconds', 0)}s; "
             f"{rt.get('chunksChecked', 0)} chunks read back, {rt.get('mismatches', 0)} mismatched",
             f"test VM deleted at {record['vmDeletedAt']}" if record["vmDeleted"]
             else f"test VM NOT deleted: {rt.get('removalError') or 'unknown error'}",
             "screenshot attached" if shot_sha else "no screenshot was taken"]
    when = job.finished_at or utcnow()
    ev = grc_automation.record_activity_evidence(db, check.tenant_id, DR_SIGNAL,
                                                 f"{RESTORE_TEST_TITLE}: {machine} {when:%Y-%m-%d} ({record['result']})",
                                                 lines, record, actor="system:backup")
    if ev is None:
        return None
    record_sha = ev.sha256
    if check.screenshot:
        ev.kind, ev.filename = "file", f"restore-test-{(image.machine_id if image else 'vm')[:40]}-{when:%Y%m%d}.png"
        ev.content_type, ev.size, ev.sha256 = "image/png", len(check.screenshot), shot_sha
        ev.storage_name = hashlib.sha256(f"{ev.id}:{record_sha}".encode()).hexdigest()[:32]
        ev.description = f"{ev.description}\nRecord SHA-256: {record_sha}"
        path = _evidence_dir() / ev.storage_name
        with open(path, "w", encoding="utf-8") as out:
            path.chmod(0o600)
            json.dump(crypto.encrypt(bytes(check.screenshot), _aad(ev)), out)
    check.evidence_id = ev.id
    audit.record(db, f"backup-agent:{agent.id}", "backup.restore_test", machine, tenant_id=check.tenant_id,
                 result=record["result"], image=check.image_id, host=host, evidence=ev.id, recordSha256=record_sha,
                 screenshotSha256=shot_sha, vmDeleted=record["vmDeleted"], rtoSeconds=record["rtoSeconds"])
    if not record["vmDeleted"]:
        raise_alert(db, check.tenant_id, agent.device_id, RULE_VM_LEFT, f"Restore test VM left on {host}", "medium",
                    f"The restore test of {machine} could not delete its VM or restored disks on {host}: "
                    f"{rt.get('removalError') or 'unknown error'}. Remove them on the host; they hold a copy of the machine.",
                    dedupe_key=f"vm-left:{job.id}")
    return ev


def log(db: Session, tenant_ids: list[str], limit: int = 200) -> list[dict]:
    """The DR test log: restore tests, newest first, with their evidence."""
    rows = db.execute(select(BackupBootCheck).where(BackupBootCheck.tenant_id.in_(tenant_ids),
                                                    BackupBootCheck.restore_test.is_not(None))
                      .order_by(BackupBootCheck.at.desc()).limit(limit)).scalars().all()
    out = []
    for c in rows:
        ev = db.get(GrcEvidence, c.evidence_id) if c.evidence_id else None
        data = (ev.data or {}) if ev else {}
        out.append({"id": c.id, "tenantId": c.tenant_id, "at": _iso(c.at), "imageId": c.image_id,
                    "machine": data.get("machine"), "host": data.get("host"), "recoveryPoint": data.get("recoveryPoint"),
                    "result": data.get("result") or ("passed" if c.outcome == "verified" else "failed"),
                    "outcome": c.outcome, "message": c.message, "restore": c.restore_test,
                    "vmDeleted": bool((c.restore_test or {}).get("vmRemoved")), "rtoSeconds": data.get("rtoSeconds"),
                    "hasScreenshot": c.screenshot is not None, "evidenceId": c.evidence_id,
                    "evidenceSha256": ev.sha256 if ev else None})
    return out


def signal(db: Session, tenant: Tenant) -> dict:
    """ISMS signal: every machine backed up in the last 30 days had a passing restore test within 8 days."""
    now = utcnow()
    from .models import BackupRepository

    scheduled = db.execute(select(BackupRepository).where(BackupRepository.tenant_id == tenant.id,
                                                          BackupRepository.boot_full_restore.is_(True),
                                                          BackupRepository.boot_agent_id.is_not(None))).first()
    tests = db.execute(select(BackupBootCheck).where(BackupBootCheck.tenant_id == tenant.id,
                                                     BackupBootCheck.restore_test.is_not(None),
                                                     BackupBootCheck.at > now - TEST_FRESH)).scalars().all()
    if not scheduled and not tests:
        return {"passed": None, "evidence": ["No scheduled restore tests are set up (Backups: repository, boot verification)"]}
    images = db.execute(select(BackupImage).where(BackupImage.tenant_id == tenant.id,
                                                  BackupImage.created_unix > (now - timedelta(days=30)).timestamp())).scalars().all()
    machine_of = {i.image_id: (i.machine_id, i.vm_name or i.hostname) for i in images}
    names = {m: n for m, n in machine_of.values()}
    ok = {machine_of[t.image_id][0] for t in tests if t.image_id in machine_of and t.outcome == "verified"
          and not (t.restore_test or {}).get("mismatches")}
    failed = [t for t in tests if t.outcome != "verified" or (t.restore_test or {}).get("mismatches")]
    missing = sorted(n for m, n in names.items() if m not in ok)
    ev = [f"{len(ok)} of {len(names)} backed-up machines passed a restore test in the last {TEST_FRESH.days} days"]
    ev += [f"{n}: no passing restore test" for n in missing[:20]]
    ev += [f"{machine_of.get(t.image_id, ('', t.image_id))[1]}: restore test failed ({t.message[:120]})" for t in failed[:10]]
    return {"passed": bool(names) and not missing, "evidence": ev}
