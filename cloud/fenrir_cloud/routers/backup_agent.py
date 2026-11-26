"""Endpoints the backup agent (backup/crates/agent) calls, mounted under /backup so the agent's server URL is
https://<this server>/backup. Agents always initiate; the server never connects to them.

Also: the one-time installer downloads and the agent builds served for self-update.
"""

from __future__ import annotations

import base64
import binascii
import os
import time
import uuid as uuidlib

from datetime import timedelta
from types import SimpleNamespace

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import backup as bk
from .. import backup_cases as cases
from .. import backup_gateway as gw
from .. import ratelimit
from .. import restore_tests
from ..security import digest
from ..config import get_settings
from ..db import get_db
from ..models import (EnrollmentToken, BackupAgent, BackupBootCheck, BackupEnrollment, BackupImage, BackupJob, BackupRepoAccess,
                      BackupRepository, Tenant, utcnow)

router = APIRouter(prefix="/backup", tags=["Backup agent"])


def backup_settings(db: Session) -> dict:
    msp = db.execute(select(Tenant).where(Tenant.kind == "msp").order_by(Tenant.created_at)).scalars().first()
    stored = ((msp.settings or {}) if msp else {}).get("backup") or {}
    return {"autoUpdate": True, **stored}


def current_backup_agent(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> BackupAgent:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "agent token required")
    agent = db.execute(select(BackupAgent).where(
        BackupAgent.token_hash == bk.token_hash(authorization[7:].strip()))).scalars().first()
    if agent is None or agent.revoked:
        raise HTTPException(401, "agent not recognised or revoked")
    return agent


def _str(v, n: int) -> str:
    return str(v or "")[:n]


@router.post("/api/agent/enroll")
def enroll(body: dict = Body(...), db: Session = Depends(get_db)):
    if body.get("protocol") != bk.PROTOCOL_VERSION:
        raise HTTPException(400, f"server speaks protocol {bk.PROTOCOL_VERSION}, agent sent {body.get('protocol')}")
    machine_id, hostname = _str(body.get("machine_id"), 200).strip(), _str(body.get("hostname"), 255).strip()
    public_key = _str(body.get("public_key"), 64)
    try:
        key_ok = len(base64.b64decode(public_key, validate=True)) == 32
    except (binascii.Error, ValueError):
        key_ok = False
    if not machine_id or not hostname or not key_ok:
        raise HTTPException(400, "hostname, machine_id and a 32-byte public key are required")
    role = body.get("role")
    if role not in bk.ROLES:
        raise HTTPException(400, "unknown role")
    raw = str(body.get("token") or "")
    if raw.startswith("fet_"):
        # The all-in-one Fenrir installer: the backup agent enrols with the same deployment token as the security
        # agent. It does not use up one of the token's uses; the security agent's enrolment does.
        ratelimit.check(f"backup-enroll:{bk.token_hash(raw)[:16]}", 500, 3600)
        fet = db.execute(select(EnrollmentToken).where(EnrollmentToken.token_hash == digest(raw))).scalars().first()
        if fet is None:
            raise HTTPException(403, "enrollment token not recognised")
        if fet.revoked or (fet.expires_at and fet.expires_at < utcnow()):
            raise HTTPException(403, "the deployment token has expired or was revoked")
        if fet.include_backup is False:
            raise HTTPException(409, "device backup is not included in this deployment")
        if role == "recovery":
            raise HTTPException(403, "recovery sessions enrol with a recovery media link")
        tok = SimpleNamespace(id=fet.id, tenant_id=fet.tenant_id, device_id=None, label="bundled", uses=0, revoked=False)
    else:
        tok = db.execute(select(BackupEnrollment).where(BackupEnrollment.token_hash == bk.token_hash(raw))).scalars().first()
        if tok is None:
            raise HTTPException(403, "enrollment token not recognised")
        if tok.revoked or tok.expires_at < utcnow():
            raise HTTPException(403, "enrollment token has expired or was revoked; create a new download")
        # Recovery media links enrol recovery sessions only, and recovery sessions need one.
        if (tok.role == "recovery") != (role == "recovery"):
            raise HTTPException(403, "this enrollment token is for recovery media only, or this agent needs one")

    agent_token = bk.new_token()
    os_ = body.get("os") if isinstance(body.get("os"), dict) else {}
    os_ = {k: _str(os_.get(k), 100) for k in ("family", "name", "version", "arch")}
    version = _str(body.get("agent_version"), 64)
    # Reinstall on the same machine (same tenant) keeps the agent's identity and history. If its key pair changed,
    # secrets sealed to the old key are useless and are dropped; an administrator grants access again.
    existing = db.execute(select(BackupAgent).where(
        BackupAgent.machine_id == machine_id, BackupAgent.tenant_id == tok.tenant_id, BackupAgent.revoked.is_(False),
    ).order_by(BackupAgent.enrolled_at.desc())).scalars().first()
    now = utcnow()
    if existing:
        agent = existing
        if agent.public_key != public_key:
            for a in db.execute(select(BackupRepoAccess).where(BackupRepoAccess.agent_id == agent.id)).scalars():
                db.delete(a)
            action = "backup.agent.reenrolled_new_key"
        else:
            action = "backup.agent.reenrolled"
        agent.token_hash, agent.hostname, agent.role, agent.os = bk.token_hash(agent_token), hostname, role, os_
        agent.public_key, agent.agent_version, agent.last_seen_at = public_key, version, now
        agent.device_id = tok.device_id or agent.device_id
    else:
        agent = BackupAgent(tenant_id=tok.tenant_id, device_id=tok.device_id, token_hash=bk.token_hash(agent_token),
                            hostname=hostname, machine_id=machine_id, role=role, os=os_, public_key=public_key,
                            agent_version=version, last_seen_at=now)
        db.add(agent)
        db.flush()
        action = "backup.agent.enrolled"
    if agent.device_id is None and role != "recovery":
        agent.device_id = bk.matching_device(db, agent)
    tok.uses += 1
    if tok.label.startswith("push:"):
        tok.revoked = True  # pushed to one device through its Fenrir agent: single use
    bk.record(db, f"backup-agent:{agent.id}", action, hostname, agent.tenant_id, enrollment=tok.id)
    db.commit()
    return {"agent_id": agent.id, "agent_token": agent_token, "poll_seconds": bk.POLL_SECONDS}


def _access(db: Session, agent: BackupAgent, repo_id: str) -> dict | None:
    """A repository's access sealed to this agent, as the agent receives it. None: no access."""
    repo = db.get(BackupRepository, repo_id)
    access = db.get(BackupRepoAccess, (repo_id, agent.id))
    if repo is None or access is None:
        return None
    out = {"repository_id": repo.id, "path": repo.path, "sealed_secret": access.sealed,
           "gateway": gw.route(db, repo, access), "sealed_share": access.sealed_share}
    if repo.s3:
        out["s3"] = repo.s3
    return out


def _job_spec(db: Session, agent: BackupAgent, job: BackupJob) -> dict | None:
    """The job as the agent receives it, with the sealed repository access. None: no access (to the repository, or to
    a copy's destination)."""
    repository = None
    if job.repository_id:
        repository = _access(db, agent, job.repository_id)
        if repository is None:
            return None
    kind = dict(job.kind or {})
    unlock = kind.pop("unlock", None)
    if isinstance(unlock, dict) and repository is not None:
        # A passphrase check (console unlock): the machine opens the repository with the passphrase just typed,
        # sealed to it in the browser, instead of the one it was given.
        if not unlock.get("sealed"):
            return None
        repository = {**repository, "sealed_secret": unlock["sealed"]}
    spec = {"id": job.id, "kind": kind, "repository": repository}
    # Local recovery (backup/docs/design/local-recovery.md): a year-long enrolment code for recovery sessions,
    # replacing this machine's earlier one; the agent adds its own server address and pin.
    if (job.kind or {}).get("type") == "local_recovery":
        label = f"local-recovery:{agent.id}"
        for e in db.execute(select(BackupEnrollment).where(BackupEnrollment.label == label)).scalars():
            e.revoked = True
        if job.kind.get("action") != "remove":
            raw = bk.new_token()
            expires = utcnow() + timedelta(days=bk.LOCAL_RECOVERY_DAYS)
            db.add(BackupEnrollment(tenant_id=agent.tenant_id, device_id=agent.device_id, role="recovery", label=label,
                                    token_hash=bk.token_hash(raw), expires_at=expires, created_by="local recovery"))
            spec["recovery_settings"] = {"server": "", "pin": "", "token": raw, "expires": int(expires.timestamp())}
    # A new member of a dedup group: the member it takes the group's key from, which this machine must open.
    if (job.kind or {}).get("type") == "init_repository" and job.repository_id:
        repo = db.get(BackupRepository, job.repository_id)
        if repo is not None and repo.dedup_source_id:
            source = _access(db, agent, repo.dedup_source_id)
            if source is None:
                return None
            spec["group_source"] = source
    if (job.kind or {}).get("type") == "copy_images":
        target = _access(db, agent, str(job.kind.get("target_repository_id") or ""))
        if target is None:
            return None
        spec["copy_target"] = target
        # An offline media set: the set's other drives, tried in order when this one is not attached.
        tr = db.get(BackupRepository, str(job.kind.get("target_repository_id") or ""))
        if tr is not None and tr.media_set:
            others = db.execute(select(BackupRepository).where(
                BackupRepository.tenant_id == tr.tenant_id, BackupRepository.media_set == tr.media_set,
                BackupRepository.id != tr.id, BackupRepository.status == "ready")
                .order_by(BackupRepository.name)).scalars().all()
            alts = [a for a in (_access(db, agent, o.id) for o in others) if a is not None]
            if alts:
                spec["copy_alternatives"] = alts
    return spec


@router.post("/api/agent/heartbeat")
def heartbeat(body: dict = Body(...), agent: BackupAgent = Depends(current_backup_agent), db: Session = Depends(get_db)):
    now = utcnow()
    inv = body.get("inventory") if isinstance(body.get("inventory"), dict) else {}
    agent.last_seen_at, agent.inventory = now, inv
    agent.hostname = _str(inv.get("hostname"), 255) or agent.hostname
    agent.agent_version = _str(inv.get("agent_version"), 64) or agent.agent_version
    running = body.get("running_job") or ""

    # Jobs this agent was given but no longer reports: it restarted.
    for j in db.execute(select(BackupJob).where(
            BackupJob.agent_id == agent.id, BackupJob.state.in_(("dispatched", "running")), BackupJob.id != running,
            BackupJob.dispatched_at < now - bk.LOST_AFTER)).scalars():
        j.state, j.finished_at = "failed", now
        j.error = ("The agent stopped before finishing this job (restart or crash). "
                   "It will run again at the next scheduled time.")

    jobs = []
    busy = db.execute(select(BackupJob.id).where(BackupJob.agent_id == agent.id,
                                                 BackupJob.state.in_(("dispatched", "running")))).first()
    if busy is None and not running:
        for job in db.execute(select(BackupJob).where(BackupJob.agent_id == agent.id, BackupJob.state == "queued")
                              .order_by(BackupJob.created_at)).scalars():
            repo = db.get(BackupRepository, job.repository_id) if job.repository_id else None
            if repo is not None and repo.hold and job.kind.get("type") in ("apply_retention", "prune"):
                continue  # on hold: wait until released
            spec = _job_spec(db, agent, job)
            if spec is None:
                job.state, job.finished_at = "failed", now
                joining = (job.kind or {}).get("type") == "init_repository" and job.repository_id and \
                    getattr(db.get(BackupRepository, job.repository_id), "dedup_source_id", None)
                job.error = ("This machine has no access to the repository whose dedup group the new one joins. "
                             "Grant it access there first.") if joining else \
                    "This machine has not been given access to the repository. Grant access on the Backups page."
                continue
            job.state, job.dispatched_at = "dispatched", now
            jobs.append(spec)
            break

    cancel = [j for (j,) in db.execute(select(BackupJob.id).where(
        BackupJob.agent_id == agent.id, BackupJob.cancel_requested.is_(True),
        BackupJob.state.in_(("dispatched", "running"))))]
    update_ = bk.update_offer(inv) if backup_settings(db).get("autoUpdate", True) else None
    db.commit()
    gateway = gw.gateway_config(db, agent)
    db.commit()
    return {"jobs": jobs, "poll_seconds": bk.poll_seconds(db, agent), "cancel": cancel, "update": update_,
            "gateway": gateway}


def _record_boot_check(db: Session, job: BackupJob, agent: BackupAgent, b: dict) -> BackupBootCheck:
    shot = None
    if b.get("screenshot_png"):
        try:
            raw = base64.b64decode(b["screenshot_png"])
            shot = raw if len(raw) <= bk.MAX_SCREENSHOT and raw.startswith(b"\x89PNG") else None
        except (binascii.Error, ValueError):
            shot = None
    outcome = b.get("outcome") if b.get("outcome") in ("verified", "screen") else "failed"
    row = BackupBootCheck(image_id=str(b["image_id"]), repository_id=job.repository_id, tenant_id=job.tenant_id,
                          agent_id=agent.id, job_id=job.id, outcome=outcome, method=_str(b.get("method"), 40),
                          seconds=int(b.get("seconds") or 0), firmware=_str(b.get("firmware"), 10),
                          accel=_str(b.get("accel"), 10), message=_str(b.get("message"), 1000), screenshot=shot,
                          restore_test=restore_tests.clean_restore_test(b.get("restore_test"))
                          if (job.kind or {}).get("full_restore") else None)
    db.add(row)
    db.flush()
    return row


IMAGE_INT_FIELDS = ("captured_bytes", "stored_new_bytes", "chunks_total", "chunks_new", "bytes_new_raw")


def _applications(v) -> list | None:
    """The image's application components (VSS writers), rebuilt from known fields only, bounded."""
    if not isinstance(v, list) or not v:
        return None
    out = []
    for a in v[:500]:
        if isinstance(a, dict):
            out.append({"writer": _str(a.get("writer"), 200), "component": _str(a.get("component"), 500),
                        "caption": _str(a.get("caption"), 300), "included": bool(a.get("included")),
                        "note": _str(a.get("note"), 500) or None,
                        "fileSets": a["file_sets"] if isinstance(a.get("file_sets"), int) and 0 <= a["file_sets"] < 10_000 else 0})
    return out or None


@router.post("/api/agent/jobs/{job_id}/download")
async def upload_download(job_id: str, offset: int, request: Request, agent: BackupAgent = Depends(current_backup_agent),
                          db: Session = Depends(get_db)):
    """The agent appends to the encrypted stream of its download_files job (backup/docs/design/file-download.md).
    Uploads carry their offset, so a retried request is harmless; a gap is refused. Ciphertext only."""
    job = db.get(BackupJob, job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    if job.agent_id != agent.id:
        raise HTTPException(403, "job belongs to another agent")
    if (job.kind or {}).get("type") not in ("download_files", "export_saas") or job.state in bk.FINAL_STATES:
        raise HTTPException(409, "not a running download")
    body = await request.body()
    if len(body) > 16 << 20 or offset < 0:
        raise HTTPException(413, "upload in smaller parts")
    path = bk.download_path(job.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    have = path.stat().st_size if path.exists() else 0
    end = offset + len(body)
    if end > bk.DOWNLOAD_MAX:
        raise HTTPException(400, "the download is too large")
    if offset > have:
        raise HTTPException(409, f"expected offset {have}")
    if end > have:
        with open(path, "r+b" if path.exists() else "wb") as f:
            f.seek(offset)
            f.write(body)
    return {"have": max(end, have)}


@router.post("/api/agent/jobs/{job_id}/update")
def update_job(job_id: str, body: dict = Body(...), agent: BackupAgent = Depends(current_backup_agent),
               db: Session = Depends(get_db)):
    job = db.get(BackupJob, job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    if job.agent_id != agent.id:
        raise HTTPException(403, "job belongs to another agent")
    if job.state in bk.FINAL_STATES:
        raise HTTPException(409, "job already finished")
    state = body.get("state")
    if state not in ("running",) + bk.FINAL_STATES:
        raise HTTPException(400, "unknown state")
    now, final, kind = utcnow(), state in bk.FINAL_STATES, job.kind or {}
    name = agent.display_name or agent.hostname
    job.state = state
    if body.get("progress") is not None:
        job.progress = body["progress"]
    if state == "running" and job.started_at is None:
        job.started_at = now
    if final:
        job.finished_at = now
    if body.get("result") is not None:
        job.result = body["result"]
    if body.get("error"):
        job.error = _str(body["error"], 4000)
    if body.get("warnings"):
        job.warnings = [_str(w, 1000) for w in body["warnings"]][:100]

    repo = db.get(BackupRepository, job.repository_id) if job.repository_id else None
    images = body.get("images") or []
    # A copy reports the images it put in its destination.
    # (an offline media set: the drive that was attached, as the agent reports it)
    copied_to = (body.get("result") or {}).get("target_repository_id") if isinstance(body.get("result"), dict) else None
    image_repo = db.get(BackupRepository, str(copied_to or kind.get("target_repository_id"))) \
        if kind.get("type") == "copy_images" else repo
    if image_repo is not None and repo is not None and image_repo.tenant_id != repo.tenant_id:
        image_repo = None
    if image_repo is not None:
        for im in images:
            if db.get(BackupImage, str(im["image_id"])) is not None:
                continue
            row = BackupImage(image_id=str(im["image_id"]), repository_id=image_repo.id, tenant_id=image_repo.tenant_id,
                              agent_id=agent.id, machine_id=_str(im.get("machine_id"), 200),
                              hostname=_str(im.get("hostname"), 255), created_unix=int(im.get("created_unix") or 0),
                              kind=_str(im.get("kind"), 20), consistency=_str(im.get("consistency"), 30),
                              disks=im.get("disks") or [], label=im.get("label"), vm_name=im.get("vm_name"),
                              applications=_applications(im.get("applications")),
                              **{f: int(im.get(f) or 0) for f in IMAGE_INT_FIELDS})
            db.add(row)
            db.flush()
            if bk.is_backup(kind) or kind.get("type") == "copy_images":
                cases.hold_new_image(db, row)
            if bk.is_backup(kind):
                reason = bk.check_anomaly(db, repo.id, im)
                if reason:
                    what = im.get("vm_name") or im.get("hostname") or name
                    row.anomaly = reason
                    repo.hold, repo.hold_since = True, now
                    repo.hold_reason = f"Possible ransomware on {what}: {reason}"
                    bk.record(db, f"backup-agent:{agent.id}", "backup.repository.hold.anomaly", repo.name,
                              repo.tenant_id, machine=what, reason=reason)
                    bk.raise_alert(db, repo.tenant_id, agent.device_id, bk.RULE_RANSOMWARE,
                                   f"Possible ransomware detected on {what}", "critical",
                                   f"The latest backup of {what} looks like mass encryption: {reason}. Deletion of old "
                                   "backups in this repository is on hold, so earlier images are kept. Check the "
                                   "machine, then release the hold on the Backups page.")
        for removed in body.get("removed_images") or []:
            for model in (BackupImage, BackupBootCheck):
                for r in db.execute(select(model).where(model.image_id == str(removed),
                                                        model.repository_id == repo.id)).scalars():
                    db.delete(r)
        if kind.get("type") == "prune" and not kind.get("dry_run") and state == "succeeded":
            repo.last_prune_at = now
        b = body.get("boot_check")
        if kind.get("type") == "boot_check" and final and isinstance(b, dict) and str(b.get("image_id")) == kind.get("image_id"):
            check = _record_boot_check(db, job, agent, b)
            if check.restore_test is not None:
                restore_tests.record_restore_test(db, job, agent, check)
            if check.outcome == "failed":
                bk.raise_alert(db, job.tenant_id, agent.device_id, bk.RULE_BOOT,
                               f"Backup of {name} did not boot", "high",
                               f"A boot check of image {kind.get('image_id')} failed: {_str(b.get('message'), 500)}")
        if kind.get("type") == "check_access" and final and job.requested_by == bk.STORAGE_CHECK_BY:
            bk.record_storage_check(db, job, state, job.error)
        if final and (job.requested_by or "").startswith(cases.PREFIX):
            cases.record_job(db, job, state)
        if kind.get("type") == "scan_image" and final:
            bk.record_scan(db, job, agent, state, body.get("result") if isinstance(body.get("result"), dict) else None)
        if kind.get("type") == "list_images" and final and repo.status == "pending" and not repo.repo_uuid:
            # Adopting an existing repository: the machine reports its ID with the listing.
            got = str(body.get("repo_uuid") or "")
            dup = db.execute(select(BackupRepository).where(BackupRepository.tenant_id == repo.tenant_id,
                                                           BackupRepository.repo_uuid == got,
                                                           BackupRepository.id != repo.id)).scalars().first() if got else None
            if state not in ("succeeded", "warning"):
                repo.status, repo.status_message = "failed", job.error
            elif not got:
                repo.status, repo.status_message = "failed", "the machine did not report the repository's ID; update its agent"
            elif dup is not None:
                repo.status, repo.status_message = "failed", f"this repository is already registered as {dup.name}"
            else:
                repo.repo_uuid, repo.status, repo.status_message = got, "ready", None
        if kind.get("type") == "init_repository" and final:
            if state in ("succeeded", "warning"):
                ok = str(body.get("repo_uuid") or "") == repo.repo_uuid
                repo.status = "ready" if ok else "failed"
                repo.status_message = None if ok else "agent reported a different repository ID"
            else:
                repo.status, repo.status_message = "failed", job.error
    # Each new backup's file catalogue is built on the machine that took it, for searching across backups.
    if bk.is_backup(kind) and state in ("succeeded", "warning") and repo is not None \
            and "search_files" in bk.capabilities(agent):
        for im in images:
            if db.get(BackupImage, str(im.get("image_id"))) is not None:
                bk.queue(db, agent, {"type": "index_image", "image_id": str(im.get("image_id"))}, repo.id,
                         f"backup-agent:{agent.id}", job.plan_id)
    # A plan can scan each new backup for malware on the machine that took it.
    settings = kind.get("settings") if isinstance(kind.get("settings"), dict) else {}
    if bk.is_backup(kind) and state in ("succeeded", "warning") and settings.get("scan_after_backup") \
            and repo is not None and "scan_images" in bk.capabilities(agent):
        for im in images:
            row = db.get(BackupImage, str(im.get("image_id")))
            if row is not None:
                bk.queue_scan(db, agent, row, f"backup-agent:{agent.id}", plan_id=job.plan_id)
    # Retention runs after each successful plan backup (held repositories wait).
    if bk.is_backup(kind) and state in ("succeeded", "warning") and job.plan_id and repo is not None:
        bk.queue_copy(db, job.plan_id, repo.id, agent, images)
        bk.queue_standby(db, job.plan_id, repo.id, images)
        bk.queue_retention(db, job.plan_id, repo.id, agent, images)
    if state == "failed" and kind.get("type") not in ("check_access", "list_images", "browse_files"):
        alert = bk.raise_alert(db, job.tenant_id, agent.device_id, bk.RULE_FAILED, f"{bk.label(kind)} failed: {name}",
                               "high" if bk.is_backup(kind) or kind.get("type") == "restore" else "medium",
                               f"{bk.label(kind)} on {name} failed. {job.error or ''}".strip())
        if bk.is_backup(kind) and job.plan_id:
            bk.backup_incident(db, job, agent, alert)
    if bk.is_backup(kind) and state in ("succeeded", "warning") and job.plan_id:
        bk.backup_succeeded(db, agent)
    if kind.get("type") == "boot_check" and final and (job.requested_by or "").startswith(bk.RECOVERY_BY):
        b = body.get("boot_check") if isinstance(body.get("boot_check"), dict) else None
        bk.record_recovery(db, job, agent, state, b)
    if final and isinstance(kind.get("unlock"), dict):
        # The typed passphrase is no longer needed once checked.
        job.kind = {**kind, "unlock": {"user": kind["unlock"].get("user")}}
        if repo is not None:
            bk.record(db, f"backup-agent:{agent.id}",
                      "backup.repository.unlocked" if state in ("succeeded", "warning") else "backup.repository.unlock_failed",
                      repo.name, repo.tenant_id, job=job.id)
    if final and bk.is_backup(kind):
        # The backup status log: machine, plan, duration and error in the tamper-evident audit log.
        restore_tests.record_backup_status(db, job, agent, len(images))
    elif final:
        bk.record(db, f"backup-agent:{agent.id}", f"backup.job.{state}", job.id, job.tenant_id, kind=kind.get("type"))
        from .. import restore_evidence

        restore_evidence.record(db, job)  # BDR-03: recovery point, times, RPO/RTO and what was written
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------
# Downloads
# --------------------------------------------------------------------------

@router.get("/agent/{triple}/{file}")
def agent_build(triple: str, file: str):
    """Agent builds, for installers (before enrolment) and self-update. Not secret: every installer and update checks
    the file's SHA-256, which it gets from the server over TLS."""
    t = bk.ALL_TARGETS.get(triple)
    if t is None or t.file != file or not bk.binary_path(t).is_file():
        raise HTTPException(404, "no such agent build")
    return FileResponse(bk.binary_path(t), media_type="application/octet-stream", filename=file)


def server_url(request: Request) -> str:
    base = (get_settings().public_base_url or str(request.base_url)).rstrip("/")
    return base + "/backup"


def enrollment_for(db: Session, raw: str) -> BackupEnrollment:
    tok = db.execute(select(BackupEnrollment).where(BackupEnrollment.token_hash == bk.token_hash(raw))).scalars().first()
    if tok is None or tok.revoked or tok.expires_at < utcnow():
        raise HTTPException(404, "This download link has expired or was revoked. Create a new one in the console.")
    return tok


def tls_pin() -> str:
    """SHA-256 of the server's TLS certificate for agents to pin; empty when served behind a trusted certificate."""
    return os.getenv("FENRIR_BACKUP_TLS_PIN", "").strip().lower()


@router.get("/install/{token}/{platform}")
def install(token: str, platform: str, request: Request, db: Session = Depends(get_db)):
    if platform not in bk.PLATFORMS:
        raise HTTPException(404, "unknown platform")
    tok = enrollment_for(db, token)
    p = bk.PLATFORMS[platform]
    role = p["role"] or tok.role
    if not any(bk.binary_info(t) for t in p["targets"]):
        raise HTTPException(503, f"The {p['name']} backup agent is not on this server yet.")
    script = bk.install_script(platform, server_url(request), tls_pin(), token, role)
    return PlainTextResponse(script, headers={"Content-Disposition": f'attachment; filename="{p["script"]}"',
                                              "Cache-Control": "no-store"})


@router.get("/install/{token}/{platform}/{file}")
def setup_program(token: str, platform: str, file: str, request: Request, db: Session = Depends(get_db)):
    """Fenrir-Backup-Setup.exe: the Windows agent with this enrollment's settings appended. Double-click installs."""
    p = bk.PLATFORMS.get(platform)
    if p is None or p["setup"] != file:
        raise HTTPException(404, "unknown setup program")
    tok = enrollment_for(db, token)
    info = bk.binary_info(bk.WIN[0])
    if info is None:
        raise HTTPException(503, "The Windows backup agent is not on this server yet.")
    exe = bk.binary_path(bk.WIN[0]).read_bytes()
    data = bk.setup_exe(exe, server_url(request), tls_pin(), token, p["role"] or tok.role)
    return Response(data, media_type="application/vnd.microsoft.portable-executable",
                    headers={"Content-Disposition": f'attachment; filename="{file}"', "Cache-Control": "no-store"})


@router.get("/recovery/{token}/{file}")
def recovery_media(token: str, file: str, request: Request, db: Session = Depends(get_db)):
    """fenrir-recovery.iso with this server's settings in its placeholder block, or the same settings as
    fenrir-recovery.json for a USB stick. The link is a recovery enrolment token."""
    tok = enrollment_for(db, token)
    if tok.role != "recovery":
        raise HTTPException(404, "This link is not for recovery media.")
    cfg = bk.recovery_settings(server_url(request), tls_pin(), token, tok.expires_at)
    if file == bk.RECOVERY_SETTINGS:
        return JSONResponse(cfg, headers={"Content-Disposition": f'attachment; filename="{file}"', "Cache-Control": "no-store"})
    if file != bk.RECOVERY_ISO:
        raise HTTPException(404, "no such file")
    path = bk.recovery_iso_path()
    if not path.is_file():
        raise HTTPException(503, "The recovery ISO is not on this server yet.")
    offset = bk.recovery_block_offset(path)
    if offset is None:
        raise HTTPException(500, "The recovery ISO on this server has no settings block.")
    return StreamingResponse(bk.personalised_iso(path, offset, bk.recovery_block(cfg)), media_type="application/octet-stream",
                             headers={"Content-Disposition": f'attachment; filename="{file}"', "Cache-Control": "no-store",
                                      "Content-Length": str(path.stat().st_size)})


@router.get("/uninstall/{platform}")
def uninstall(platform: str):
    if platform not in bk.UNINSTALLERS:
        raise HTTPException(404, "unknown platform")
    name, body = bk.UNINSTALLERS[platform]
    return PlainTextResponse(body, headers={"Content-Disposition": f'attachment; filename="{name}"'})


def valid_uuid(v: str) -> bool:
    try:
        uuidlib.UUID(v)
        return True
    except (ValueError, TypeError):
        return False



# --------------------------------------------------------------------------
# NAS gateway relay (backup_gateway.py). Bodies are end-to-end encrypted between the two agents.
# --------------------------------------------------------------------------


async def _body(request: Request) -> bytes:
    size = int(request.headers.get("content-length") or 0)
    if size > gw.MAX_MESSAGE:
        raise HTTPException(413, "message too large")
    data = bytearray()
    async for part in request.stream():
        data += part
        if len(data) > gw.MAX_MESSAGE:
            raise HTTPException(413, "message too large")
    return bytes(data)


@router.post("/api/agent/relay/{gateway_id}")
async def relay_send(gateway_id: str, request: Request, agent: BackupAgent = Depends(current_backup_agent),
                     db: Session = Depends(get_db)):
    """A client's message for its gateway; answers with the gateway's (encrypted) reply."""
    key, now = (agent.id, gateway_id), time.monotonic()
    if now - gw.RELAY.allowed.get(key, -1e9) > 60:
        if not gw.may_relay(db, agent, gateway_id):
            raise HTTPException(403, "this machine is not routed through that gateway")
        gw.RELAY.allowed[key] = now
    db.close()  # do not hold a database connection while waiting for the gateway
    body = await _body(request)
    try:
        reply = await gw.RELAY.forward(gateway_id, body)
    except OverflowError:
        raise HTTPException(503, "the relay is busy; try again shortly") from None
    if reply is None:
        raise HTTPException(504, "the gateway did not answer: is it online?")
    return Response(reply, media_type="application/octet-stream")


@router.get("/api/agent/relay/next")
async def relay_next(agent: BackupAgent = Depends(current_backup_agent), db: Session = Depends(get_db)):
    """Long poll for the gateway: the next message from a client, or 204 after 25 seconds."""
    agent_id = agent.id
    db.close()
    item = await gw.RELAY.next(agent_id)
    if item is None:
        return Response(status_code=204)
    rid, body = item
    return Response(body, media_type="application/octet-stream", headers={"X-Relay-Id": rid})


@router.post("/api/agent/relay/reply/{rid}")
async def relay_reply(rid: str, request: Request, agent: BackupAgent = Depends(current_backup_agent),
                      db: Session = Depends(get_db)):
    agent_id = agent.id
    db.close()
    body = await _body(request)
    if not gw.RELAY.answer(agent_id, rid, body):
        raise HTTPException(404, "nobody is waiting for that answer any more")
    return Response(status_code=204)
