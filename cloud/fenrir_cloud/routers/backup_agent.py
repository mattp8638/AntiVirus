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

from types import SimpleNamespace

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import backup as bk
from .. import backup_gateway as gw
from .. import ratelimit
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


def _job_spec(db: Session, agent: BackupAgent, job: BackupJob) -> dict | None:
    """The job as the agent receives it, with the sealed repository access. None: no access."""
    repository = None
    if job.repository_id:
        repo = db.get(BackupRepository, job.repository_id)
        access = db.get(BackupRepoAccess, (job.repository_id, agent.id))
        if repo is None or access is None:
            return None
        repository = {"repository_id": repo.id, "path": repo.path, "sealed_secret": access.sealed,
                      "gateway": gw.route(db, repo, access),
                      "sealed_share": access.sealed_share}
    return {"id": job.id, "kind": job.kind, "repository": repository}


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
                job.error = "This machine has not been given access to the repository. Grant access on the Backups page."
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


def _record_boot_check(db: Session, job: BackupJob, agent: BackupAgent, b: dict) -> str:
    shot = None
    if b.get("screenshot_png"):
        try:
            raw = base64.b64decode(b["screenshot_png"])
            shot = raw if len(raw) <= bk.MAX_SCREENSHOT and raw.startswith(b"\x89PNG") else None
        except (binascii.Error, ValueError):
            shot = None
    outcome = b.get("outcome") if b.get("outcome") in ("verified", "screen") else "failed"
    db.add(BackupBootCheck(image_id=str(b["image_id"]), repository_id=job.repository_id, tenant_id=job.tenant_id,
                           agent_id=agent.id, job_id=job.id, outcome=outcome, method=_str(b.get("method"), 40),
                           seconds=int(b.get("seconds") or 0), firmware=_str(b.get("firmware"), 10),
                           accel=_str(b.get("accel"), 10), message=_str(b.get("message"), 1000), screenshot=shot))
    return outcome


IMAGE_INT_FIELDS = ("captured_bytes", "stored_new_bytes", "chunks_total", "chunks_new", "bytes_new_raw")


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
    if repo is not None:
        for im in images:
            if db.get(BackupImage, str(im["image_id"])) is not None:
                continue
            row = BackupImage(image_id=str(im["image_id"]), repository_id=repo.id, tenant_id=repo.tenant_id,
                              agent_id=agent.id, machine_id=_str(im.get("machine_id"), 200),
                              hostname=_str(im.get("hostname"), 255), created_unix=int(im.get("created_unix") or 0),
                              kind=_str(im.get("kind"), 20), consistency=_str(im.get("consistency"), 30),
                              disks=im.get("disks") or [], label=im.get("label"), vm_name=im.get("vm_name"),
                              **{f: int(im.get(f) or 0) for f in IMAGE_INT_FIELDS})
            db.add(row)
            db.flush()
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
            if _record_boot_check(db, job, agent, b) == "failed":
                bk.raise_alert(db, job.tenant_id, agent.device_id, bk.RULE_BOOT,
                               f"Backup of {name} did not boot", "high",
                               f"A boot check of image {kind.get('image_id')} failed: {_str(b.get('message'), 500)}")
        if kind.get("type") == "init_repository" and final:
            if state in ("succeeded", "warning"):
                ok = str(body.get("repo_uuid") or "") == repo.repo_uuid
                repo.status = "ready" if ok else "failed"
                repo.status_message = None if ok else "agent reported a different repository ID"
            else:
                repo.status, repo.status_message = "failed", job.error
    # Retention runs after each successful plan backup (held repositories wait).
    if bk.is_backup(kind) and state in ("succeeded", "warning") and job.plan_id and repo is not None:
        bk.queue_retention(db, job.plan_id, repo.id, agent, images)
    if state == "failed" and kind.get("type") not in ("check_access", "list_images", "browse_files"):
        bk.raise_alert(db, job.tenant_id, agent.device_id, bk.RULE_FAILED, f"{bk.label(kind)} failed: {name}",
                       "high" if bk.is_backup(kind) or kind.get("type") == "restore" else "medium",
                       f"{bk.label(kind)} on {name} failed. {job.error or ''}".strip())
    if final:
        bk.record(db, f"backup-agent:{agent.id}", f"backup.job.{state}", job.id, job.tenant_id, kind=kind.get("type"))
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
