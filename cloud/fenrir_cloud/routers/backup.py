"""Console API for device backup (/api/console/backup/*).

Permissions: `read` to view; `respond` to run backups, verifications and connection tests; `scripts` for restores to
files and boot checks; `configure` for install links, repositories, access, plans and settings; `destructive` (with
re-authentication) to overwrite a disk, release a hold or reclaim space. Every change is audited.

Repository passphrases and share passwords arrive here already sealed in the browser to each agent's key.
"""

from __future__ import annotations

import base64
import binascii
import re
import uuid as uuidlib
from types import SimpleNamespace
from datetime import datetime, timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import backup as bk
from .. import backup_gateway as gwmod
from ..db import get_db
import time
from .. import ratelimit
from ..config import get_settings
from ..deps import REAUTH_HEADER, REAUTH_MINUTES, Principal, current_principal, require_reauth, scoped_tenant
from ..security import digest, issue_token, read_token, reauth_state
from ..models import (BackupAgent, BackupBootCheck, BackupEnrollment, BackupImage, BackupJob, BackupRepoAccess,
                      BackupRepository, Device, ImageBackupPlan, Tenant, utcnow)
from .backup_agent import backup_settings, server_url, tls_pin

router = APIRouter(prefix="/api/console/backup", tags=["Backup"])


def iso(dt):
    return dt.isoformat() + "Z" if dt else None


def bad(msg: str):
    raise HTTPException(400, msg)


def _uuid(v, what="id") -> str:
    try:
        return str(uuidlib.UUID(str(v)))
    except (ValueError, TypeError):
        bad(f"invalid {what}")


def _agent(db: Session, p: Principal, agent_id: str, live: bool = True) -> BackupAgent:
    a = db.get(BackupAgent, str(agent_id))
    if a is None or a.tenant_id not in p.tenant_ids or (live and a.revoked):
        raise HTTPException(404, "No such machine")
    return a


def _repo(db: Session, p: Principal, repo_id: str) -> BackupRepository:
    r = db.get(BackupRepository, str(repo_id))
    if r is None or r.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "No such repository")
    return r


def _sealed(v) -> dict:
    if not isinstance(v, dict) or v.get("v") != 1 or not all(isinstance(v.get(k), str) and v[k] for k in ("epk", "nonce", "ct")):
        bad("sealed secret missing or malformed (it is created in the browser)")
    if len(v["ct"]) > 16_384:
        bad("sealed secret too large")
    return {"v": 1, "epk": v["epk"], "nonce": v["nonce"], "ct": v["ct"]}


def is_share_path(path: str) -> bool:
    p = path.strip()
    return p.startswith("\\\\") or p.startswith("//") or p.lower().startswith("smb://")


def is_s3_path(path: str) -> bool:
    """Object storage: S3-compatible (s3://bucket/prefix) or Azure Blob (azure://container/prefix)."""
    p = path.strip()
    return p.startswith("s3://") or p.startswith("azure://")


_BUCKET = re.compile(r"^[a-z0-9.-]{3,63}$")
_CONTAINER = re.compile(r"^(?!.*--)[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")


def _s3_settings(path: str, raw, prune_every_days: int) -> dict | None:
    """S3 settings for an s3:// repository (protocol::S3Settings), checked. The maintenance interval must be shorter
    than an Object Lock: maintenance extends the locks of backups in use (Fenrir-Backup phase-4-storage)."""
    if not is_s3_path(path):
        if raw:
            bad("object storage settings need an s3://bucket/prefix or azure://container/prefix location")
        return None
    if not isinstance(raw, dict):
        bad("an s3:// or azure:// location needs its endpoint")
    azure = path.strip().startswith("azure://")
    endpoint = str(raw.get("endpoint") or "").strip().rstrip("/")
    # Azure endpoints may carry the account in the path (the Azurite emulator); S3 endpoints are a host only.
    m = re.match(r"^https?://([^/\s]+)(/[^\s]*)?$" if azure else r"^https?://([^/\s]+)$", endpoint)
    if not m:
        bad("the endpoint is https://host (or http://host:port), without a path")
    if azure:
        if not _CONTAINER.match(path.strip()[8:].split("/", 1)[0]):
            bad("the container name is 3 to 63 lower-case letters, digits or single hyphens")
    elif not _BUCKET.match(path.strip()[5:].split("/", 1)[0]):
        bad("the bucket name is 3 to 63 lower-case letters, digits, dots or hyphens")
    mode = raw.get("lock_mode") or None
    days = raw.get("lock_days") or 0
    if mode not in (None, "none", "governance", "compliance"):
        bad("Object Lock mode must be none, governance or compliance")
    if mode in ("governance", "compliance"):
        if not isinstance(days, int) or not 1 <= days <= 36_500:
            bad("Object Lock needs 1 to 36500 days")
        if prune_every_days == 0 or prune_every_days >= days:
            bad(f"with an Object Lock of {days} days, maintenance must run more often than that (it extends the locks "
                f"of backups in use); it runs every {prune_every_days or '0 (never)'} days")
    else:
        mode, days = None, 0
    return {"endpoint": endpoint, "region": str(raw.get("region") or "us-east-1").strip()[:64],
            "path_style": bool(raw.get("path_style")), "lock_mode": mode, "lock_days": days}


def _share_mode(body: dict) -> tuple[str, str | None]:
    mode = body.get("share_auth") or "none"
    if mode not in ("none", "machine", "password"):
        bad("share_auth must be none, machine or password")
    user = str(body.get("share_user") or "").strip()[:200] or None
    if mode == "password" and not user:
        bad("enter the share username")
    return mode, (user if mode == "password" else None)


# --------------------------------------------------------------------------
# Serialisation
# --------------------------------------------------------------------------


def agent_out(db: Session, a: BackupAgent, now=None) -> dict:
    inv = a.inventory or {}
    last = db.execute(select(BackupJob).where(BackupJob.agent_id == a.id, BackupJob.finished_at.is_not(None))
                      .order_by(BackupJob.finished_at.desc()).limit(20)).scalars().all()
    last_backup = next((j for j in last if bk.is_backup(j.kind)), None)
    running = db.execute(select(BackupJob).where(BackupJob.agent_id == a.id,
                                                 BackupJob.state.in_(("dispatched", "running")))).scalars().first()
    return {
        "id": a.id, "tenantId": a.tenant_id, "deviceId": a.device_id, "name": a.display_name or a.hostname,
        "hostname": a.hostname, "role": a.role, "os": a.os or {}, "agentVersion": a.agent_version,
        "enrolledAt": iso(a.enrolled_at), "lastSeenAt": iso(a.last_seen_at), "online": bk.online(a, now) and not a.revoked,
        "revoked": a.revoked, "publicKey": a.public_key, "capabilities": inv.get("capabilities") or [],
        "vmCount": len(inv.get("vms") or []), "disks": [d.get("path") for d in inv.get("disks") or [] if d.get("path")],
        "diskInfo": [{"path": d.get("path"), "size": d.get("size") or 0, "model": d.get("model") or "",
                      "serial": d.get("serial") or "", "system": bool(d.get("system")), "inUse": bool(d.get("in_use"))}
                     for d in inv.get("disks") or [] if isinstance(d, dict) and d.get("path")],
        "firmware": inv.get("firmware"), "secureBoot": inv.get("secure_boot"),
        "localRecovery": inv.get("local_recovery") if isinstance(inv.get("local_recovery"), dict) else None,
        "runningVms": [{"sessionId": v.get("session_id"), "imageId": v.get("image_id"), "startedUnix": v.get("started_unix"),
                        "vncPort": v.get("vnc_port") or 0} for v in inv.get("running_vms") or [] if isinstance(v, dict)],
        "lastBackup": ({"jobId": last_backup.id, "state": last_backup.state, "at": iso(last_backup.finished_at),
                        "error": last_backup.error} if last_backup else None),
        "runningJob": ({"id": running.id, "label": bk.label(running.kind), "state": running.state,
                        "progress": running.progress} if running else None),
    }


def job_out(j: BackupJob, names: dict[str, str]) -> dict:
    return {"id": j.id, "agentId": j.agent_id, "agentName": names.get(j.agent_id, ""), "repositoryId": j.repository_id,
            "planId": j.plan_id, "kind": j.kind, "label": bk.label(j.kind), "state": j.state,
            "createdAt": iso(j.created_at), "startedAt": iso(j.started_at), "finishedAt": iso(j.finished_at),
            "progress": j.progress, "result": j.result, "error": j.error, "warnings": j.warnings or [],
            "requestedBy": j.requested_by, "cancelRequested": j.cancel_requested}


def image_out(i: BackupImage, checks: dict[str, BackupBootCheck]) -> dict:
    b = checks.get(i.image_id)
    return {"imageId": i.image_id, "repositoryId": i.repository_id, "agentId": i.agent_id, "machineId": i.machine_id,
            "hostname": i.hostname, "created": i.created_unix, "kind": i.kind, "consistency": i.consistency,
            "capturedBytes": i.captured_bytes, "storedNewBytes": i.stored_new_bytes, "disks": i.disks, "label": i.label,
            "vmName": i.vm_name, "anomaly": i.anomaly, "applications": i.applications or [],
            "lastBootCheck": ({"outcome": b.outcome, "at": iso(b.at), "message": b.message} if b else None)}


_MEMBER = re.compile(r"^(.+)[\\/]repos[\\/]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\\/]?$", re.I)


def dedup_member(path: str) -> str | None:
    """The dedup group folder of a member path `<group>/repos/<uuid>` (same rule as protocol::dedup)."""
    m = _MEMBER.match(path or "")
    return m.group(1) if m else None


def member_path(root: str, repo_uuid: str) -> str:
    sep = "\\" if "\\" in root and "/" not in root else "/"
    return f"{root.rstrip('/' + chr(92))}{sep}repos{sep}{repo_uuid}"


def repo_out(db: Session, r: BackupRepository) -> dict:
    count, stored, last = db.execute(select(func.count(), func.coalesce(func.sum(BackupImage.stored_new_bytes), 0),
                                            func.max(BackupImage.created_unix)).where(BackupImage.repository_id == r.id)).one()
    anomalies = db.execute(select(func.count()).select_from(BackupImage).where(
        BackupImage.repository_id == r.id, BackupImage.anomaly.is_not(None))).scalar()
    verified = db.execute(select(func.max(BackupBootCheck.at)).where(BackupBootCheck.repository_id == r.id,
                                                                     BackupBootCheck.outcome == "verified")).scalar()
    agents = db.execute(select(BackupAgent).join(BackupRepoAccess, BackupRepoAccess.agent_id == BackupAgent.id).where(
        BackupRepoAccess.repository_id == r.id, BackupAgent.revoked.is_(False))).scalars().all()
    return {"id": r.id, "tenantId": r.tenant_id, "name": r.name, "path": r.path, "repoUuid": r.repo_uuid,
            "status": r.status, "statusMessage": r.status_message, "createdAt": iso(r.created_at), "images": count,
            "storedBytes": int(stored or 0), "lastImage": last, "hold": r.hold, "holdReason": r.hold_reason,
            "holdSince": iso(r.hold_since), "maintenanceAgentId": r.maintenance_agent_id,
            "pruneEveryDays": r.prune_every_days, "lastPruneAt": iso(r.last_prune_at), "anomalies": anomalies,
            "bootAgentId": r.boot_agent_id, "bootEveryDays": r.boot_every_days, "lastVerifiedBoot": iso(verified),
            "shareAuth": r.share_auth, "shareUser": r.share_user, "isShare": is_share_path(r.path), "s3": r.s3,
            "dedupGroup": dedup_member(r.path),
            "agents": [{"id": a.id, "name": a.display_name or a.hostname,
                        "viaGateway": bool((db.get(BackupRepoAccess, (r.id, a.id)) or SimpleNamespace(via_gateway=None)).via_gateway)}
                       for a in agents],
            "gateway": _gateway_out(db, r)}


def _gateway_out(db: Session, r: BackupRepository) -> dict | None:
    if not r.gateway_agent_id:
        return None
    g = db.get(BackupAgent, r.gateway_agent_id)
    if g is None:
        return None
    return {"agentId": g.id, "name": g.display_name or g.hostname, "online": bk.online(g) and not g.revoked,
            "port": g.gateway_port or 0, "address": g.gateway_address, "addresses": gwmod.addresses(g)}


def plan_out(p: ImageBackupPlan, names: dict[str, str]) -> dict:
    return {"id": p.id, "tenantId": p.tenant_id, "name": p.name, "agentId": p.agent_id,
            "agentName": names.get(p.agent_id, ""), "repositoryId": p.repository_id, "job": p.job,
            "label": bk.label(p.job), "schedule": p.schedule, "retention": p.retention, "enabled": p.enabled,
            "copyToRepositoryId": p.copy_to_repository_id,
            "nextRunAt": iso(p.next_run_at), "lastRunAt": iso(p.last_run_at)}


def _names(db: Session, tenants) -> dict[str, str]:
    return {a.id: a.display_name or a.hostname for a in
            db.execute(select(BackupAgent).where(BackupAgent.tenant_id.in_(tenants))).scalars()}


def _boot_latest(db: Session, image_ids: list[str]) -> dict[str, BackupBootCheck]:
    out: dict[str, BackupBootCheck] = {}
    if image_ids:
        for b in db.execute(select(BackupBootCheck).where(BackupBootCheck.image_id.in_(image_ids))
                            .order_by(BackupBootCheck.at.desc(), BackupBootCheck.id.desc())).scalars():
            out.setdefault(b.image_id, b)
    return out


# --------------------------------------------------------------------------
# Overview and machines
# --------------------------------------------------------------------------


@router.get("/overview")
def overview(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    tenants = scoped_tenant(p, tenantId)
    now = utcnow()
    agents = db.execute(select(BackupAgent).where(BackupAgent.tenant_id.in_(tenants),
                                                  BackupAgent.revoked.is_(False))).scalars().all()
    repos = db.execute(select(BackupRepository).where(BackupRepository.tenant_id.in_(tenants))).scalars().all()
    since = now - timedelta(days=1)
    recent = db.execute(select(BackupJob).where(BackupJob.tenant_id.in_(tenants), BackupJob.finished_at > since)).scalars().all()
    backups = [j for j in recent if bk.is_backup(j.kind)]
    stored = db.execute(select(func.coalesce(func.sum(BackupImage.stored_new_bytes), 0)).where(
        BackupImage.tenant_id.in_(tenants))).scalar()
    images = db.execute(select(func.count()).select_from(BackupImage).where(BackupImage.tenant_id.in_(tenants))).scalar()
    active = db.execute(select(func.count()).select_from(BackupJob).where(
        BackupJob.tenant_id.in_(tenants), BackupJob.state.in_(bk.ACTIVE_STATES))).scalar()
    return {"machines": len(agents), "online": sum(1 for a in agents if bk.online(a, now)),
            "repositories": len(repos), "onHold": sum(1 for r in repos if r.hold), "images": images,
            "storedBytes": int(stored or 0), "activeJobs": active,
            "last24h": {"succeeded": sum(1 for j in backups if j.state == "succeeded"),
                        "warning": sum(1 for j in backups if j.state == "warning"),
                        "failed": sum(1 for j in backups if j.state == "failed")},
            "holds": [{"id": r.id, "name": r.name, "reason": r.hold_reason, "since": iso(r.hold_since)} for r in repos if r.hold],
            "autoUpdate": backup_settings(db).get("autoUpdate", True)}


def plan_period(schedule: dict) -> int | None:
    """Seconds between a plan's scheduled backups (None: manual)."""
    t = (schedule or {}).get("type")
    if t == "interval":
        return int(schedule.get("hours") or 0) * 3600 + int(schedule.get("minutes") or 0) * 60 or None
    return {"daily": 86_400, "weekly": 7 * 86_400}.get(t)


SEVERITY = {"hold": 0, "failing": 1, "boot_failed": 2, "overdue": 3, "offline": 4, "no_plan": 5}


@router.get("/msp")
def msp_dashboard(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Backup health across every customer this person manages (the MSP view): per customer and per machine."""
    p.require("read")
    tenants = sorted(p.tenant_ids)
    names = {t.id: t.name for t in db.execute(select(Tenant).where(Tenant.id.in_(tenants))).scalars()}
    now = utcnow()
    agents = [a for a in db.execute(select(BackupAgent).where(BackupAgent.tenant_id.in_(tenants),
                                                              BackupAgent.revoked.is_(False))).scalars()
              if a.role != "recovery"]
    plans = db.execute(select(ImageBackupPlan).where(ImageBackupPlan.tenant_id.in_(tenants),
                                                     ImageBackupPlan.enabled.is_(True))).scalars().all()
    repos = db.execute(select(BackupRepository).where(BackupRepository.tenant_id.in_(tenants))).scalars().all()
    since14 = now - timedelta(days=14)
    jobs = db.execute(select(BackupJob).where(BackupJob.tenant_id.in_(tenants), BackupJob.finished_at > since14)).scalars().all()
    backups = [j for j in jobs if bk.is_backup(j.kind)]
    last_ok: dict[str, datetime] = dict(db.execute(
        select(BackupJob.plan_id, func.max(BackupJob.finished_at))
        .where(BackupJob.tenant_id.in_(tenants), BackupJob.plan_id.is_not(None),
               BackupJob.state.in_(("succeeded", "warning")))
        .group_by(BackupJob.plan_id)).all())
    stored = dict(db.execute(select(BackupImage.tenant_id, func.coalesce(func.sum(BackupImage.stored_new_bytes), 0))
                             .where(BackupImage.tenant_id.in_(tenants)).group_by(BackupImage.tenant_id)).all())
    month = now - timedelta(days=30)
    checks = db.execute(select(BackupBootCheck).where(BackupBootCheck.tenant_id.in_(tenants),
                                                      BackupBootCheck.at > month)).scalars().all()
    images_of = dict(db.execute(select(BackupImage.image_id, BackupImage.agent_id)
                                .where(BackupImage.tenant_id.in_(tenants))).all())
    verified_agents = {images_of.get(c.image_id) for c in checks if c.outcome == "verified"}
    latest_check: dict[str, BackupBootCheck] = {}
    for c in sorted(checks, key=lambda c: c.at):
        if images_of.get(c.image_id):
            latest_check[images_of[c.image_id]] = c
    anomalies = dict(db.execute(select(BackupImage.tenant_id, func.count()).where(
        BackupImage.tenant_id.in_(tenants), BackupImage.anomaly.is_not(None),
        BackupImage.created_unix > int((now - timedelta(days=7)).timestamp())).group_by(BackupImage.tenant_id)).all())

    attention: list[dict] = []
    per: dict[str, dict] = {}

    def row(tid: str) -> dict:
        return per.setdefault(tid, {"tenantId": tid, "name": names.get(tid, tid), "machines": 0, "protected": 0,
                                    "atRisk": 0, "failing": 0, "unprotected": 0, "offline": 0, "storedBytes": 0,
                                    "holds": 0, "anomalies7d": 0, "bootVerified": 0, "jobs7d": 0, "ok7d": 0,
                                    "lastBackup": None})

    def flag(a: BackupAgent | None, tid: str, kind: str, detail: str, since=None, name: str | None = None):
        attention.append({"tenantId": tid, "tenantName": names.get(tid, tid), "kind": kind, "detail": detail,
                          "agentId": a.id if a else None,
                          "machine": name or ((a.display_name or a.hostname) if a else ""), "since": iso(since)})

    for a in agents:
        r = row(a.tenant_id)
        r["machines"] += 1
        name = a.display_name or a.hostname
        mine = [pl for pl in plans if pl.agent_id == a.id and plan_period(pl.schedule)]
        mine_jobs = sorted((j for j in backups if j.agent_id == a.id), key=lambda j: j.finished_at)
        last = mine_jobs[-1] if mine_jobs else None
        offline = a.last_seen_at is None or now - a.last_seen_at > timedelta(hours=24)
        overdue = []
        for pl in mine:
            ok = last_ok.get(pl.id)
            if (ok or pl.created_at) < now - timedelta(seconds=2 * plan_period(pl.schedule) + 3600):
                overdue.append((pl, ok))
        if not mine:
            r["unprotected"] += 1
            flag(a, a.tenant_id, "no_plan", "no scheduled backup plan")
        elif last is not None and last.state == "failed":
            r["failing"] += 1
            flag(a, a.tenant_id, "failing", (last.error or "the last backup failed")[:300], last.finished_at)
        elif overdue:
            r["atRisk"] += 1
            pl, ok = overdue[0]
            flag(a, a.tenant_id, "overdue", f"{pl.name}: no successful backup " + (f"since {ok:%Y-%m-%d %H:%M} UTC" if ok else "yet"), ok)
        else:
            r["protected"] += 1
        if offline:
            r["offline"] += 1
            flag(a, a.tenant_id, "offline", "the backup agent has not checked in for a day", a.last_seen_at)
        if a.id in verified_agents:
            r["bootVerified"] += 1
        lc = latest_check.get(a.id)
        if lc is not None and lc.outcome == "failed":
            flag(a, a.tenant_id, "boot_failed", "the latest boot test failed", lc.at)
        if last is not None and (r["lastBackup"] is None or iso(last.finished_at) > r["lastBackup"]):
            r["lastBackup"] = iso(last.finished_at)
    week = now - timedelta(days=7)
    for j in backups:
        if j.finished_at > week:
            r = row(j.tenant_id)
            r["jobs7d"] += 1
            r["ok7d"] += j.state in ("succeeded", "warning")
    for repo in repos:
        if repo.hold:
            row(repo.tenant_id)["holds"] += 1
            flag(None, repo.tenant_id, "hold", repo.hold_reason or "retention is on hold", repo.hold_since,
                 name=f"repository {repo.name}")
    for tid, n in stored.items():
        row(tid)["storedBytes"] = int(n or 0)
    for tid, n in anomalies.items():
        row(tid)["anomalies7d"] = int(n)
    customers = []
    for r in per.values():
        r["successRate7d"] = round(100 * r["ok7d"] / r["jobs7d"]) if r["jobs7d"] else None
        r["status"] = "critical" if r["holds"] or r["failing"] or r["anomalies7d"] else \
            "warning" if r["atRisk"] or r["offline"] or r["unprotected"] else "ok"
        customers.append(r)
    order = {"critical": 0, "warning": 1, "ok": 2}
    customers.sort(key=lambda r: (order[r["status"]], r["name"].lower()))
    attention.sort(key=lambda x: (SEVERITY[x["kind"]], x["tenantName"].lower(), x["machine"].lower()))
    trend = []
    for d in range(13, -1, -1):
        day = (now - timedelta(days=d)).date()
        js = [j for j in backups if j.finished_at.date() == day]
        trend.append({"day": day.isoformat(), "succeeded": sum(j.state == "succeeded" for j in js),
                      "warning": sum(j.state == "warning" for j in js), "failed": sum(j.state == "failed" for j in js)})
    keys = ("machines", "protected", "atRisk", "failing", "unprotected", "offline", "storedBytes", "holds",
            "anomalies7d", "bootVerified", "jobs7d", "ok7d")
    totals = {k: sum(r[k] for r in customers) for k in keys}
    totals["customers"] = len(customers)
    totals["successRate7d"] = round(100 * totals["ok7d"] / totals["jobs7d"]) if totals["jobs7d"] else None
    return {"totals": totals, "customers": customers, "attention": attention[:200], "trend": trend}


@router.get("/agents")
def list_agents(tenantId: str | None = None, deviceId: str | None = None, p: Principal = Depends(current_principal),
                db: Session = Depends(get_db)):
    p.require("read")
    q = select(BackupAgent).where(BackupAgent.tenant_id.in_(scoped_tenant(p, tenantId)), BackupAgent.revoked.is_(False))
    if deviceId:
        q = q.where(BackupAgent.device_id == deviceId)
    now = utcnow()
    rows = sorted(db.execute(q).scalars().all(), key=lambda a: (a.display_name or a.hostname).lower())
    return [agent_out(db, a, now) for a in rows]


@router.get("/agents/{agent_id}")
def get_agent(agent_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    a = _agent(db, p, agent_id, live=False)
    names = {a.id: a.display_name or a.hostname}
    jobs = db.execute(select(BackupJob).where(BackupJob.agent_id == a.id).order_by(BackupJob.created_at.desc()).limit(50)).scalars().all()
    images = db.execute(select(BackupImage).where(BackupImage.agent_id == a.id).order_by(BackupImage.created_unix.desc())).scalars().all()
    plans = db.execute(select(ImageBackupPlan).where(ImageBackupPlan.agent_id == a.id)).scalars().all()
    repos = db.execute(select(BackupRepository).join(BackupRepoAccess, BackupRepoAccess.repository_id == BackupRepository.id)
                       .where(BackupRepoAccess.agent_id == a.id)).scalars().all()
    return {"agent": agent_out(db, a), "inventory": a.inventory, "jobs": [job_out(j, names) for j in jobs],
            "imageCount": len(images),
            "plans": [plan_out(pl, names) for pl in plans],
            "repositories": [{"id": r.id, "name": r.name, "status": r.status} for r in repos]}


@router.patch("/agents/{agent_id}")
def rename_agent(agent_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    a = _agent(db, p, agent_id)
    name = str(body.get("name") or "").strip()[:80]
    a.display_name = name or None
    if "deviceId" in body:
        dev = db.get(Device, str(body["deviceId"])) if body["deviceId"] else None
        if body["deviceId"] and (dev is None or dev.tenant_id != a.tenant_id):
            bad("that device is not in this machine's tenant")
        a.device_id = dev.id if dev else None
    bk.record(db, p.actor, "backup.agent.updated", a.hostname, a.tenant_id, name=name, device=a.device_id)
    db.commit()
    return {"ok": True}


@router.delete("/agents/{agent_id}")
def remove_agent(agent_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    a = _agent(db, p, agent_id)
    now = utcnow()
    a.revoked = True
    for x in db.execute(select(BackupRepoAccess).where(BackupRepoAccess.agent_id == a.id)).scalars():
        db.delete(x)
    for pl in db.execute(select(ImageBackupPlan).where(ImageBackupPlan.agent_id == a.id)).scalars():
        pl.enabled = False
    for j in db.execute(select(BackupJob).where(BackupJob.agent_id == a.id, BackupJob.state == "queued")).scalars():
        j.state, j.finished_at, j.error = "cancelled", now, "machine removed"
    bk.record(db, p.actor, "backup.agent.removed", a.hostname, a.tenant_id)
    db.commit()
    return {"ok": True, "note": "The machine can no longer reach the server. Its backups are kept."}


# --------------------------------------------------------------------------
# Jobs
# --------------------------------------------------------------------------


def _settings(s) -> dict:
    s = s if isinstance(s, dict) else {}
    pct = s.get("verify_sample_percent")
    if pct is not None and (not isinstance(pct, (int, float)) or not 0 <= pct <= 100):
        bad("verification sample must be 0 to 100 percent")
    rate = s.get("rate_limit_mib") or 0
    if not isinstance(rate, int) or rate < 0:
        bad("rate limit must be a whole number of MiB/s")
    lab = str(s.get("label") or "").strip()[:200] or None
    return {"label": lab, "rate_limit_mib": rate, "vss_full": bool(s.get("vss_full")), "verify_sample_percent": pct,
            "full_read": bool(s.get("full_read"))}


def normalise_kind(kind) -> dict:
    """A console-requested job, rebuilt from validated fields only."""
    if not isinstance(kind, dict):
        bad("job kind required")
    t = kind.get("type")
    if t == "backup_system":
        return {"type": t, "settings": _settings(kind.get("settings"))}
    if t == "backup_disks":
        paths = [str(x).strip() for x in kind.get("paths") or [] if str(x).strip()]
        if not paths or any(len(x) > 500 for x in paths):
            bad("choose at least one disk")
        return {"type": t, "paths": paths[:32], "settings": _settings(kind.get("settings"))}
    if t == "backup_hyperv":
        return {"type": t, "vm_ids": [str(x)[:100] for x in kind.get("vm_ids") or []][:200],
                "settings": _settings(kind.get("settings"))}
    if t == "verify":
        level, pct = kind.get("level"), kind.get("sample_percent")
        if level not in ("quick", "sample", "full") or (pct is not None and not (isinstance(pct, (int, float)) and 0 <= pct <= 100)):
            bad("verify level must be quick, sample or full")
        return {"type": t, "level": level, "sample_percent": pct}
    if t == "list_images":
        return {"type": t}
    bad("use the repository (create, reclaim space) or the restore dialog for that")


def validate_job(db: Session, agent: BackupAgent, kind: dict, repository_id: str | None) -> None:
    need = bk.KIND_CAPABILITY.get(kind["type"])
    if need and need not in bk.capabilities(agent):
        bad(f"this machine cannot run that job (it does not report {need}; role {agent.role})")
    if repository_id is None:
        bad("choose a repository")
    repo = db.get(BackupRepository, repository_id)
    if repo is None or repo.tenant_id != agent.tenant_id or db.get(BackupRepoAccess, (repository_id, agent.id)) is None:
        bad("this machine has no access to that repository")
    if repo.status != "ready":
        bad(f"the repository is not ready ({repo.status})")


@router.post("/agents/{agent_id}/jobs")
def create_job(agent_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("respond")
    a = _agent(db, p, agent_id)
    kind = normalise_kind(body.get("kind"))
    repo_id = _uuid(body["repositoryId"], "repository") if body.get("repositoryId") else None
    validate_job(db, a, kind, repo_id)
    job = bk.queue(db, a, kind, repo_id, p.actor)
    bk.record(db, p.actor, "backup.job.created", a.hostname, a.tenant_id, job=job.id, kind=kind["type"])
    db.commit()
    return {"id": job.id}


@router.post("/agents/{agent_id}/local-recovery")
def local_recovery(agent_id: str, request: Request, body: dict = Body(...), p: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)):
    """Install, rebuild or remove a Windows machine's local recovery partition (backup/docs/design/local-recovery.md).
    Installing and removing repartition its system disk: destructive permission, a fresh password check and the
    machine's name typed."""
    a = _agent(db, p, agent_id)
    action = str(body.get("action") or "")
    if action not in ("install", "refresh", "remove"):
        bad("action is install, refresh or remove")
    if "local_recovery" not in bk.capabilities(a):
        bad("this machine cannot have a local recovery partition (Windows, with an up-to-date backup agent)")
    installed = isinstance((a.inventory or {}).get("local_recovery"), dict)
    confirm = str(body.get("confirm") or "").strip()
    if action == "refresh":
        p.require("configure")
        if not installed:
            bad("local recovery is not installed on this machine")
    else:
        p.require("destructive")
        require_reauth(request, p)
        if confirm.lower() != (a.hostname or "").lower():
            bad(f"type the machine's name ({a.hostname}) to confirm: this repartitions its system disk")
        if action == "install" and installed:
            bad("local recovery is already installed; rebuild it instead")
        if action == "remove" and not installed:
            bad("local recovery is not installed on this machine")
    size = body.get("sizeMb") or 0
    if not isinstance(size, int) or not 0 <= size <= 16384:
        bad("the recovery partition is at most 16 GB")
    auto = bool(body.get("autoStart")) if action != "refresh" else bool(((a.inventory or {}).get("local_recovery") or {}).get("auto_start"))
    job = bk.queue(db, a, {"type": "local_recovery", "action": action, "size_mb": size, "auto_start": auto,
                           "confirm": confirm}, None, p.actor)
    bk.record(db, p.actor, f"backup.local_recovery.{action}_requested", a.hostname, a.tenant_id, auto_start=auto)
    db.commit()
    return {"id": job.id}


@router.get("/jobs")
def list_jobs(tenantId: str | None = None, agentId: str | None = None, limit: int = Query(100, le=500),
              p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    tenants = scoped_tenant(p, tenantId)
    q = select(BackupJob).where(BackupJob.tenant_id.in_(tenants))
    if agentId:
        q = q.where(BackupJob.agent_id == agentId)
    names = _names(db, tenants)
    return [job_out(j, names) for j in db.execute(q.order_by(BackupJob.created_at.desc()).limit(limit)).scalars()]


@router.get("/jobs/{job_id}")
def get_job(job_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    j = db.get(BackupJob, job_id)
    if j is None or j.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "No such job")
    return job_out(j, _names(db, [j.tenant_id]))


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("respond")
    j = db.get(BackupJob, job_id)
    if j is None or j.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "No such job")
    if j.state == "queued":
        j.state, j.finished_at, j.error = "cancelled", utcnow(), f"cancelled by {p.actor}"
    elif j.state in ("dispatched", "running"):
        j.cancel_requested = True
    else:
        raise HTTPException(409, "the job has already finished")
    bk.record(db, p.actor, "backup.job.cancelled", j.id, j.tenant_id)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------
# Install links
# --------------------------------------------------------------------------


def _recovery_links(request: Request, raw: str) -> dict:
    base = server_url(request)
    iso = bk.recovery_iso_path()
    return {"available": iso.is_file(), "size": iso.stat().st_size if iso.is_file() else None,
            "iso": f"{base}/recovery/{raw}/{bk.RECOVERY_ISO}", "settings": f"{base}/recovery/{raw}/{bk.RECOVERY_SETTINGS}"}


def _links(request: Request, raw: str) -> dict:
    base = server_url(request)
    out = {}
    for key, pl in bk.PLATFORMS.items():
        script = f"{base}/install/{raw}/{key}"
        available = any(bk.binary_info(t) for t in pl["targets"])
        entry = {"name": pl["name"], "available": available, "script": script, "file": pl["script"]}
        if pl["setup"]:
            entry["setup"] = f"{script}/{pl['setup']}"
            entry["setupFile"] = pl["setup"]
            entry["oneLiner"] = bk.windows_one_liner(script, tls_pin())
        else:
            pin = tls_pin()
            fetch = f"curl -fsSL --pinnedpubkey 'sha256//{pin}' -k" if pin else "curl -fsSL"
            entry["oneLiner"] = f"{fetch} '{script}' | sudo sh"
        out[key] = entry
    return out


@router.post("/enrollments")
def create_enrollment(request: Request, body: dict = Body(...), p: Principal = Depends(current_principal),
                      db: Session = Depends(get_db)):
    p.require("configure")
    tenant_id = str(body.get("tenantId") or "")
    device_id = body.get("deviceId") or None
    if device_id:
        dev = db.get(Device, str(device_id))
        if dev is None or dev.tenant_id not in p.tenant_ids:
            raise HTTPException(404, "No such device")
        tenant_id = dev.tenant_id
    p.check_tenant(tenant_id or None)
    if db.get(Tenant, tenant_id) is None:
        bad("choose a customer")
    role = body.get("role") or "server"
    if role not in bk.ROLES:
        bad("role must be workstation, server, hyperv or recovery")
    if role == "recovery" and device_id:
        bad("recovery media is not bound to a device")
    days = body.get("days", 7)
    if not isinstance(days, int) or not 1 <= days <= 90:
        bad("a link lasts 1 to 90 days")
    raw = bk.new_token()
    e = BackupEnrollment(tenant_id=tenant_id, device_id=device_id, role=role, label=str(body.get("label") or "")[:200],
                         token_hash=bk.token_hash(raw), expires_at=utcnow() + timedelta(days=days), created_by=p.actor)
    db.add(e)
    bk.record(db, p.actor, "backup.enrollment.created", e.label or role, tenant_id, role=role, device=device_id, days=days)
    db.commit()
    if role == "recovery":
        return {"id": e.id, "token": raw, "expiresAt": iso(e.expires_at), "recovery": _recovery_links(request, raw)}
    return {"id": e.id, "token": raw, "expiresAt": iso(e.expires_at), "links": _links(request, raw),
            "uninstall": {k: f"{server_url(request)}/uninstall/{k}" for k in bk.UNINSTALLERS}}


@router.get("/recovery-media")
def recovery_media_status(p: Principal = Depends(current_principal)):
    p.require("configure")
    iso = bk.recovery_iso_path()
    return {"available": iso.is_file(), "size": iso.stat().st_size if iso.is_file() else None}


@router.post("/devices/{device_id}/install")
def install_on_device(device_id: str, request: Request, body: dict = Body(default={}), p: Principal = Depends(current_principal),
                      db: Session = Depends(get_db)):
    """Install the backup agent on a device through its Fenrir agent (an ordinary script.run command, as SYSTEM or
    root). The enrolment link is bound to the device, valid for a day and used once."""
    p.require("configure")
    p.require("scripts")
    dev = db.get(Device, device_id)
    if dev is None or dev.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "No such device")
    platform = (dev.platform or "").lower()
    if platform not in ("windows", "linux", "macos"):
        bad(f"the backup agent is not available for {dev.platform}")
    role = body.get("role") or ("server" if "server" in (dev.os_version or "").lower() or platform == "linux" else "workstation")
    if role not in bk.INSTALL_ROLES or (role == "hyperv" and platform != "windows"):
        bad("role must be workstation, server or hyperv (Windows only)")
    key = "hyperv" if role == "hyperv" else platform
    if not any(bk.binary_info(t) for t in bk.PLATFORMS[key]["targets"]):
        bad(f"the {bk.PLATFORMS[key]['name']} backup agent is not built on this server yet")
    raw = bk.new_token()
    e = BackupEnrollment(tenant_id=dev.tenant_id, device_id=dev.id, role=role, label=f"push:{dev.hostname}"[:200],
                         token_hash=bk.token_hash(raw), expires_at=utcnow() + timedelta(days=1), created_by=p.actor)
    db.add(e)
    db.flush()
    script = bk.install_script(key, server_url(request), tls_pin(), raw, role)
    payload = {"language": "powershell" if platform == "windows" else "bash", "body": script, "timeoutSeconds": 900,
               "runAs": "system", "scriptName": "Install Fenrir backup agent", "backupEnrollment": e.id}
    from .. import services

    try:
        cmd = services.enqueue_command(db, dev, "script.run", p.actor, payload=payload, reason="Install the backup agent")
    except services.CommandError as exc:
        raise HTTPException(400, str(exc)) from exc
    db.flush()
    bk.record(db, p.actor, "backup.agent.install_pushed", dev.hostname, dev.tenant_id, role=role, command=cmd.id)
    db.commit()
    return {"commandId": cmd.id, "enrollmentId": e.id}


@router.get("/enrollments")
def list_enrollments(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    rows = db.execute(select(BackupEnrollment).where(BackupEnrollment.tenant_id.in_(scoped_tenant(p, tenantId)))
                      .order_by(BackupEnrollment.created_at.desc()).limit(100)).scalars().all()
    now = utcnow()
    return [{"id": e.id, "tenantId": e.tenant_id, "deviceId": e.device_id, "role": e.role, "label": e.label,
             "uses": e.uses, "expiresAt": iso(e.expires_at), "createdAt": iso(e.created_at), "createdBy": e.created_by,
             "active": not e.revoked and e.expires_at > now, "revoked": e.revoked} for e in rows]


@router.delete("/enrollments/{enrollment_id}")
def revoke_enrollment(enrollment_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    e = db.get(BackupEnrollment, enrollment_id)
    if e is None or e.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "No such link")
    e.revoked = True
    bk.record(db, p.actor, "backup.enrollment.revoked", e.label or e.id, e.tenant_id)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------
# Repositories
# --------------------------------------------------------------------------


@router.get("/repositories")
def list_repos(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    rows = db.execute(select(BackupRepository).where(BackupRepository.tenant_id.in_(scoped_tenant(p, tenantId)))
                      .order_by(BackupRepository.created_at)).scalars().all()
    return [repo_out(db, r) for r in rows]


@router.post("/repositories")
def create_repo(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    name, path = str(body.get("name") or "").strip()[:120], str(body.get("path") or "").strip()
    if not name or not path or len(path) > 1000:
        bad("name and path are required")
    init = _agent(db, p, str(body.get("initAgentId") or ""))
    access = body.get("access") or []
    if not any(x.get("agentId") == init.id for x in access):
        bad("the machine that creates the repository needs its sealed secret")
    mode, user = _share_mode(body)
    s3 = _s3_settings(path, body.get("s3"), 7)
    if s3 and mode != "password":
        bad("an S3 repository needs an access key and secret for every machine")
    if mode != "none" and not is_share_path(path) and not s3:
        bad(r"a share sign-in needs a network path like \\server\share\folder")
    # An existing repository (moved from a Fenrir-Backup server, or added again): its first listing names it.
    existing = bool(body.get("existing"))
    repo_uuid = "" if existing else _uuid(body.get("repoUuid"), "repository UUID")
    # Dedup group: a member lives in <group>/repos/<its id> (backup/docs/design/dedup-groups.md).
    dedup, dedup_source = str(body.get("dedup") or "").strip(), None
    if dedup and existing:
        bad("an existing repository cannot be added to a dedup group")
    if dedup == "new":
        if dedup_member(path):
            bad("choose the folder for the new dedup group, not a repository inside one")
        path = member_path(path, repo_uuid)
    elif dedup:
        src = _repo(db, p, dedup)
        root = dedup_member(src.path)
        if root is None:
            bad("that repository is not in a dedup group")
        if src.tenant_id != init.tenant_id:
            bad("a dedup group never spans customers")
        if path.rstrip("/\\") != root:
            bad(f"a repository in this dedup group is stored in the group's folder: {root}")
        path, dedup_source = member_path(root, repo_uuid), src.id
    repo = BackupRepository(tenant_id=init.tenant_id, name=name, path=path, repo_uuid=repo_uuid,
                            maintenance_agent_id=init.id, share_auth=mode, share_user=user, created_by=p.actor, s3=s3,
                            dedup_source_id=dedup_source)
    db.add(repo)
    db.flush()
    for x in access:
        a = _agent(db, p, str(x.get("agentId") or ""))
        if a.tenant_id != repo.tenant_id:
            bad("every machine must belong to the same customer as the repository")
        share = _sealed(x.get("sealedShare")) if mode == "password" else None
        if mode == "password" and share is None:
            bad("enter the share password for every machine")
        db.add(BackupRepoAccess(repository_id=repo.id, agent_id=a.id, sealed=_sealed(x.get("sealed")),
                                sealed_share=share, granted_by=p.actor))
    job = bk.queue(db, init, {"type": "list_images" if existing else "init_repository"}, repo.id, p.actor)
    bk.record(db, p.actor, "backup.repository.added" if existing else "backup.repository.created", f"{name} at {path}",
              repo.tenant_id, share=mode)
    db.commit()
    return {"id": repo.id, "initJobId": job.id}


@router.post("/repositories/{repo_id}/access")
def grant_access(repo_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    repo = _repo(db, p, repo_id)
    a = _agent(db, p, str(body.get("agentId") or ""))
    if a.tenant_id != repo.tenant_id:
        bad("that machine belongs to another customer")
    via = bool(body.get("viaGateway"))
    if via and (not repo.gateway_agent_id or repo.gateway_agent_id == a.id):
        bad("set up a gateway for this repository first (and choose another machine than the gateway)")
    share = None
    if repo.share_auth == "password" and not via:
        if not body.get("sealedShare"):
            bad("this repository is on a network share: enter the share password for the machine too")
        share = _sealed(body["sealedShare"])
    row = db.get(BackupRepoAccess, (repo.id, a.id))
    if row is None:
        row = BackupRepoAccess(repository_id=repo.id, agent_id=a.id, sealed={}, granted_by=p.actor)
        db.add(row)
    row.sealed, row.sealed_share, row.granted_at, row.granted_by = _sealed(body.get("sealed")), share, utcnow(), p.actor
    row.via_gateway = via or None
    bk.record(db, p.actor, "backup.repository.access_granted", repo.name, repo.tenant_id, machine=a.hostname,
              via_gateway=via)
    db.commit()
    return {"ok": True}


@router.delete("/repositories/{repo_id}/access/{agent_id}")
def revoke_access(repo_id: str, agent_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    repo = _repo(db, p, repo_id)
    if agent_id == repo.gateway_agent_id:
        bad("that machine is this repository's gateway: stop serving through it first")
    row = db.get(BackupRepoAccess, (repo.id, agent_id))
    if row is not None:
        db.delete(row)
    for pl in db.execute(select(ImageBackupPlan).where(ImageBackupPlan.repository_id == repo.id,
                                                       ImageBackupPlan.agent_id == agent_id)).scalars():
        pl.enabled = False
    bk.record(db, p.actor, "backup.repository.access_revoked", repo.name, repo.tenant_id, agent=agent_id)
    db.commit()
    return {"ok": True}


@router.delete("/repositories/{repo_id}")
def forget_repo(repo_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    repo = _repo(db, p, repo_id)
    if db.execute(select(ImageBackupPlan.id).where(ImageBackupPlan.repository_id == repo.id)).first():
        raise HTTPException(409, "delete the backup plans that use this repository first")
    for model in (BackupRepoAccess, BackupImage, BackupBootCheck):
        for r in db.execute(select(model).where(model.repository_id == repo.id)).scalars():
            db.delete(r)
    bk.record(db, p.actor, "backup.repository.forgotten", repo.name, repo.tenant_id, path=repo.path)
    db.delete(repo)
    db.commit()
    return {"ok": True, "note": "The server forgot this repository. Its data was not touched."}


@router.post("/repositories/{repo_id}/gateway")
def set_gateway(repo_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Serve the repository through a gateway agent (NAS gateway), or stop. Machines given access "through the
    gateway" then reach it via that agent: directly on `port` when they can, relayed by this server otherwise."""
    p.require("configure")
    repo = _repo(db, p, repo_id)
    if repo.s3 and body.get("agentId"):
        bad("an S3 repository is reached directly by every machine; a gateway is for folders on a NAS")
    if not body.get("agentId"):
        users = db.execute(select(BackupRepoAccess).where(BackupRepoAccess.repository_id == repo.id,
                                                          BackupRepoAccess.via_gateway.is_(True))).scalars().all()
        if users:
            bad(f"{len(users)} machine(s) reach this repository through the gateway; remove their access first")
        repo.gateway_agent_id = None
        bk.record(db, p.actor, "backup.repository.gateway_removed", repo.name, repo.tenant_id)
        db.commit()
        return {"ok": True}
    g = _agent(db, p, str(body["agentId"]))
    access = db.get(BackupRepoAccess, (repo.id, g.id))
    if g.tenant_id != repo.tenant_id or access is None or access.via_gateway:
        bad("the gateway must be a machine with direct access to the repository (give it access first)")
    if "gateway" not in bk.capabilities(g):
        bad(f"the backup agent on {g.display_name or g.hostname} is too old to be a gateway; it updates itself shortly")
    port = body.get("port", gwmod.DEFAULT_PORT)
    if port is None:
        port = 0
    if not isinstance(port, int) or not (port == 0 or 1024 <= port <= 65535):
        bad("the port must be 1024 to 65535, or 0 to use the relay only")
    address = str(body.get("address") or "").strip() or None
    if address and (len(address) > 255 or not re.fullmatch(r"[A-Za-z0-9.\-]+:\d{2,5}|\[[0-9A-Fa-f:]+\]:\d{2,5}", address)):
        bad("the extra address must look like host:port, e.g. nas-gw.example.com:8475")
    repo.gateway_agent_id = g.id
    repo.maintenance_agent_id = g.id  # retention and space reclamation run on the gateway
    g.gateway_port, g.gateway_address = port or None, address
    bk.record(db, p.actor, "backup.repository.gateway_set", repo.name, repo.tenant_id, gateway=g.hostname, port=port,
              address=address)
    db.commit()
    return {"ok": True}


@router.post("/repositories/{repo_id}/hold")
def set_hold(repo_id: str, request: Request, body: dict = Body(...), p: Principal = Depends(current_principal),
             db: Session = Depends(get_db)):
    repo = _repo(db, p, repo_id)
    if body.get("hold"):
        p.require("respond")
        repo.hold, repo.hold_since = True, utcnow()
        repo.hold_reason = str(body.get("reason") or "").strip()[:500] or f"Placed on hold by {p.actor}"
        action = "backup.repository.hold"
    else:
        # Releasing lets retention delete old images again: deliberate, re-authenticated.
        p.require("destructive")
        require_reauth(request, p)
        repo.hold, repo.hold_since, repo.hold_reason = False, None, None
        action = "backup.repository.hold_released"
        bk.resolve_alerts(db, repo.tenant_id, bk.RULE_RANSOMWARE, repo.id, f"Hold released by {p.actor}")
    bk.record(db, p.actor, action, repo.name, repo.tenant_id, reason=repo.hold_reason)
    db.commit()
    return {"ok": True}


def _has_access(db: Session, repo: BackupRepository, agent: BackupAgent) -> None:
    if db.get(BackupRepoAccess, (repo.id, agent.id)) is None:
        bad("that machine has no access to this repository")


@router.post("/repositories/{repo_id}/maintenance")
def set_maintenance(repo_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    repo = _repo(db, p, repo_id)
    if body.get("agentId"):
        a = _agent(db, p, str(body["agentId"]))
        _has_access(db, repo, a)
        if repo.gateway_agent_id and a.id != repo.gateway_agent_id:
            bad("this repository is served through a gateway: its maintenance runs on the gateway")
        repo.maintenance_agent_id = a.id
    if "pruneEveryDays" in body:
        d = body["pruneEveryDays"]
        if not isinstance(d, int) or not 0 <= d <= 365:
            bad("prune interval must be 0 (never) to 365 days")
        if repo.s3:
            _s3_settings(repo.path, repo.s3, d)
        repo.prune_every_days = d
    bk.record(db, p.actor, "backup.repository.maintenance_changed", repo.name, repo.tenant_id,
              agent=repo.maintenance_agent_id, every_days=repo.prune_every_days)
    db.commit()
    return {"ok": True}


@router.post("/repositories/{repo_id}/prune")
def prune_now(repo_id: str, request: Request, body: dict = Body(default={}), p: Principal = Depends(current_principal),
              db: Session = Depends(get_db)):
    repo = _repo(db, p, repo_id)
    dry = bool(body.get("dryRun"))
    if dry:
        p.require("respond")
    else:
        p.require("destructive")
        require_reauth(request, p)
        if repo.hold:
            raise HTTPException(409, "the repository is on hold; release the hold before reclaiming space")
    agent = db.get(BackupAgent, repo.maintenance_agent_id) if repo.maintenance_agent_id else None
    if agent is None or agent.revoked:
        bad("choose a maintenance machine first")
    job = bk.queue(db, agent, {"type": "prune", "dry_run": dry}, repo.id, p.actor)
    bk.record(db, p.actor, "backup.repository.prune", repo.name, repo.tenant_id, dry_run=dry)
    db.commit()
    return {"id": job.id}


@router.post("/repositories/{repo_id}/boot-verification")
def set_boot_verification(repo_id: str, body: dict = Body(...), p: Principal = Depends(current_principal),
                          db: Session = Depends(get_db)):
    p.require("configure")
    repo = _repo(db, p, repo_id)
    if body.get("agentId"):
        a = _agent(db, p, str(body["agentId"]))
        days = body.get("everyDays")
        if not isinstance(days, int) or not 1 <= days <= 90:
            bad("the interval must be 1 to 90 days")
        if not {"boot_kvm", "boot_hyperv"} & set(bk.capabilities(a)):
            bad("that machine cannot boot VMs")
        _has_access(db, repo, a)
        repo.boot_agent_id, repo.boot_every_days = a.id, days
    else:
        repo.boot_agent_id, repo.boot_every_days = None, 0
    bk.record(db, p.actor, "backup.repository.boot_verification_changed", repo.name, repo.tenant_id,
              agent=repo.boot_agent_id, every_days=repo.boot_every_days)
    db.commit()
    return {"ok": True}


@router.post("/repositories/{repo_id}/share")
def set_share(repo_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    repo = _repo(db, p, repo_id)
    mode, user = _share_mode(body)
    if mode != "none" and not is_share_path(repo.path) and not repo.s3:
        bad("this repository is not on a network share")
    rows = db.execute(select(BackupRepoAccess).where(BackupRepoAccess.repository_id == repo.id)).scalars().all()
    sealed = {}
    if mode == "password":
        sealed = {str(x.get("agentId")): _sealed(x.get("sealedShare")) for x in body.get("access") or []}
        missing = [r.agent_id for r in rows if r.agent_id not in sealed]
        if missing:
            bad(f"the sign-in must be sealed for every machine with access (missing {missing[0]})")
    repo.share_auth, repo.share_user = mode, user
    for r in rows:
        r.sealed_share = sealed.get(r.agent_id)
    bk.record(db, p.actor, "backup.repository.share_signin_changed", repo.name, repo.tenant_id, mode=mode, user=user)
    db.commit()
    return {"ok": True}


@router.post("/agents/{agent_id}/check-access")
def check_access(agent_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("respond")
    a = _agent(db, p, agent_id)
    path = str(body.get("path") or "").strip()
    if not path or len(path) > 1000:
        bad("enter a folder path")
    share = _sealed(body["sealedShare"]) if body.get("sealedShare") else None
    kind = {"type": "check_access", "path": path, "sealed_share": share}
    s3 = _s3_settings(path, body.get("s3"), 7)
    if s3:
        kind["s3"] = s3
    job = bk.queue(db, a, kind, None, p.actor)
    db.commit()
    return {"id": job.id}


# --------------------------------------------------------------------------
# Plans
# --------------------------------------------------------------------------


def _plan_fields(db: Session, p: Principal, body: dict, plan: ImageBackupPlan | None) -> dict:
    out = {}
    if plan is None or "name" in body:
        name = str(body.get("name") or "").strip()[:120]
        if not name:
            bad("give the plan a name")
        out["name"] = name
    if plan is None or "job" in body:
        job = normalise_kind(body.get("job"))
        if not bk.is_backup(job):
            bad("a plan runs a backup")
        out["job"] = job
    if plan is None or "schedule" in body:
        s = body.get("schedule")
        try:
            bk.validate_schedule(s if isinstance(s, dict) else {})
        except ValueError as e:
            bad(str(e))
        out["schedule"] = s
    if plan is None or "retention" in body:
        try:
            out["retention"] = bk.validate_retention(body.get("retention"))
        except ValueError as e:
            bad(str(e))
    if "enabled" in body or plan is None:
        out["enabled"] = bool(body.get("enabled", True))
    if "copyToRepositoryId" in body:
        c = body.get("copyToRepositoryId") or None
        if c is not None:
            agent_id = plan.agent_id if plan else str(body.get("agentId") or "")
            repo_id = plan.repository_id if plan else _uuid(body.get("repositoryId"), "repository")
            c = _uuid(c, "repository")
            if c == repo_id:
                bad("the copy must go to another repository than the backup")
            target = db.get(BackupRepository, c)
            if target is None or target.tenant_id not in p.tenant_ids:
                bad("no such repository")
            if db.get(BackupRepoAccess, (c, agent_id)) is None:
                bad("the machine has no access to the copy's repository; grant it access there first")
        out["copy_to_repository_id"] = c
    return out


def _reschedule(plan: ImageBackupPlan) -> None:
    nxt = bk.next_after(plan.schedule, bk.unix(utcnow())) if plan.enabled else None
    plan.next_run_at = bk.from_unix(nxt) if nxt else None


@router.get("/plans")
def list_plans(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    tenants = scoped_tenant(p, tenantId)
    names = _names(db, tenants)
    rows = db.execute(select(ImageBackupPlan).where(ImageBackupPlan.tenant_id.in_(tenants))
                      .order_by(ImageBackupPlan.name)).scalars().all()
    return [plan_out(pl, names) for pl in rows]


@router.post("/plans")
def create_plan(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    a = _agent(db, p, str(body.get("agentId") or ""))
    repo_id = _uuid(body.get("repositoryId"), "repository")
    f = _plan_fields(db, p, body, None)
    validate_job(db, a, f["job"], repo_id)
    plan = ImageBackupPlan(tenant_id=a.tenant_id, agent_id=a.id, repository_id=repo_id, created_by=p.actor, **f)
    _reschedule(plan)
    db.add(plan)
    bk.record(db, p.actor, "backup.plan.created", plan.name, a.tenant_id, machine=a.hostname)
    db.commit()
    return {"id": plan.id}


def _plan(db: Session, p: Principal, plan_id: str) -> ImageBackupPlan:
    pl = db.get(ImageBackupPlan, plan_id)
    if pl is None or pl.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "No such plan")
    return pl


@router.patch("/plans/{plan_id}")
def update_plan(plan_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    plan = _plan(db, p, plan_id)
    f = _plan_fields(db, p, body, plan)
    if "job" in f:
        validate_job(db, _agent(db, p, plan.agent_id), f["job"], plan.repository_id)
    for k, v in f.items():
        setattr(plan, k, v)
    _reschedule(plan)
    bk.record(db, p.actor, "backup.plan.updated", plan.name, plan.tenant_id, fields=sorted(f))
    db.commit()
    return {"ok": True}


@router.post("/import")
def import_config(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Recreate a Fenrir-Backup server's plans (its Settings › Move to Fenrir Cloud export). Each plan is matched to a
    machine here by machine ID and to a repository here by repository ID (added as existing first); plans that cannot
    be matched are reported and skipped. The export holds no secrets."""
    p.require("configure")
    ex = body.get("export")
    if not isinstance(ex, dict) or ex.get("format") != "fenrir-backup-export":
        bad("that is not a Fenrir-Backup export file")
    tenants = scoped_tenant(p, body.get("tenantId"))
    created, skipped = [], []
    for raw in (ex.get("plans") or [])[:1000]:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "").strip()[:120] or "Imported plan"
        def skip(why: str):
            skipped.append({"name": name, "reason": why})
        agent = db.execute(select(BackupAgent).where(BackupAgent.tenant_id.in_(tenants),
                                                     BackupAgent.machine_id == str(raw.get("machine_id") or ""),
                                                     BackupAgent.revoked.is_(False))).scalars().first()
        if agent is None:
            skip(f"machine {raw.get('hostname') or raw.get('machine_id')} is not enrolled here yet")
            continue
        def repo_by(uuid_):
            return db.execute(select(BackupRepository).where(BackupRepository.tenant_id == agent.tenant_id,
                                                             BackupRepository.repo_uuid == str(uuid_ or ""),
                                                             BackupRepository.status == "ready")).scalars().first() \
                if uuid_ else None
        repo = repo_by(raw.get("repo_uuid"))
        if repo is None:
            skip("its repository has not been added here (New repository › It already exists)")
            continue
        if db.get(BackupRepoAccess, (repo.id, agent.id)) is None:
            skip(f"{agent.hostname} has no access to {repo.name} here")
            continue
        if db.execute(select(ImageBackupPlan).where(ImageBackupPlan.agent_id == agent.id,
                                                    ImageBackupPlan.repository_id == repo.id,
                                                    ImageBackupPlan.name == name)).scalars().first():
            skip("a plan of that name already exists here")
            continue
        fields = {"name": name, "job": raw.get("job"), "schedule": raw.get("schedule"),
                  "retention": raw.get("retention"), "enabled": bool(raw.get("enabled", True))}
        copy = repo_by(raw.get("copy_to_repo_uuid"))
        if raw.get("copy_to_repo_uuid") and copy is not None:
            fields["copyToRepositoryId"] = copy.id
            fields["agentId"], fields["repositoryId"] = agent.id, repo.id
        try:
            f = _plan_fields(db, p, fields, None)
            validate_job(db, agent, f["job"], repo.id)
        except HTTPException as e:
            skip(str(e.detail))
            continue
        plan = ImageBackupPlan(tenant_id=agent.tenant_id, agent_id=agent.id, repository_id=repo.id, created_by=p.actor, **f)
        _reschedule(plan)
        db.add(plan)
        db.flush()
        created.append(name)
    bk.record(db, p.actor, "backup.plans.imported", f"{len(created)} created, {len(skipped)} skipped",
              tenants[0] if len(tenants) == 1 else None)
    db.commit()
    return {"created": created, "skipped": skipped}


@router.delete("/plans/{plan_id}")
def delete_plan(plan_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    plan = _plan(db, p, plan_id)
    bk.record(db, p.actor, "backup.plan.deleted", plan.name, plan.tenant_id)
    db.delete(plan)
    db.commit()
    return {"ok": True}


@router.post("/plans/{plan_id}/run")
def run_plan(plan_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("respond")
    plan = _plan(db, p, plan_id)
    a = _agent(db, p, plan.agent_id)
    if db.execute(select(BackupJob.id).where(BackupJob.plan_id == plan.id, BackupJob.state.in_(bk.ACTIVE_STATES))).first():
        raise HTTPException(409, "this plan is already running")
    validate_job(db, a, plan.job, plan.repository_id)
    job = bk.queue(db, a, plan.job, plan.repository_id, p.actor, plan_id=plan.id)
    bk.record(db, p.actor, "backup.plan.run", plan.name, plan.tenant_id, job=job.id)
    db.commit()
    return {"id": job.id}


# --------------------------------------------------------------------------
# Images, restores, boot checks
# --------------------------------------------------------------------------


# ---------------------------------------------------------------- unlocking a repository's backups
# Images are listed, browsed and restored only after the person proves, in this browser session, that they know the
# repository's passphrase and confirms their password (and MFA code) moments before. The passphrase is sealed in the
# browser to a machine that already has access; that machine tries it on the repository. This server never sees it.

UNLOCK_HEADER = "X-Fenrir-Unlock"
UNLOCK_MINUTES = 30
FRESH_REAUTH_SECONDS = 120


def _unlocked(request: Request, p: Principal) -> set[str]:
    """Repository ids this browser session has unlocked (tokens in the X-Fenrir-Unlock header, comma-separated)."""
    secret = get_settings().secret_key
    session = digest(request.headers.get("Authorization", ""))
    state = reauth_state(secret, p.user)
    out: set[str] = set()
    for t in request.headers.get(UNLOCK_HEADER, "").split(",")[:64]:
        pl = read_token(secret, t.strip()) if t.strip() else None
        if pl and pl.get("aud") == "backup-unlock" and pl.get("sub") == p.user.id and pl.get("session") == session \
                and pl.get("state") == state and isinstance(pl.get("repo"), str):
            out.add(pl["repo"])
    return out


def require_unlocked(request: Request, p: Principal, repo_id: str) -> None:
    if repo_id not in _unlocked(request, p):
        raise HTTPException(403, "repository_locked")


def _image_unlocked(request: Request, db: Session, p: Principal, image_id: str) -> BackupImage:
    im = _image(db, p, image_id)
    require_unlocked(request, p, im.repository_id)
    return im


def _device_key(i: BackupImage) -> str:
    return f"{i.agent_id or 'host:' + (i.hostname or '')}|{i.vm_name or ''}"


@router.get("/image-devices")
def image_devices(request: Request, tenantId: str | None = None, p: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    """Backed-up machines (and VMs), with a summary of their images; the images themselves need an unlock."""
    p.require("read")
    rows = db.execute(select(BackupImage).where(BackupImage.tenant_id.in_(scoped_tenant(p, tenantId)))
                      .order_by(BackupImage.created_unix.desc())).scalars().all()
    repos = {r.id: r for r in db.execute(select(BackupRepository).where(
        BackupRepository.id.in_({i.repository_id for i in rows}))).scalars()} if rows else {}
    checks = _boot_latest(db, [i.image_id for i in rows]) if rows else {}
    unlocked = _unlocked(request, p)
    groups: dict[str, dict] = {}
    for i in rows:
        g = groups.get(_device_key(i))
        if g is None:
            g = groups[_device_key(i)] = {
                "key": _device_key(i), "name": i.vm_name or i.hostname, "hostname": i.hostname, "vmName": i.vm_name,
                "agentId": i.agent_id, "tenantId": i.tenant_id, "images": 0, "lastCreated": i.created_unix,
                "firstCreated": i.created_unix, "storedBytes": 0, "lastKind": i.kind, "lastConsistency": i.consistency,
                "anomalies": 0, "lastVerified": None, "repositories": {}}
        g["images"] += 1
        g["firstCreated"] = min(g["firstCreated"], i.created_unix)
        g["storedBytes"] += i.stored_new_bytes or 0
        g["anomalies"] += 1 if i.anomaly else 0
        b = checks.get(i.image_id)
        if b is not None and b.outcome == "verified" and (g["lastVerified"] is None or iso(b.at) > g["lastVerified"]):
            g["lastVerified"] = iso(b.at)
        r = g["repositories"].setdefault(i.repository_id, {
            "id": i.repository_id, "name": repos[i.repository_id].name if i.repository_id in repos else "?",
            "images": 0, "unlocked": i.repository_id in unlocked})
        r["images"] += 1
    out = []
    for g in groups.values():
        g["repositories"] = sorted(g["repositories"].values(), key=lambda r: -r["images"])
        out.append(g)
    return sorted(out, key=lambda g: (g["name"] or "").lower())


@router.post("/repositories/{repo_id}/unlock")
def unlock_repository(repo_id: str, request: Request, body: dict = Body(...), p: Principal = Depends(current_principal),
                      db: Session = Depends(get_db)):
    """Check the repository passphrase, sealed in the browser to a machine with access, on that machine. Needs a
    password (and MFA) confirmation from the last two minutes."""
    p.require("read")
    require_reauth(request, p)
    pl = read_token(get_settings().secret_key, request.headers.get(REAUTH_HEADER, "")) or {}
    if int(pl.get("exp") or 0) - time.time() < REAUTH_MINUTES * 60 - FRESH_REAUTH_SECONDS:
        raise HTTPException(403, "reauth_required")
    ratelimit.check(f"backup-unlock:{p.user.id}", 10, 300)
    r = _repo(db, p, repo_id)
    a = _agent(db, p, str(body.get("agentId") or ""))
    if a.tenant_id != r.tenant_id or db.get(BackupRepoAccess, (r.id, a.id)) is None:
        bad("that machine has no access to this repository")
    if not bk.online(a):
        bad(f"{a.display_name or a.hostname} is offline; choose a machine that is online")
    job = bk.queue(db, a, {"type": "list_images", "unlock": {"user": p.user.id, "sealed": _sealed(body.get("sealed"))}},
                   r.id, p.actor)
    bk.record(db, p.actor, "backup.repository.unlock_requested", r.name, r.tenant_id, machine=a.hostname)
    db.commit()
    return {"id": job.id}


@router.get("/unlock/{job_id}")
def unlock_result(job_id: str, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The outcome of a passphrase check; when it passed, a 30-minute unlock for this browser session."""
    p.require("read")
    job = db.get(BackupJob, job_id)
    unlock = (job.kind or {}).get("unlock") if job is not None else None
    if job is None or job.tenant_id not in p.tenant_ids or not isinstance(unlock, dict) or unlock.get("user") != p.user.id:
        raise HTTPException(404, "No such check")
    if job.state in ("queued", "dispatched", "running"):
        return {"state": "pending"}
    if job.state not in ("succeeded", "warning"):
        return {"state": "failed", "error": job.error or f"the check was {job.state}"}
    if job.finished_at is None or utcnow() - job.finished_at > timedelta(minutes=10):
        return {"state": "failed", "error": "this check has expired; unlock again"}
    secret = get_settings().secret_key
    token = issue_token(secret, p.user.id, UNLOCK_MINUTES, aud="backup-unlock", repo=job.repository_id,
                        session=digest(request.headers.get("Authorization", "")), state=reauth_state(secret, p.user))
    return {"state": "unlocked", "repositoryId": job.repository_id, "token": token, "expiresInSeconds": UNLOCK_MINUTES * 60}


@router.get("/images")
def list_images(request: Request, tenantId: str | None = None, repositoryId: str | None = None,
                agentId: str | None = None, device: str | None = None, order: str = "desc",
                p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Images in repositories this browser session has unlocked: the newest 1000, newest first, or oldest first with
    order=asc (a machine's backups in the order they were taken)."""
    if order not in ("asc", "desc"):
        bad("order must be asc or desc")
    p.require("read")
    unlocked = _unlocked(request, p)
    if repositoryId and repositoryId not in unlocked:
        raise HTTPException(403, "repository_locked")
    q = select(BackupImage).where(BackupImage.tenant_id.in_(scoped_tenant(p, tenantId)),
                                  BackupImage.repository_id.in_([repositoryId] if repositoryId else unlocked or [""]))
    if agentId:
        q = q.where(BackupImage.agent_id == agentId)
    rows = db.execute(q.order_by(BackupImage.created_unix.desc()).limit(2000)).scalars().all()
    if device:
        rows = [i for i in rows if _device_key(i) == device]
    rows = rows[:1000]
    if order == "asc":
        rows.reverse()
    checks = _boot_latest(db, [i.image_id for i in rows])
    return [image_out(i, checks) for i in rows]


def _image(db: Session, p: Principal, image_id: str) -> BackupImage:
    im = db.get(BackupImage, _uuid(image_id, "image id"))
    if im is None or im.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "No such image")
    return im


# Restores as files for another hypervisor (agent vmdef.rs): format -> hypervisor.
VM_FILE_FORMATS = {"qcow2": "QEMU/KVM", "vdi": "VirtualBox", "vmdk": "VMware"}
VM_NAME = re.compile(r"[A-Za-z0-9._-](?:[A-Za-z0-9 ._-]{0,78}[A-Za-z0-9._-])?")


@router.post("/restores")
def create_restore(request: Request, body: dict = Body(...), p: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)):
    im = _image_unlocked(request, db, p, str(body.get("imageId") or ""))
    a = _agent(db, p, str(body.get("agentId") or ""))
    t = body.get("target") if isinstance(body.get("target"), dict) else {}
    kind = t.get("type")
    if kind == "vhdx":
        p.require("scripts")
        d = str(t.get("directory") or "").strip()
        if not d:
            bad("choose a folder on the target machine")
        target, need = {"type": "vhdx", "directory": d}, "restore_vhdx"
    elif kind == "hyperv_vm":
        p.require("scripts")
        name, d = str(t.get("name") or "").strip()[:100], str(t.get("directory") or "").strip()
        if not name or not d:
            bad("choose a VM name and a folder on the host")
        target = {"type": "hyperv_vm", "name": name, "directory": d,
                  "switch": (str(t.get("switch")).strip() or None) if t.get("switch") else None, "start": bool(t.get("start"))}
        need = "restore_hyperv"
    elif kind == "vm_files":
        # Disk files and a VM definition for another hypervisor, in a new folder.
        p.require("scripts")
        fmt = t.get("format")
        if fmt not in VM_FILE_FORMATS:
            bad("choose QEMU (qcow2), VirtualBox (vdi) or VMware (vmdk)")
        name, d = str(t.get("name") or ""), str(t.get("directory") or "").strip()
        if not VM_NAME.fullmatch(name) or not d:
            bad("choose a VM name (letters, digits, spaces, dots, hyphens, underscores) and a folder on the machine")
        target, need = {"type": "vm_files", "format": fmt, "name": name, "directory": d}, "restore_vm_files"
    elif kind == "disk":
        # Overwrites a whole disk: typed confirmation, destructive permission and a fresh password check.
        p.require("destructive")
        require_reauth(request, p)
        device = str(t.get("device") or "").strip()
        if not device or t.get("confirm") != device:
            bad("type the target device exactly to confirm that it will be overwritten")
        disk = t.get("disk", 0)
        if not isinstance(disk, int) or disk < 0:
            bad("choose a disk of the image")
        # A device must be one the machine reported, and not its system disk or a disk in use (such as the
        # recovery medium). Image files are checked by the agent.
        if device.startswith("/dev/") or device.startswith("\\\\.\\"):
            d = next((x for x in (a.inventory or {}).get("disks") or [] if x.get("path") == device), None)
            if d is None:
                bad("that disk is not one the machine reported")
            if d.get("system") or d.get("in_use"):
                bad("that disk is in use on the machine (its system disk, the recovery medium, or mounted)")
        target, need = {"type": "disk", "device": device, "disk": disk, "confirm": device,
                        "grow": bool(t.get("grow", True))}, "restore_disk"
    else:
        bad("choose where to restore to")
    if need not in bk.capabilities(a):
        bad("that machine cannot perform this kind of restore")
    if a.tenant_id != im.tenant_id or db.get(BackupRepoAccess, (im.repository_id, a.id)) is None:
        bad("that machine has no access to the image's repository; give it access first")
    disks = [d for d in body.get("disks") or [] if isinstance(d, int) and d >= 0]
    job = bk.queue(db, a, {"type": "restore", "image_id": im.image_id, "disks": disks, "target": target},
                   im.repository_id, p.actor)
    bk.record(db, p.actor, "backup.restore.requested", im.hostname, im.tenant_id, image=im.image_id,
              machine=a.hostname, restore_to=kind, device=target.get("device"), format=target.get("format"))
    db.commit()
    return {"id": job.id}


def _file_agent(db: Session, p: Principal, im: BackupImage, agent_id: str | None) -> BackupAgent:
    """The machine that reads the image: the one asked for, else the machine it came from, else any with access."""
    if agent_id:
        a = _agent(db, p, agent_id)
    else:
        candidates = [x for x in db.execute(select(BackupAgent).join(BackupRepoAccess, BackupRepoAccess.agent_id == BackupAgent.id)
                                            .where(BackupRepoAccess.repository_id == im.repository_id,
                                                   BackupAgent.revoked.is_(False))).scalars()]
        candidates.sort(key=lambda x: (x.id != im.agent_id, not bk.online(x), "restore_files" not in bk.capabilities(x)))
        if not candidates:
            bad("no machine has access to this image's repository")
        a = candidates[0]
    if a.tenant_id != im.tenant_id or db.get(BackupRepoAccess, (im.repository_id, a.id)) is None:
        bad("that machine has no access to the image's repository; give it access first")
    if "restore_files" not in bk.capabilities(a):
        bad(f"the backup agent on {a.display_name or a.hostname} is too old to browse files; it updates itself shortly")
    return a


def _volume(body: dict) -> dict | None:
    if body.get("disk") is None and body.get("partition") is None:
        return None
    disk, part = body.get("disk"), body.get("partition")
    if not isinstance(disk, int) or not isinstance(part, int) or disk < 0 or part < 1:
        bad("choose a volume")
    return {"disk": disk, "partition": part}


@router.post("/images/{image_id}/browse")
def browse_files(image_id: str, request: Request, body: dict = Body(default={}), p: Principal = Depends(current_principal),
                 db: Session = Depends(get_db)):
    """List an image's volumes (no volume given) or one folder. Returns a job; poll it for the listing."""
    p.require("scripts")
    im = _image_unlocked(request, db, p, image_id)
    a = _file_agent(db, p, im, body.get("agentId"))
    path = str(body.get("path") or "/")
    if len(path) > 4000 or ".." in path.replace("\\", "/").split("/"):
        bad("invalid folder")
    job = bk.queue(db, a, {"type": "browse_files", "image_id": im.image_id, "volume": _volume(body), "path": path},
                   im.repository_id, p.actor)
    if _volume(body) is None:
        bk.record(db, p.actor, "backup.files.browsed", im.hostname, im.tenant_id, image=im.image_id, machine=a.hostname)
    db.commit()
    return {"id": job.id, "agentId": a.id, "agentName": a.display_name or a.hostname, "agentOnline": bk.online(a)}


@router.post("/images/{image_id}/restore-files")
def restore_files(image_id: str, request: Request, body: dict = Body(...), p: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    """Copy chosen files and folders out of a backup to a folder on a machine."""
    p.require("scripts")
    im = _image_unlocked(request, db, p, image_id)
    a = _file_agent(db, p, im, body.get("agentId"))
    volume = _volume(body)
    if volume is None:
        bad("choose a volume")
    paths = [str(x) for x in body.get("paths") or [] if str(x).strip("/")]
    if not paths or len(paths) > 1000 or any(len(x) > 4000 for x in paths):
        bad("choose 1 to 1000 files or folders")
    target = str(body.get("target") or "").strip()
    if not target or len(target) > 1000:
        bad("choose the folder to restore into")
    conflict = body.get("conflict") or "rename"
    if conflict not in ("rename", "skip", "overwrite"):
        bad("existing files: rename, skip or overwrite")
    if conflict == "overwrite":
        # Replaces files that are on the machine now: deliberate, re-authenticated.
        p.require("destructive")
        require_reauth(request, p)
    job = bk.queue(db, a, {"type": "restore_files", "image_id": im.image_id, "volume": volume, "paths": paths,
                           "target": target, "keep_structure": bool(body.get("keepStructure", True)),
                           "conflict": conflict}, im.repository_id, p.actor)
    bk.record(db, p.actor, "backup.files.restore_requested", im.hostname, im.tenant_id, image=im.image_id,
              machine=a.hostname, items=len(paths), first=paths[0][:300], restore_to=target, conflict=conflict)
    db.commit()
    return {"id": job.id}


@router.post("/images/{image_id}/download-files")
def download_files(image_id: str, request: Request, body: dict = Body(...), p: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)):
    """Send chosen files to this browser, encrypted for its one-time key: the machine restores and encrypts them,
    this server only relays ciphertext (backup/docs/design/file-download.md)."""
    p.require("scripts")
    im = _image_unlocked(request, db, p, image_id)
    a = _file_agent(db, p, im, body.get("agentId"))
    volume = _volume(body)
    if volume is None:
        bad("choose a volume")
    paths = [str(x) for x in body.get("paths") or [] if str(x).strip("/")]
    if not paths or len(paths) > 1000 or any(len(x) > 4000 for x in paths):
        bad("choose 1 to 1000 files or folders")
    recipient = str(body.get("recipient") or "").strip()
    try:
        ok = len(base64.b64decode(recipient, validate=True)) == 32
    except (binascii.Error, ValueError):
        ok = False
    if not ok:
        bad("recipient must be a 32-byte X25519 public key (base64)")
    job = bk.queue(db, a, {"type": "download_files", "image_id": im.image_id, "volume": volume, "paths": paths,
                           "recipient": recipient}, im.repository_id, p.actor)
    bk.record(db, p.actor, "backup.files.download_requested", im.hostname, im.tenant_id, image=im.image_id,
              machine=a.hostname, items=len(paths), first=paths[0][:300])
    db.commit()
    return {"id": job.id}


@router.get("/jobs/{job_id}/download")
def get_download(job_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The encrypted stream of a finished download; only the browser that asked can open it."""
    p.require("scripts")
    job = db.get(BackupJob, job_id)
    if job is None or job.tenant_id not in p.tenant_ids or (job.kind or {}).get("type") != "download_files":
        raise HTTPException(404, "No such download")
    if job.state not in ("succeeded", "warning"):
        raise HTTPException(409, "the download is not ready")
    path = bk.download_path(job.id)
    if not path.exists():
        raise HTTPException(404, "the download has expired")
    return FileResponse(path, media_type="application/octet-stream", headers={"Cache-Control": "no-store"})


@router.post("/images/{image_id}/boot-check")
def create_boot_check(image_id: str, request: Request, body: dict = Body(default={}), p: Principal = Depends(current_principal),
                      db: Session = Depends(get_db)):
    p.require("scripts")
    im = _image_unlocked(request, db, p, image_id)
    a = _agent(db, p, str(body.get("agentId") or ""))
    mem, cpus, keep = body.get("memoryMb"), body.get("cpus"), bool(body.get("keepRunning"))
    if (mem is not None and not (isinstance(mem, int) and 256 <= mem <= 65536)) or \
            (cpus is not None and not (isinstance(cpus, int) and 1 <= cpus <= 16)):
        bad("memory must be 256 MB to 64 GB, CPUs 1 to 16")
    caps = bk.capabilities(a)
    if "boot_kvm" not in caps and "boot_hyperv" not in caps:
        bad("that machine cannot boot VMs (it needs QEMU on Linux, or Hyper-V on Windows)")
    directory = str(body.get("directory") or "").strip() or None
    if directory and ("boot_hyperv" not in caps or len(directory) > 500 or not re.match(r"^([A-Za-z]:\\|\\\\)", directory)):
        bad("the folder for the VM is for Hyper-V hosts and must be a full Windows path, e.g. D:\\Fenrir checks")
    if a.tenant_id != im.tenant_id or db.get(BackupRepoAccess, (im.repository_id, a.id)) is None:
        bad("that machine has no access to the image's repository; give it access first")
    job = bk.queue(db, a, {"type": "boot_check", "image_id": im.image_id, "keep_running": keep, "memory_mb": mem,
                           "cpus": cpus, "directory": directory}, im.repository_id, p.actor)
    bk.record(db, p.actor, "backup.boot_check.requested", im.hostname, im.tenant_id, image=im.image_id, machine=a.hostname,
              keep=keep, directory=directory)
    db.commit()
    return {"id": job.id}


@router.get("/images/{image_id}/boot-checks")
def list_boot_checks(image_id: str, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    im = _image_unlocked(request, db, p, image_id)
    names = _names(db, [im.tenant_id])
    rows = db.execute(select(BackupBootCheck).where(BackupBootCheck.image_id == im.image_id)
                      .order_by(BackupBootCheck.at.desc(), BackupBootCheck.id.desc()).limit(50)).scalars().all()
    return [{"id": b.id, "at": iso(b.at), "outcome": b.outcome, "method": b.method, "seconds": b.seconds,
             "firmware": b.firmware, "accel": b.accel, "message": b.message, "hasScreenshot": b.screenshot is not None,
             "agentId": b.agent_id, "agentName": names.get(b.agent_id), "jobId": b.job_id} for b in rows]


@router.get("/boot-checks/{check_id}/screenshot.png")
def boot_screenshot(check_id: int, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    b = db.get(BackupBootCheck, check_id)
    if b is None or b.tenant_id not in p.tenant_ids or not b.screenshot:
        raise HTTPException(404, "No screenshot")
    return Response(b.screenshot, media_type="image/png", headers={"Cache-Control": "private, max-age=86400"})


@router.post("/agents/{agent_id}/vms/{session_id}/stop")
def stop_vm(agent_id: str, session_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("scripts")
    a = _agent(db, p, agent_id)
    job = bk.queue(db, a, {"type": "stop_vm", "session_id": _uuid(session_id, "session id")}, None, p.actor)
    bk.record(db, p.actor, "backup.vm.stop_requested", a.hostname, a.tenant_id, session=session_id)
    db.commit()
    return {"id": job.id}


# --------------------------------------------------------------------------
# Settings (platform-wide)
# --------------------------------------------------------------------------


@router.get("/settings")
def get_backup_settings(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    builds = {t.triple: (bk.binary_info(t) or (None, 0)) for t in bk.ALL_TARGETS.values()}
    return {**backup_settings(db), "builds": {k: {"sha256": v[0], "size": v[1]} for k, v in builds.items()}}


@router.put("/settings")
def put_backup_settings(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("platform")
    msp = db.execute(select(Tenant).where(Tenant.kind == "msp").order_by(Tenant.created_at)).scalars().first()
    if msp is None:
        raise HTTPException(409, "no MSP tenant")
    settings = dict(msp.settings or {})
    settings["backup"] = {**(settings.get("backup") or {}), "autoUpdate": bool(body.get("autoUpdate", True))}
    msp.settings = settings
    bk.record(db, p.actor, "backup.settings.changed", "backup", None, autoUpdate=settings["backup"]["autoUpdate"])
    db.commit()
    return {"ok": True}
