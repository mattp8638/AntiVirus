"""Device backup: the server side of backup/ (fenrir-backup-agent).

Ported from the Fenrir-Backup server. Agents enrol with a one-time link, poll a heartbeat for jobs, and report
progress and results; the console creates repositories, plans and restores. Repository passphrases and network
share sign-ins are sealed in the browser to each agent's X25519 key: this server stores only the sealed copies.

This module holds the logic shared by routers/backup_agent.py (agents), routers/backup.py (console) and the
background scheduler: schedules, retention, the ransomware guard, update offers, installers and alerts.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import struct
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit
from . import backup_installers as tpl
from .models import (Alert, Device, BackupAgent, BackupBootCheck, BackupImage, BackupJob, BackupRepoAccess, BackupRepository,
                     BackupScan, DrRun, DrRunbook, ImageBackupPlan, Indicator, YaraRule, utcnow)

PROTOCOL_VERSION = 1
POLL_SECONDS = 15
# A dispatched job the agent stopped mentioning for this long is considered lost (agent restarted mid-job).
LOST_AFTER = timedelta(seconds=180)
ACTIVE_STATES = ("queued", "dispatched", "running")
FINAL_STATES = ("succeeded", "warning", "failed", "cancelled")
ROLES = ("workstation", "server", "hyperv", "recovery")
# Roles an installer can enrol; "recovery" is only for recovery media.
INSTALL_ROLES = ("workstation", "server", "hyperv")
MAX_SCREENSHOT = 4 << 20

# Alert rules (Alert.rule_id) raised into the normal alert queue.
RULE_FAILED = "backup.job_failed"
RULE_RANSOMWARE = "backup.ransomware_hold"
RULE_BOOT = "backup.boot_failed"
RULE_OFFLINE = "backup.agent_offline"
RULE_OVERDUE = "backup.overdue"


def unix(dt: datetime | None) -> int | None:
    return None if dt is None else int(dt.replace(tzinfo=timezone.utc).timestamp())


def from_unix(t: int) -> datetime:
    return datetime.fromtimestamp(t, timezone.utc).replace(tzinfo=None)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# --------------------------------------------------------------------------
# Job kinds (protocol JobKind, "type"-tagged)
# --------------------------------------------------------------------------

BACKUP_KINDS = ("backup_system", "backup_disks", "backup_hyperv", "backup_kubernetes", "backup_saas")
KIND_LABELS = {
    "init_repository": "Create repository", "backup_system": "System backup", "backup_disks": "Disk backup",
    "backup_hyperv": "Hyper-V backup", "verify": "Verify", "list_images": "Refresh images",
    "apply_retention": "Apply retention", "copy_images": "Copy off-site", "prune": "Reclaim space", "restore": "Restore", "boot_check": "Boot check",
    "stop_vm": "Stop VM", "check_access": "Test connection", "browse_files": "Browse files",
    "restore_files": "Restore files", "download_files": "Download files",
    "backup_kubernetes": "Kubernetes backup", "restore_kubernetes": "Kubernetes restore",
    "backup_saas": "SaaS backup", "restore_saas": "SaaS restore",
}
LOCAL_RECOVERY_LABELS = {"install": "Install local recovery", "refresh": "Refresh local recovery",
                         "remove": "Remove local recovery"}
# How long a local recovery partition's enrolment code works (renewed whenever it is rebuilt).
LOCAL_RECOVERY_DAYS = 365
# Capability the agent must report for console-created jobs of each kind.
KIND_CAPABILITY = {"backup_system": "backup_system", "backup_disks": "backup_disks", "backup_hyperv": "backup_hyperv",
                   "verify": "verify", "backup_kubernetes": "kubernetes", "restore_kubernetes": "kubernetes",
                   "backup_saas": "saas", "restore_saas": "saas"}


def label(kind: dict | None) -> str:
    if (kind or {}).get("unlock"):
        return "Passphrase check"
    if (kind or {}).get("type") == "local_recovery":
        return LOCAL_RECOVERY_LABELS.get(str(kind.get("action")), "Local recovery")
    return KIND_LABELS.get((kind or {}).get("type", ""), "Job")


def is_backup(kind: dict | None) -> bool:
    return (kind or {}).get("type") in BACKUP_KINDS


# --------------------------------------------------------------------------
# Schedules
# --------------------------------------------------------------------------


def _parse_hm(value: str) -> tuple[int, int] | None:
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", value or "")
    if not m:
        return None
    h, mi = int(m.group(1)), int(m.group(2))
    return (h, mi) if h < 24 and mi < 60 else None


def validate_schedule(s: dict) -> None:
    kind = s.get("type")
    if kind == "interval":
        # Hours and minutes (frequent backups, Fenrir-Backup frequent-backups.md): 5 minutes to 31 days.
        hours, minutes = s.get("hours", 0), s.get("minutes", 0)
        if not isinstance(hours, int) or not isinstance(minutes, int) or not 0 <= minutes < 60 or hours < 0 \
                or not 5 <= hours * 60 + minutes <= 31 * 24 * 60:
            raise ValueError("interval must be 5 minutes to 31 days")
    elif kind == "daily":
        if _parse_hm(s.get("time", "")) is None:
            raise ValueError("time must be HH:MM")
        if any(not isinstance(d, int) or not 0 <= d <= 6 for d in s.get("days", [])):
            raise ValueError("days are 0 (Monday) to 6 (Sunday)")
        if abs(int(s.get("utc_offset_minutes", 0))) > 14 * 60:
            raise ValueError("UTC offset out of range")
    elif kind != "manual":
        raise ValueError("schedule type must be interval, daily or manual")


def next_after(s: dict, after: int) -> int | None:
    """First run time strictly after `after` (Unix seconds)."""
    kind = s.get("type")
    if kind == "interval":
        return after + int(s.get("hours", 0)) * 3600 + int(s.get("minutes", 0)) * 60
    if kind != "daily":
        return None
    hm = _parse_hm(s.get("time", ""))
    if hm is None:
        return None
    off = int(s.get("utc_offset_minutes", 0)) * 60
    local = after + off
    day_start = (local // 86_400) * 86_400
    days = s.get("days") or []
    for d in range(8):
        cand = day_start + d * 86_400 + hm[0] * 3600 + hm[1] * 60
        if cand <= local:
            continue
        weekday = ((cand // 86_400) + 3) % 7  # 1970-01-01 was a Thursday (Monday = 0)
        if not days or weekday in days:
            return cand - off
    return None


RETENTION_FIELDS = ("keep_last", "keep_hourly", "keep_daily", "keep_weekly", "keep_monthly", "keep_yearly")


def keeps_everything(r: dict | None) -> bool:
    return not r or all(int(r.get(k, 0) or 0) == 0 for k in RETENTION_FIELDS)


def validate_retention(r: dict | None) -> dict | None:
    if r is None:
        return None
    out = {}
    for k in RETENTION_FIELDS:
        v = r.get(k, 0)
        if not isinstance(v, int) or not 0 <= v <= 10_000:
            raise ValueError("retention counts must be 0 to 10000")
        out[k] = v
    return None if keeps_everything(out) else out


# --------------------------------------------------------------------------
# Ransomware guard (anomaly.rs)
# --------------------------------------------------------------------------


@dataclass
class ChangeStats:
    chunks_total: int
    chunks_new: int
    bytes_new_raw: int
    bytes_new_stored: int

    def change_ratio(self) -> float:
        return 0.0 if self.chunks_total == 0 else self.chunks_new / self.chunks_total

    def incompressibility(self) -> float:
        return 0.0 if self.bytes_new_raw == 0 else self.bytes_new_stored / self.bytes_new_raw


def evaluate_anomaly(history: list[ChangeStats], current: ChangeStats) -> str | None:
    """The reason when `current` looks like mass encryption: far more changed than usual, and incompressible."""
    ratio, incompressible = current.change_ratio(), current.incompressibility()
    if current.chunks_new < 8:
        return None  # too little new data to judge
    ratios = sorted(h.change_ratio() for h in history if h.chunks_total > 0)
    if len(ratios) >= 5:
        baseline = ratios[len(ratios) // 2]
        if ratio > max(3.0 * baseline, 0.25) and incompressible > 0.9:
            return (f"{ratio * 100:.0f}% of the data changed (usual: {baseline * 100:.0f}%) and the new data does not "
                    f"compress ({incompressible * 100:.0f}% of original size): possible mass encryption")
        return None
    if ratios and ratio > 0.5 and incompressible > 0.95:
        return (f"{ratio * 100:.0f}% of the data changed since the previous backup and the new data does not compress: "
                "possible mass encryption")
    return None  # first backup: everything is new by definition


# --------------------------------------------------------------------------
# Agent builds, updates and installers
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Target:
    triple: str
    file: str
    arch: str


WIN = (Target("x86_64-pc-windows-msvc", "fenrir-backup-agent.exe", "x64"),)
LINUX = (Target("x86_64-unknown-linux-musl", "fenrir-backup-agent", "x86_64"),
         Target("aarch64-unknown-linux-musl", "fenrir-backup-agent", "arm64"))
MAC = (Target("aarch64-apple-darwin", "fenrir-backup-agent", "Apple silicon"),
       Target("x86_64-apple-darwin", "fenrir-backup-agent", "Intel"))
PLATFORMS = {
    "windows": {"name": "Windows", "targets": WIN, "role": None, "script": "install-fenrir-backup.ps1",
                "setup": "Fenrir-Backup-Setup.exe"},
    "hyperv": {"name": "Hyper-V host", "targets": WIN, "role": "hyperv", "script": "install-fenrir-backup-hyperv.ps1",
               "setup": "Fenrir-Backup-Setup-HyperV.exe"},
    "linux": {"name": "Linux", "targets": LINUX, "role": None, "script": "install-fenrir-backup.sh", "setup": None},
    "macos": {"name": "macOS", "targets": MAC, "role": None, "script": "install-fenrir-backup-macos.sh", "setup": None},
}
ALL_TARGETS = {t.triple: t for p in PLATFORMS.values() for t in p["targets"]}


# Encrypted file downloads waiting for the browser (backup/docs/design/file-download.md): kept a day.
DOWNLOAD_MAX = (4 << 30) + (64 << 20)


def downloads_dir() -> Path:
    from .config import get_settings

    return Path(get_settings().artifact_dir) / "backup-downloads"


def download_path(job_id: str) -> Path:
    return downloads_dir() / f"{uuid.UUID(job_id)}.bin"


def purge_downloads(max_age_seconds: int = 86_400) -> int:
    d, n = downloads_dir(), 0
    if not d.is_dir():
        return 0
    for f in d.iterdir():
        try:
            if time.time() - f.stat().st_mtime >= max_age_seconds:
                f.unlink()
                n += 1
        except OSError:
            pass
    return n


def agents_dir() -> Path:
    return Path(os.getenv("FENRIR_BACKUP_AGENTS_DIR", "/app/cloud/downloads/backup"))


def binary_path(t: Target) -> Path:
    return agents_dir() / t.triple / t.file


_HASHES: dict[Path, tuple[float, int, str]] = {}


def binary_info(t: Target) -> tuple[str, int] | None:
    """(sha256, size) of an agent build, cached by mtime and size."""
    p = binary_path(t)
    try:
        st = p.stat()
    except OSError:
        return None
    hit = _HASHES.get(p)
    if hit and hit[0] == st.st_mtime and hit[1] == st.st_size:
        return hit[2], st.st_size
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    _HASHES[p] = (st.st_mtime, st.st_size, h)
    return h, st.st_size


def update_offer(inventory: dict) -> dict | None:
    """The build this agent should run, if it differs from the one it runs (static Linux builds replace glibc ones;
    the Windows slot holds MSVC or MinGW builds)."""
    target, running = inventory.get("agent_target") or "", inventory.get("agent_sha256") or ""
    if not target or not running:
        return None
    want = target.replace("-unknown-linux-gnu", "-unknown-linux-musl").replace("-pc-windows-gnu", "-pc-windows-msvc")
    t = ALL_TARGETS.get(want)
    info = binary_info(t) if t else None
    if info is None or info[0].lower() == running.lower():
        return None
    return {"path": f"/agent/{t.triple}/{t.file}", "sha256": info[0]}


SETUP_MAGIC = b"FENRIR-SETUP-V1\0"


def setup_exe(exe: bytes, server: str, pin: str, token: str, role: str) -> bytes:
    """The Windows agent with this enrollment's settings appended (backup/crates/protocol/src/setup.rs)."""
    cfg = json.dumps({"server": server, "pin": pin, "token": token, "role": role}, separators=(",", ":")).encode()
    return exe + cfg + struct.pack("<I", len(cfg)) + SETUP_MAGIC


def windows_one_liner(script_url: str, pin: str) -> str:
    return ("if (-not ('FenrirDl' -as [type])) { Add-Type -IgnoreWarnings -TypeDefinition '" + tpl.WIN_DOWNLOADER_CS
            + "' }; [FenrirDl]::Pin = '" + pin + "'; iex ([Text.Encoding]::UTF8.GetString([FenrirDl]::Get('"
            + script_url + "')))")


def install_script(platform: str, server: str, pin: str, token: str, role: str) -> str:
    p = PLATFORMS[platform]
    shas = {t.triple: (binary_info(t) or ("", 0))[0] for t in p["targets"]}
    if platform in ("windows", "hyperv"):
        hyperv = platform == "hyperv"
        return tpl.WINDOWS.format(url=server, pin=pin, token=token, role=role, sha=shas[WIN[0].triple],
                                  hyperv_check=tpl.HYPERV_CHECK if hyperv else "", cs=tpl.WIN_DOWNLOADER_CS,
                                  kind=" (Hyper-V host)" if hyperv else "", suffix="-hyperv" if hyperv else "")
    common = tpl.UNIX_COMMON.format(url=server, pin=pin, token=token, role=role)
    if platform == "linux":
        return tpl.LINUX.format(common=common, x64=shas["x86_64-unknown-linux-musl"], arm=shas["aarch64-unknown-linux-musl"])
    return tpl.MACOS.format(common=common, arm=shas["aarch64-apple-darwin"], x64=shas["x86_64-apple-darwin"])


UNINSTALLERS = {"windows": ("uninstall-fenrir-backup.ps1", tpl.WIN_UNINSTALL),
                "hyperv": ("uninstall-fenrir-backup.ps1", tpl.WIN_UNINSTALL),
                "linux": ("uninstall-fenrir-backup.sh", tpl.LINUX_UNINSTALL),
                "macos": ("uninstall-fenrir-backup-macos.sh", tpl.MAC_UNINSTALL)}


# --------------------------------------------------------------------------
# Jobs
# --------------------------------------------------------------------------


def queue(db: Session, agent: BackupAgent, kind: dict, repository_id: str | None, by: str,
          plan_id: str | None = None) -> BackupJob:
    job = BackupJob(tenant_id=agent.tenant_id, agent_id=agent.id, repository_id=repository_id, plan_id=plan_id,
                    kind=kind, requested_by=by)
    db.add(job)
    db.flush()
    return job


def capabilities(agent: BackupAgent) -> list[str]:
    return list((agent.inventory or {}).get("capabilities") or [])


def online(agent: BackupAgent, now: datetime | None = None) -> bool:
    now = now or utcnow()
    return agent.last_seen_at is not None and now - agent.last_seen_at < timedelta(seconds=POLL_SECONDS * 4 + 30)


def raise_alert(db: Session, tenant_id: str, device_id: str | None, rule: str, title: str, severity: str,
                description: str, link: str = "/backups", dedupe_key: str | None = None) -> None:
    """An alert in the normal queue. With `dedupe_key`, at most one open alert per key."""
    if dedupe_key:
        open_ = db.execute(select(Alert).where(Alert.tenant_id == tenant_id, Alert.rule_id == rule,
                                               Alert.status.in_(("new", "triaged")))).scalars().all()
        if any((a.details or {}).get("key") == dedupe_key for a in open_):
            return
    db.add(Alert(tenant_id=tenant_id, device_id=device_id, rule_id=rule, title=title[:300], severity=severity,
                 mitre=["T1486"] if rule == RULE_RANSOMWARE else [], event_ids=[],
                 details={"category": "backup", "source": "Fenrir backup", "description": description,
                          "link": link, "key": dedupe_key}))


def resolve_alerts(db: Session, tenant_id: str, rule: str, dedupe_key: str, note: str) -> None:
    for a in db.execute(select(Alert).where(Alert.tenant_id == tenant_id, Alert.rule_id == rule,
                                            Alert.status.in_(("new", "triaged")))).scalars():
        if (a.details or {}).get("key") == dedupe_key:
            a.status, a.updated_at = "resolved", utcnow()
            a.details = {**(a.details or {}), "autoResolved": note}


def check_anomaly(db: Session, repo_id: str, im: dict) -> str | None:
    rows = db.execute(select(BackupImage).where(
        BackupImage.machine_id == im["machine_id"], BackupImage.repository_id == repo_id,
        BackupImage.image_id != im["image_id"], BackupImage.chunks_total > 0,
    ).order_by(BackupImage.created_unix.desc()).limit(10)).scalars().all()
    hist = [ChangeStats(r.chunks_total, r.chunks_new, r.bytes_new_raw, r.stored_new_bytes) for r in rows]
    cur = ChangeStats(int(im.get("chunks_total") or 0), int(im.get("chunks_new") or 0),
                      int(im.get("bytes_new_raw") or 0), int(im.get("stored_new_bytes") or 0))
    return evaluate_anomaly(hist, cur)


def queue_copy(db: Session, plan_id: str, repo_id: str, agent: BackupAgent, images: list[dict]) -> None:
    """The plan's off-site copy of the images just taken, on the same machine (Fenrir-Backup offsite-copy.md)."""
    plan = db.get(ImageBackupPlan, plan_id)
    ids = [str(i["image_id"]) for i in images if i.get("image_id")]
    if plan is None or not plan.copy_to_repository_id or not ids:
        return
    queue(db, agent, {"type": "copy_images", "target_repository_id": plan.copy_to_repository_id, "images": ids,
                      "full_verify": False}, repo_id, "copy", plan_id=plan_id)


def queue_retention(db: Session, plan_id: str, repo_id: str, agent: BackupAgent, images: list[dict]) -> None:
    plan = db.get(ImageBackupPlan, plan_id)
    if plan is None or keeps_everything(plan.retention):
        return
    machine_ids = sorted({i["machine_id"] for i in images})
    repo = db.get(BackupRepository, repo_id)
    if repo is not None and repo.gateway_agent_id and repo.gateway_agent_id != agent.id:
        # Served append-only through a gateway: only the gateway deletes old images.
        gateway = db.get(BackupAgent, repo.gateway_agent_id)
        if gateway is not None and not gateway.revoked:
            agent = gateway
    if machine_ids:
        queue(db, agent, {"type": "apply_retention", "machine_ids": machine_ids, "retention": plan.retention,
                          "dry_run": False}, repo_id, "retention", plan_id=plan_id)


# --------------------------------------------------------------------------
# Background work (main._scheduled_jobs / _maintenance_jobs)
# --------------------------------------------------------------------------


def run_due_plans(db: Session) -> int:
    """Queue jobs for plans that are due. A plan never has more than one unfinished job, so a machine that was
    offline catches up with one run rather than one per missed slot."""
    now = utcnow()
    created = 0
    for plan in db.execute(select(ImageBackupPlan).where(ImageBackupPlan.enabled.is_(True),
                                                         ImageBackupPlan.next_run_at.is_not(None),
                                                         ImageBackupPlan.next_run_at <= now)).scalars().all():
        agent = db.get(BackupAgent, plan.agent_id)
        busy = db.execute(select(func.count()).select_from(BackupJob).where(
            BackupJob.plan_id == plan.id, BackupJob.state.in_(ACTIVE_STATES))).scalar()
        if agent is not None and not agent.revoked and not busy:
            queue(db, agent, plan.job, plan.repository_id, "schedule", plan_id=plan.id)
            created += 1
        nxt = next_after(plan.schedule, unix(now))
        plan.last_run_at, plan.next_run_at = now, (from_unix(nxt) if nxt else None)
    db.commit()
    return created


def run_maintenance(db: Session) -> int:
    """Queue space reclamation where the interval has passed (not while on hold, one at a time)."""
    now = utcnow()
    queued = 0
    for repo in db.execute(select(BackupRepository).where(BackupRepository.status == "ready",
                                                          BackupRepository.hold.is_(False),
                                                          BackupRepository.prune_every_days > 0)).scalars().all():
        since = repo.last_prune_at or repo.created_at
        if now - since < timedelta(days=repo.prune_every_days):
            continue
        agent = db.get(BackupAgent, repo.maintenance_agent_id) if repo.maintenance_agent_id else None
        if agent is None or agent.revoked or db.get(BackupRepoAccess, (repo.id, agent.id)) is None:
            continue
        pending = db.execute(select(BackupJob).where(BackupJob.repository_id == repo.id,
                                                     BackupJob.state.in_(ACTIVE_STATES))).scalars().all()
        if any(j.kind.get("type") == "prune" for j in pending):
            continue
        queue(db, agent, {"type": "prune", "dry_run": False}, repo.id, "maintenance")
        queued += 1
    db.commit()
    return queued


def run_boot_checks(db: Session) -> int:
    """Boot verification: per repository, a boot check of the newest image of each machine not checked within
    the interval. One check per repository at a time."""
    now = utcnow()
    queued = 0
    for repo in db.execute(select(BackupRepository).where(BackupRepository.status == "ready",
                                                          BackupRepository.boot_every_days > 0,
                                                          BackupRepository.boot_agent_id.is_not(None))).scalars().all():
        agent = db.get(BackupAgent, repo.boot_agent_id)
        if agent is None or agent.revoked or db.get(BackupRepoAccess, (repo.id, agent.id)) is None:
            continue
        active = db.execute(select(BackupJob).where(BackupJob.repository_id == repo.id,
                                                    BackupJob.state.in_(ACTIVE_STATES))).scalars().all()
        if any(j.kind.get("type") == "boot_check" for j in active):
            continue
        images = db.execute(select(BackupImage).where(BackupImage.repository_id == repo.id)
                            .order_by(BackupImage.created_unix.desc())).scalars().all()
        newest: dict[str, BackupImage] = {}
        for im in images:
            newest.setdefault(im.machine_id, im)
        cutoff = now - timedelta(days=repo.boot_every_days)
        for machine_id, im in sorted(newest.items(), key=lambda kv: kv[1].created_unix):
            machine_images = [i.image_id for i in images if i.machine_id == machine_id]
            checked = db.execute(select(func.count()).select_from(BackupBootCheck).where(
                BackupBootCheck.repository_id == repo.id, BackupBootCheck.image_id.in_(machine_images),
                BackupBootCheck.at > cutoff)).scalar()
            recent_try = db.execute(select(BackupJob).where(
                BackupJob.repository_id == repo.id, BackupJob.requested_by == "boot verification",
                BackupJob.created_at > now - timedelta(days=1))).scalars().all()
            if checked or any(j.kind.get("image_id") == im.image_id for j in recent_try):
                continue
            queue(db, agent, {"type": "boot_check", "image_id": im.image_id, "keep_running": False,
                              "memory_mb": None, "cpus": None}, repo.id, "boot verification")
            queued += 1
            break
    db.commit()
    return queued


def check_health(db: Session) -> None:
    """Alerts for backup agents that stopped checking in and machines whose plan has not succeeded for too long;
    resolved automatically when they recover."""
    now = utcnow()
    for agent in db.execute(select(BackupAgent).where(BackupAgent.revoked.is_(False),
                                                      BackupAgent.role != "recovery")).scalars().all():
        name = agent.display_name or agent.hostname
        key = f"offline:{agent.id}"
        if agent.last_seen_at is not None and now - agent.last_seen_at > timedelta(hours=24):
            raise_alert(db, agent.tenant_id, agent.device_id, RULE_OFFLINE, f"Backup agent on {name} is offline",
                        "medium", f"The backup agent on {name} has not checked in since {agent.last_seen_at:%Y-%m-%d %H:%M} UTC.",
                        dedupe_key=key)
        elif agent.last_seen_at is not None:
            resolve_alerts(db, agent.tenant_id, RULE_OFFLINE, key, "The backup agent checked in again.")
    for plan in db.execute(select(ImageBackupPlan).where(ImageBackupPlan.enabled.is_(True))).scalars().all():
        if plan.schedule.get("type") == "manual":
            continue
        last_ok = db.execute(select(func.max(BackupJob.finished_at)).where(
            BackupJob.plan_id == plan.id, BackupJob.state.in_(("succeeded", "warning")))).scalar()
        since = last_ok or plan.created_at
        key = f"overdue:{plan.id}"
        agent = db.get(BackupAgent, plan.agent_id)
        if now - since > timedelta(days=3):
            raise_alert(db, plan.tenant_id, agent.device_id if agent else None, RULE_OVERDUE,
                        f"No successful backup for 3 days: {plan.name}", "high",
                        f"Plan {plan.name} has not completed a backup since {since:%Y-%m-%d %H:%M} UTC.", dedupe_key=key)
        else:
            resolve_alerts(db, plan.tenant_id, RULE_OVERDUE, key, "A backup completed.")
    db.commit()


def refresh_local_recovery(db: Session) -> int:
    """Rebuild local recovery partitions after an agent update, or when their enrolment code has under 60 days left
    (backup/docs/design/local-recovery.md). One at a time; not within a day of a failed attempt."""
    now = utcnow()
    n = 0
    for a in db.execute(select(BackupAgent).where(BackupAgent.revoked.is_(False), BackupAgent.role != "recovery")).scalars():
        inv = a.inventory or {}
        lr = inv.get("local_recovery")
        if not isinstance(lr, dict):
            continue
        expires = int(lr.get("expires") or 0)
        if lr.get("agent_version") == inv.get("agent_version") and not (expires and expires < now.timestamp() + 60 * 86400):
            continue
        busy = [j for j in db.execute(select(BackupJob).where(BackupJob.agent_id == a.id)).scalars()
                if (j.kind or {}).get("type") == "local_recovery" and
                (j.state in ACTIVE_STATES or (j.state in ("failed", "cancelled") and j.created_at > now - timedelta(days=1)))]
        if busy:
            continue
        queue(db, a, {"type": "local_recovery", "action": "refresh", "size_mb": 0, "auto_start": bool(lr.get("auto_start")),
                      "confirm": ""}, None, "schedule")
        n += 1
    db.commit()
    return n


# --------------------------------------------------------------------------
# DR runbooks (backup/docs/design/dr-runbooks.md)
# --------------------------------------------------------------------------

RULE_DR = "backup.dr_test_failed"
RULE_MALWARE = "backup.malware_found"

# --------------------------------------------------------------------------
# Malware scans of backup images (Fenrir-Backup docs/design/malware-scan.md)
# --------------------------------------------------------------------------

SCAN_MAX_INDICATORS = 500_000
SCAN_MAX_FINDINGS = 1000


def scan_content(db: Session, tenant_id: str) -> tuple[list[str], list[dict]]:
    """The detection content a scan of this customer's backups uses: malicious SHA-256 indicators (global and the
    customer's own, not expired, minus those allow-listed) and enabled YARA rules."""
    now = utcnow()
    scope = (Indicator.tenant_id.is_(None)) | (Indicator.tenant_id == tenant_id)
    live = (Indicator.expires_at.is_(None)) | (Indicator.expires_at > now)
    rows = db.execute(select(Indicator.value, Indicator.verdict).where(Indicator.type == "sha256", scope, live)).all()
    allowed = {v.lower() for v, verdict in rows if verdict == "allow"}
    hashes = sorted({v.lower() for v, verdict in rows if verdict == "malicious" and re.fullmatch(r"[0-9a-fA-F]{64}", v)}
                    - allowed)[:SCAN_MAX_INDICATORS]
    rules = [{"name": r.name, "source": r.source} for r in db.execute(
        select(YaraRule).where(YaraRule.enabled.is_(True),
                               (YaraRule.tenant_id.is_(None)) | (YaraRule.tenant_id == tenant_id))
        .order_by(YaraRule.name)).scalars()]
    return hashes, rules


def queue_scan(db: Session, agent: BackupAgent, image: BackupImage, by: str, selection: str = "executables",
               plan_id: str | None = None) -> BackupJob:
    hashes, rules = scan_content(db, image.tenant_id)
    return queue(db, agent, {"type": "scan_image", "image_id": image.image_id, "indicators": hashes, "rules": rules,
                             "selection": selection, "max_file_mib": 64}, image.repository_id, by, plan_id)


def scan_latest(db: Session, image_ids: list[str]) -> dict[str, BackupScan]:
    out: dict[str, BackupScan] = {}
    if image_ids:
        for r in db.execute(select(BackupScan).where(BackupScan.image_id.in_(image_ids))
                            .order_by(BackupScan.at.desc(), BackupScan.id.desc())).scalars():
            out.setdefault(r.image_id, r)
    return out


def _s(v, n: int) -> str:
    return str(v or "")[:n]


def record_scan(db: Session, job: BackupJob, agent: BackupAgent, state: str, result: dict | None) -> BackupScan | None:
    """Store what a finished scan job found. Only paths and names are kept, each field bounded."""
    kind = job.kind or {}
    image = db.get(BackupImage, str(kind.get("image_id")))
    if image is None:
        return None
    rep = (result or {}).get("scan") if isinstance((result or {}).get("scan"), dict) else None
    if state not in ("succeeded", "warning") or rep is None:
        row = BackupScan(image_id=image.image_id, repository_id=image.repository_id, tenant_id=image.tenant_id,
                         agent_id=agent.id, job_id=job.id, state="incomplete",
                         summary={"error": _s(job.error, 1000)})
        db.add(row)
        return row
    findings = []
    for f in (rep.get("findings") or [])[:SCAN_MAX_FINDINGS]:
        if not isinstance(f, dict):
            continue
        findings.append({"volume": _s(f.get("volume"), 200), "path": _s(f.get("path"), 2000),
                         "size": f["size"] if isinstance(f.get("size"), int) and f["size"] >= 0 else 0,
                         "sha256": _s(f.get("sha256"), 64).lower(),
                         "detections": [{"kind": _s(d.get("kind"), 10), "name": _s(d.get("name"), 300)}
                                        for d in (f.get("detections") or [])[:20] if isinstance(d, dict)]})
    scanned = [_s(v, 200) for v in (rep.get("volumes_scanned") or [])[:50]]
    summary = {k: [_s(v, 500) for v in (rep.get(k) or [])[:50]] for k in ("volumes_skipped", "rule_errors")}
    summary.update({"volumes_scanned": scanned, "truncated": bool(rep.get("truncated")),
                    **{k: int(rep.get(k) or 0) for k in ("files_cached", "files_skipped_large", "files_unreadable",
                                                          "rules_used", "indicators_used")},
                    "selection": _s(kind.get("selection") or "executables", 20)})
    verdict = "infected" if findings else ("clean" if scanned else "incomplete")
    row = BackupScan(image_id=image.image_id, repository_id=image.repository_id, tenant_id=image.tenant_id,
                     agent_id=agent.id, job_id=job.id, state=verdict, files_scanned=int(rep.get("files_scanned") or 0),
                     bytes_scanned=int(rep.get("bytes_scanned") or 0), findings=findings, summary=summary)
    db.add(row)
    what = image.vm_name or image.hostname or "a machine"
    record(db, f"backup-agent:{agent.id}", f"backup.scan.{verdict}", what, image.tenant_id, image=image.image_id,
           findings=len(findings))
    if findings:
        names = sorted({d["name"] for f in findings for d in f["detections"]})
        raise_alert(db, image.tenant_id, agent.device_id, RULE_MALWARE, f"Malware found in a backup of {what}",
                    "critical",
                    f"A scan of the backup of {what} taken at unix time {image.created_unix} found {len(findings)} "
                    f"infected file{'s' if len(findings) != 1 else ''} ({', '.join(names[:5])}). Restoring it brings "
                    "them back: restore from a clean backup (Images & restore shows the last clean one), or restore "
                    "and clean the files.", dedupe_key=f"backup-malware:{image.image_id}")
    return row


def device_key(i: BackupImage) -> str:
    """A backed-up machine (or VM): its agent, or host name, and VM name."""
    return f"{i.agent_id or 'host:' + (i.hostname or '')}|{i.vm_name or ''}"


def start_dr_run(db: Session, rb: DrRunbook, mode: str, by: str) -> DrRun:
    items = []
    for gi, g in enumerate(rb.groups or []):
        for m in g.get("machines") or []:
            items.append({"group": gi, "groupName": g.get("name") or f"Group {gi + 1}", "key": m["key"],
                          "name": m.get("name") or m["key"], "hostAgentId": m["hostAgentId"],
                          "memoryMb": m.get("memoryMb"), "cpus": m.get("cpus"), "directory": m.get("directory"),
                          "state": "pending", "message": None, "imageId": None, "imageCreated": None, "jobId": None,
                          "upAt": None, "seconds": None})
    run = DrRun(runbook_id=rb.id, tenant_id=rb.tenant_id, mode=mode, items=items, started_by=by,
                stop_after_minutes=rb.stop_after_minutes if mode == "test" else 0)
    db.add(run)
    db.flush()
    advance_dr_run(db, run)
    return run


def _latest_image(db: Session, key: str, host: BackupAgent) -> tuple[BackupImage | None, str | None]:
    """The machine's newest image in a repository the host can read."""
    agent_part, vm = key.split("|", 1)
    q = select(BackupImage).where(BackupImage.tenant_id == host.tenant_id)
    q = q.where(BackupImage.hostname == agent_part[5:]) if agent_part.startswith("host:") else q.where(BackupImage.agent_id == agent_part)
    images = [i for i in db.execute(q.order_by(BackupImage.created_unix.desc())).scalars() if (i.vm_name or "") == vm]
    if not images:
        return None, "no backup of this machine yet"
    for i in images:
        if db.get(BackupRepoAccess, (i.repository_id, host.id)) is not None:
            return i, None
    return None, f"{host.display_name or host.hostname} has no access to the repository holding this machine's backups"


def advance_dr_run(db: Session, run: DrRun) -> None:
    """Start the current group's machines, collect their boot results, move on to the next group."""
    if run.state != "running":
        return
    items = [dict(i) for i in run.items or []]
    now = utcnow()
    current = [i for i in items if i["group"] == run.group]
    for it in current:
        if it["state"] == "pending":
            host = db.get(BackupAgent, it["hostAgentId"])
            caps = capabilities(host) if host is not None and not host.revoked else []
            if "boot_kvm" not in caps and "boot_hyperv" not in caps:
                it["state"], it["message"] = "failed", "the host cannot start VMs (QEMU on Linux, or Hyper-V)"
                continue
            im, why = _latest_image(db, it["key"], host)
            if im is None:
                it["state"], it["message"] = "failed", why
                continue
            job = queue(db, host, {"type": "boot_check", "image_id": im.image_id, "keep_running": True,
                                   "memory_mb": it.get("memoryMb"), "cpus": it.get("cpus"),
                                   "directory": it.get("directory") if "boot_hyperv" in caps else None},
                        im.repository_id, f"dr:{run.id}")
            it.update(state="starting", imageId=im.image_id, imageCreated=im.created_unix, jobId=job.id)
        elif it["state"] == "starting":
            job = db.get(BackupJob, it["jobId"])
            if job is None or job.state not in FINAL_STATES:
                continue
            check = db.execute(select(BackupBootCheck).where(BackupBootCheck.job_id == job.id)).scalars().first()
            outcome = check.outcome if check is not None else "failed"
            at = check.at if check is not None else job.finished_at or now
            it["upAt"], it["seconds"] = at.isoformat() + "Z", int((at - run.started_at).total_seconds())
            if outcome == "verified":
                it["state"], it["message"] = "up", (check.message if check else None)
            elif outcome == "screen":
                it["state"] = "warning"
                it["message"] = "started; its screen was captured but the guest did not confirm it is ready"
            else:
                it["state"] = "failed"
                it["message"] = (check.message if check else None) or job.error or "it did not start"
    if all(i["state"] not in ("pending", "starting") for i in current):
        failed = any(i["state"] == "failed" for i in current)
        last = max((i["group"] for i in items), default=-1)
        if failed or run.group >= last:
            for i in items:
                if i["state"] == "pending":
                    i["state"], i["message"] = "skipped", "an earlier group failed"
            run.state = "failed" if failed else ("warning" if any(i["state"] == "warning" for i in items) else "succeeded")
            run.finished_at = now
        else:
            run.group += 1
            run.items = items
            return advance_dr_run(db, run)  # start the next group now
    run.items = items


def stop_dr_vms(db: Session, run: DrRun, by: str) -> int:
    """Stop the VMs a run started (still running on their hosts)."""
    n = 0
    for it in run.items or []:
        host = db.get(BackupAgent, it.get("hostAgentId") or "")
        if host is None or not it.get("imageId"):
            continue
        for vm in (host.inventory or {}).get("running_vms") or []:
            if isinstance(vm, dict) and vm.get("image_id") == it["imageId"]:
                queue(db, host, {"type": "stop_vm", "session_id": vm.get("session_id")}, None, by)
                n += 1
    run.vms_stopped = True
    return n


def run_dr(db: Session) -> None:
    """Advance running DR runs; stop test VMs when their time is up; start scheduled tests."""
    now = utcnow()
    for run in db.execute(select(DrRun).where(DrRun.state == "running")).scalars().all():
        before = run.state
        advance_dr_run(db, run)
        if before == "running" and run.state != "running" and run.mode == "test" and run.state == "failed":
            rb = db.get(DrRunbook, run.runbook_id)
            raise_alert(db, run.tenant_id, None, RULE_DR, f"DR test failed: {rb.name if rb else run.runbook_id}", "high",
                        "A disaster-recovery test did not bring every machine up: " + "; ".join(
                            f"{i['name']}: {i['message']}" for i in run.items if i["state"] == "failed"),
                        link="/backups", dedupe_key=f"dr:{run.runbook_id}")
    for run in db.execute(select(DrRun).where(DrRun.mode == "test", DrRun.vms_stopped.is_(False),
                                              DrRun.state != "running")).scalars().all():
        if run.stop_after_minutes and run.finished_at and now - run.finished_at > timedelta(minutes=run.stop_after_minutes):
            stop_dr_vms(db, run, "dr-schedule")
    for rb in db.execute(select(DrRunbook).where(DrRunbook.test_every_days > 0)).scalars().all():
        last = db.execute(select(func.max(DrRun.started_at)).where(DrRun.runbook_id == rb.id)).scalar()
        active = db.execute(select(func.count()).select_from(DrRun).where(DrRun.runbook_id == rb.id,
                                                                          DrRun.state == "running")).scalar()
        if not active and (last is None or now - last > timedelta(days=rb.test_every_days)) and rb.groups:
            start_dr_run(db, rb, "test", "schedule")
    db.commit()


def tick(db: Session) -> None:
    """30-second scheduler: plans, boot verification, ended recovery sessions."""
    run_due_plans(db)
    run_boot_checks(db)
    expire_recovery_sessions(db)
    refresh_local_recovery(db)
    run_dr(db)
    purge_downloads()


# --------------------------------------------------------------------------
# Recovery media (Fenrir-Backup docs/design/phase-2.md)
# --------------------------------------------------------------------------

RECOVERY_ISO = "fenrir-recovery.iso"
RECOVERY_SETTINGS = "fenrir-recovery.json"
RECOVERY_MARKER = b"FENRIR-RECOVERY-CONFIG-V1\n"
RECOVERY_BLOCK = 4096
RECOVERY_SESSION_KEEP = timedelta(days=7)


def recovery_iso_path() -> Path:
    """The stock recovery ISO from the Fenrir-Backup build (recovery-env/build.sh)."""
    return agents_dir() / "recovery" / RECOVERY_ISO


def recovery_settings(server: str, pin: str, token: str, expires: datetime) -> dict:
    """Same fields and order as protocol::recovery::RecoveryConfig."""
    return {"server": server, "pin": pin, "token": token,
            "expires": int(expires.replace(tzinfo=timezone.utc).timestamp())}


def recovery_block(cfg: dict) -> bytes:
    """protocol::recovery::render: marker, compact JSON, newline, spaces to 4 KiB."""
    b = RECOVERY_MARKER + json.dumps(cfg, separators=(",", ":")).encode() + b"\n"
    if len(b) > RECOVERY_BLOCK:
        raise ValueError("recovery settings do not fit in 4 KiB")
    return b + b" " * (RECOVERY_BLOCK - len(b))


_ISO_BLOCKS: dict[Path, tuple[float, int, int | None]] = {}


def recovery_block_offset(path: Path) -> int | None:
    """Where the unconfigured placeholder block is in the ISO (on a 2048-byte sector), cached per file version."""
    st = path.stat()
    hit = _ISO_BLOCKS.get(path)
    if hit and hit[:2] == (st.st_mtime, st.st_size):
        return hit[2]
    placeholder = RECOVERY_MARKER + b" " * (RECOVERY_BLOCK - len(RECOVERY_MARKER))
    found, off, pending = None, 0, None
    with open(path, "rb") as f:
        while True:
            sector = f.read(2048)
            if len(sector) < 2048:
                break
            if pending is not None and pending[1] + sector == placeholder:
                found = pending[0]
                break
            pending = (off, sector) if sector.startswith(RECOVERY_MARKER) else None
            off += 2048
    _ISO_BLOCKS[path] = (st.st_mtime, st.st_size, found)
    return found


def personalised_iso(path: Path, offset: int, block: bytes, chunk: int = 1 << 20):
    """The ISO's bytes with the placeholder replaced by `block`."""
    with open(path, "rb") as f:
        pos = 0
        while True:
            data = f.read(chunk)
            if not data:
                return
            s, e = max(offset, pos), min(offset + len(block), pos + len(data))
            if s < e:
                data = data[:s - pos] + block[s - offset:e - offset] + data[e - pos:]
            yield data
            pos += len(data)


def expire_recovery_sessions(db: Session) -> int:
    """Recovery sessions (machines started from recovery media) not seen for a week are removed with their access."""
    cutoff = utcnow() - RECOVERY_SESSION_KEEP
    n = 0
    for a in db.execute(select(BackupAgent).where(BackupAgent.role == "recovery", BackupAgent.revoked.is_(False),
                                                  BackupAgent.last_seen_at < cutoff)).scalars().all():
        a.revoked = True
        for x in db.execute(select(BackupRepoAccess).where(BackupRepoAccess.agent_id == a.id)).scalars():
            db.delete(x)
        for j in db.execute(select(BackupJob).where(BackupJob.agent_id == a.id, BackupJob.state == "queued")).scalars():
            j.state, j.finished_at, j.error = "cancelled", utcnow(), "recovery session ended"
        record(db, "system", "backup.recovery_session.expired", a.hostname, a.tenant_id)
        n += 1
    db.commit()
    return n


BROWSE_KEEP = timedelta(days=1)
# While someone browses a machine's backups, it polls every second (agents older than this ask for at least 5).
FAST_POLL_SECONDS = 1
FAST_POLL_FOR = timedelta(minutes=3)


def poll_seconds(db: Session, agent: BackupAgent) -> int:
    """Every second while someone browses this machine's backups or waits for it to check a passphrase."""
    recent = db.execute(select(BackupJob.kind).where(
        BackupJob.agent_id == agent.id, BackupJob.created_at > utcnow() - FAST_POLL_FOR,
        BackupJob.kind["type"].as_string().in_(("browse_files", "list_images")))).scalars().all()
    fast = any(k.get("type") == "browse_files" or k.get("unlock") for k in recent if isinstance(k, dict))
    return FAST_POLL_SECONDS if fast else POLL_SECONDS


def purge_listings(db: Session) -> int:
    """Folder listings (file names) are kept a day, then dropped from the job record."""
    n = 0
    for j in db.execute(select(BackupJob).where(BackupJob.finished_at < utcnow() - BROWSE_KEEP,
                                                BackupJob.result.is_not(None))).scalars():
        if (j.kind or {}).get("type") == "browse_files":
            j.result = None
            n += 1
    db.commit()
    return n


def _serial(s: str | None) -> str:
    """A hardware serial number fit to identify a machine ('' for firmware placeholders)."""
    v = (s or "").strip().lower()
    junk = len(v) < 3 or any(x in v for x in ("o.e.m", "default", "not specified", "serial number", "none")) \
        or all(c in "0-. " for c in v)
    return "" if junk else v


def matching_device(db: Session, agent: BackupAgent) -> str | None:
    """The Fenrir device this backup agent runs on, within its tenant: the device with the same host name and, when
    both agents report it, the same hardware serial number; or, when host names are ambiguous or differ, the one
    device with that serial number."""
    name = (agent.hostname or "").split(".")[0].lower()
    serial = _serial((agent.inventory or {}).get("hardware_serial"))
    devices = [d for d in db.execute(select(Device).where(Device.tenant_id == agent.tenant_id)).scalars()
               if d.api_key_hash != f"retired-{d.id}"]
    by_name = [d for d in devices if name and (d.hostname or "").split(".")[0].lower() == name]
    if serial:
        both = [d for d in by_name if _serial(d.serial_number) == serial]
        if len(both) == 1:
            return both[0].id
        same = [d for d in devices if _serial(d.serial_number) == serial]
        if len(same) == 1:
            return same[0].id
        # A device reporting another serial under this name is a different machine.
        by_name = [d for d in by_name if not _serial(d.serial_number)]
    return by_name[0].id if len(by_name) == 1 else None


def link_devices(db: Session) -> int:
    """Link backup agents installed by the all-in-one installer to their device once the security agent enrols."""
    n = 0
    for a in db.execute(select(BackupAgent).where(BackupAgent.device_id.is_(None), BackupAgent.revoked.is_(False))).scalars():
        if (dev := matching_device(db, a)) is not None:
            a.device_id = dev
            n += 1
    db.commit()
    return n


def hourly(db: Session) -> None:
    link_devices(db)
    run_maintenance(db)
    check_health(db)
    purge_listings(db)


def record(db: Session, actor: str, action: str, target: str, tenant_id: str | None, **details) -> None:
    audit.record(db, actor, action, target, tenant_id=tenant_id, **details)
