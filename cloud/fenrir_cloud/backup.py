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
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit
from . import backup_installers as tpl
from .models import (Alert, Device, BackupAgent, BackupBootCheck, BackupImage, BackupJob, BackupRepoAccess, BackupRepository,
                     ImageBackupPlan, utcnow)

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

BACKUP_KINDS = ("backup_system", "backup_disks", "backup_hyperv")
KIND_LABELS = {
    "init_repository": "Create repository", "backup_system": "System backup", "backup_disks": "Disk backup",
    "backup_hyperv": "Hyper-V backup", "verify": "Verify", "list_images": "Refresh images",
    "apply_retention": "Apply retention", "prune": "Reclaim space", "restore": "Restore", "boot_check": "Boot check",
    "stop_vm": "Stop VM", "check_access": "Test connection", "browse_files": "Browse files",
    "restore_files": "Restore files",
}
# Capability the agent must report for console-created jobs of each kind.
KIND_CAPABILITY = {"backup_system": "backup_system", "backup_disks": "backup_disks", "backup_hyperv": "backup_hyperv",
                   "verify": "verify"}


def label(kind: dict | None) -> str:
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


def tick(db: Session) -> None:
    """30-second scheduler: plans, boot verification, ended recovery sessions."""
    run_due_plans(db)
    run_boot_checks(db)
    expire_recovery_sessions(db)


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
    recent = db.execute(select(BackupJob.id).where(
        BackupJob.agent_id == agent.id, BackupJob.created_at > utcnow() - FAST_POLL_FOR,
        BackupJob.kind["type"].as_string() == "browse_files")).first()
    return FAST_POLL_SECONDS if recent else POLL_SECONDS


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


def matching_device(db: Session, agent: BackupAgent) -> str | None:
    """The Fenrir device this backup agent runs on: the one device in its tenant with the same host name."""
    name = (agent.hostname or "").split(".")[0].lower()
    if not name:
        return None
    rows = [d for d in db.execute(select(Device).where(Device.tenant_id == agent.tenant_id)).scalars()
            if (d.hostname or "").split(".")[0].lower() == name and d.api_key_hash != f"retired-{d.id}"]
    return rows[0].id if len(rows) == 1 else None


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
