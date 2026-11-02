"""Is background work actually happening? Used by GET /health/background (for uptime monitors), the worker
container's healthcheck (``python -m fenrir_cloud.worker --check``), the platform status page, GET /metrics
(Prometheus) and the health watch, which tells the MSP's webhooks when the platform degrades and recovers.

The report names jobs and counts, never errors or customers: the endpoint needs no sign-in.
"""

from __future__ import annotations

import logging
import shutil
import threading
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import Settings
from .models import BackgroundJob, PlatformEvent, PlatformState, utcnow

log = logging.getLogger("fenrir.health")

SCHEDULER_STALE = timedelta(minutes=5)  # it passes every 30 seconds
MAINTENANCE_STALE = timedelta(hours=2, minutes=30)  # hourly
STUCK_AFTER = timedelta(minutes=30)
OUTBOX_LATE = timedelta(minutes=10)
FAILING_IN_A_ROW = 3
# The artifacts volume (evidence, forensic bundles, installers) is nearly full under 5% free, but never on a large disk
# with 10 GiB still free, and always under 1 GiB.
STORAGE_LOW_FRACTION = 0.05
STORAGE_PLENTY = 10 * 1024**3
STORAGE_MINIMUM = 1024**3


def _age(at: datetime | None, now: datetime) -> int | None:
    return int((now - at).total_seconds()) if at else None


def background_health(db: Session, settings: Settings) -> dict:
    now = utcnow()
    jobs = {job.name: job for job in db.execute(select(BackgroundJob)).scalars()}
    problems: list[str] = []
    checks: dict[str, dict] = {}

    def pass_check(name: str, stale: timedelta, enabled: bool) -> None:
        row = jobs.get(name)
        last = row.last_ok_at if row else None
        healthy = not enabled or (last is not None and now - last <= stale)
        checks[name] = {"ok": healthy, "enabled": enabled, "lastPassSecondsAgo": _age(last, now)}
        if not healthy:
            problems.append(f"{name} has not completed {'yet' if last is None else f'for {_age(last, now)} s'}")

    pass_check("scheduler.pass", SCHEDULER_STALE, settings.scheduler_enabled)
    pass_check("maintenance.pass", MAINTENANCE_STALE, True)

    stuck = sorted(name for name, row in jobs.items() if row.running_since and now - row.running_since > STUCK_AFTER)
    failing = sorted(name for name, row in jobs.items() if (row.failures or 0) >= FAILING_IN_A_ROW)
    checks["jobs"] = {"ok": not stuck, "stuck": stuck, "failingRepeatedly": failing}
    if stuck:
        problems.append("stuck: " + ", ".join(stuck))

    counts = dict(db.execute(select(PlatformEvent.status, func.count()).group_by(PlatformEvent.status)).all())
    oldest_due = db.execute(select(func.min(PlatformEvent.next_attempt_at))
                            .where(PlatformEvent.status == "pending")).scalar()
    late = oldest_due is not None and now - oldest_due > OUTBOX_LATE
    checks["outbox"] = {"ok": not late, "pending": counts.get("pending", 0), "dead": counts.get("dead", 0),
                        "oldestDueSecondsAgo": _age(oldest_due, now) if oldest_due and oldest_due < now else 0}
    if late:
        problems.append(f"event outbox is {_age(oldest_due, now)} s behind")

    storage = storage_usage(settings.artifact_dir)
    low = storage is not None and storage["totalBytes"] > 0 and storage["freeBytes"] < max(
        STORAGE_MINIMUM, min(storage["totalBytes"] * STORAGE_LOW_FRACTION, STORAGE_PLENTY))
    checks["storage"] = {"ok": not low, **(storage or {})}
    if low:
        problems.append(f"artifact storage is nearly full: {storage['freeBytes'] / 1024**3:.1f} GiB free "
                        f"({storage['freeBytes'] * 100 // storage['totalBytes']}%)")

    signing = code_signing_expiry()
    if signing is not None:
        days = (signing - now).days
        checks["codeSigning"] = {"ok": days >= CODE_SIGNING_WARN_DAYS, "expiresInDays": days}
        if days < 0:
            problems.append("the Windows code-signing certificate has expired: new installers and updates cannot be signed")
        elif days < CODE_SIGNING_WARN_DAYS:
            problems.append(f"the Windows code-signing certificate expires in {days} days")

    return {"ok": not problems, "role": settings.role, "problems": problems, "checks": checks,
            "checkedAt": now.isoformat(timespec="seconds") + "Z"}


CODE_SIGNING_WARN_DAYS = 30
CODE_SIGNING_CERT = Path(__file__).resolve().parents[1] / "downloads" / "windows" / "fenrir-codesign.cer"


def code_signing_expiry(path: Path | None = None) -> datetime | None:
    """When the Windows code-signing certificate the running build was signed with expires (UTC, naive), or None for
    an unsigned build. The image publishes its public half; the private key never reaches the server."""
    target = path or CODE_SIGNING_CERT
    try:
        data = target.read_bytes()
    except OSError:
        return None
    from cryptography import x509

    try:
        cert = x509.load_der_x509_certificate(data) if not data.lstrip().startswith(b"-----") else x509.load_pem_x509_certificate(data)
    except ValueError:
        return None
    return cert.not_valid_after_utc.replace(tzinfo=None)


def storage_usage(path) -> dict | None:
    """Free and total bytes of the filesystem holding ``path`` (or its nearest existing parent)."""
    try:
        target = Path(path)
        while not target.exists() and target != target.parent:
            target = target.parent
        usage = shutil.disk_usage(target)
    except (OSError, TypeError, ValueError):
        return None
    return {"freeBytes": usage.free, "totalBytes": usage.total}


# ---------------------------------------------------------------------------------------------------------------------
# Health watch: alert the MSP when background work degrades, and again when it recovers.

WATCH_LOCK = 726191904223
WATCH_INTERVAL = 60.0
WATCH_FIRST_DELAY = 120.0  # give a freshly started worker time to complete its first passes
ALERT_STATE_KEY = "health.alerted"


def problem_keys(report: dict) -> list[str]:
    """Stable names for what is wrong (the problem texts carry ages that change every check). Jobs failing
    repeatedly are included: background health stays up for them, but an MSP wants to know a sync keeps failing."""
    checks = report.get("checks", {})
    keys = [name for name in ("scheduler.pass", "maintenance.pass") if not checks.get(name, {}).get("ok", True)]
    jobs = checks.get("jobs", {})
    keys += [f"stuck:{name}" for name in jobs.get("stuck", [])]
    keys += [f"failing:{name}" for name in jobs.get("failingRepeatedly", [])]
    if not checks.get("outbox", {}).get("ok", True):
        keys.append("outbox")
    if not checks.get("storage", {}).get("ok", True):
        keys.append("storage")
    if not checks.get("codeSigning", {}).get("ok", True):
        keys.append("code-signing")
    return sorted(set(keys))


def _describe(report: dict, keys: list[str]) -> list[str]:
    lines = list(report.get("problems", []))
    lines += [f"{key.removeprefix('failing:')} has failed {FAILING_IN_A_ROW} or more times in a row"
              for key in keys if key.startswith("failing:")]
    return lines


def _send(db: Session, event: str, body: dict) -> int:
    """Deliver straight to the MSP's subscribed webhooks: the event outbox may be the thing that is broken. A delivery
    that fails is handed to the outbox, which retries it once background work is running again."""
    from . import services
    from .models import Tenant, Webhook

    msp = db.execute(select(Tenant).where(Tenant.kind == "msp").order_by(Tenant.created_at)).scalars().first()
    if msp is None:
        return 0
    hooks = db.execute(select(Webhook).where(Webhook.tenant_id == msp.id, Webhook.enabled.is_(True))).scalars().all()
    sent = 0
    for hook in hooks:
        if event not in (hook.events or []) and "*" not in (hook.events or []):
            continue
        try:
            services._post(hook.url, services._format_webhook(hook.kind, event, body), hook.secret)
            sent += 1
        except Exception as exc:  # noqa: BLE001 - queue it for the outbox to retry
            log.warning("health alert to webhook %s failed (%s); queued for retry", hook.id, exc)
            from . import events

            events.publish(db, "webhook.delivery", {"webhookId": hook.id, "event": event, "body": body}, msp.id)
    return sent


def watch_once(db: Session, settings: Settings) -> str | None:
    """One check. Sends platform.health.degraded when something new is wrong, platform.health.recovered when
    everything is fine again after an alert, and nothing otherwise. Returns the event sent, if any."""
    from . import audit

    report = background_health(db, settings)
    keys = problem_keys(report)
    row = db.get(PlatformState, ALERT_STATE_KEY)
    previous = list((row.value or {}).get("keys", [])) if row else []
    if keys == previous:
        return None
    new = [key for key in keys if key not in previous]
    event = None
    base = settings.public_base_url.rstrip("/")
    if new:
        event = "platform.health.degraded"
        body = {"title": "Fenrir platform degraded", "severity": "high", "problems": _describe(report, keys),
                "new": new, "url": f"{base}/settings", "checkedAt": report["checkedAt"]}
    elif not keys:
        event = "platform.health.recovered"
        body = {"title": "Fenrir platform recovered", "severity": "info", "problems": [], "resolved": previous,
                "url": f"{base}/settings", "checkedAt": report["checkedAt"]}
    if row is None:
        row = PlatformState(key=ALERT_STATE_KEY, value={})
        db.add(row)
    row.value, row.updated_at = {"keys": keys, "since": report["checkedAt"]}, utcnow()
    if event:
        audit.record(db, "system:health-watch", event, "platform", None, problems=keys if new else [], resolved=[] if new else previous)
        db.commit()  # remember the state before sending, so a slow webhook never causes a second alert
        if new:
            log.warning("platform degraded: %s", "; ".join(body["problems"]))
        else:
            log.info("platform recovered")
        _send(db, event, body)
    db.commit()
    return event


def watch_loop(settings: Settings, stop: threading.Event) -> None:
    """Runs in the web process (FENRIR_ROLE=web or all), so a worker that has died is still reported. With several web
    processes, a PostgreSQL advisory lock picks one to send."""
    from . import db as database
    from .main import _scheduler_lease

    delay = WATCH_FIRST_DELAY
    while not stop.wait(delay):
        delay = WATCH_INTERVAL
        try:
            with _scheduler_lease(WATCH_LOCK) as acquired:
                if not acquired:
                    continue
                with database.session_factory()() as db:
                    try:
                        watch_once(db, settings)
                    except Exception:
                        db.rollback()
                        raise
        except Exception as exc:  # noqa: BLE001 - keep watching
            log.warning("health watch failed: %s", exc)


# ---------------------------------------------------------------------------------------------------------------------
# Prometheus metrics (GET /metrics with FENRIR_METRICS_TOKEN). Counts and ages only: no customer names or errors.

def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def prometheus(db: Session, settings: Settings, version: str, schema: int | None, connected_agents: int) -> str:
    from .models import Device

    now = utcnow()
    report = background_health(db, settings)
    checks = report["checks"]
    out: list[str] = []

    def metric(name: str, kind: str, help_text: str, samples: list[tuple[dict, float | int]]) -> None:
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            rendered = ",".join(f'{k}="{_label(str(v))}"' for k, v in labels.items())
            out.append(f"{name}{{{rendered}}} {value}" if rendered else f"{name} {value}")

    metric("fenrir_build_info", "gauge", "Version of this server.", [({"version": version}, 1)])
    metric("fenrir_schema_version", "gauge", "Database schema version.", [({}, schema or 0)])
    metric("fenrir_background_ok", "gauge", "1 when /health/background would answer 200.", [({}, int(report["ok"]))])
    metric("fenrir_health_problems", "gauge", "Problems /health/background reports.", [({}, len(report["problems"]))])
    jobs = db.execute(select(BackgroundJob).order_by(BackgroundJob.name)).scalars().all()
    metric("fenrir_job_last_success_age_seconds", "gauge", "Seconds since each background job last succeeded.",
           [({"job": j.name}, int((now - j.last_ok_at).total_seconds())) for j in jobs if j.last_ok_at])
    metric("fenrir_job_consecutive_failures", "gauge", "Failures in a row for each background job.",
           [({"job": j.name}, j.failures or 0) for j in jobs])
    metric("fenrir_job_duration_seconds", "gauge", "Duration of each background job's last run.",
           [({"job": j.name}, round((j.duration_ms or 0) / 1000, 3)) for j in jobs])
    metric("fenrir_job_running", "gauge", "1 while a background job is running.",
           [({"job": j.name}, int(j.running_since is not None)) for j in jobs])
    outbox = checks["outbox"]
    metric("fenrir_outbox_events", "gauge", "Platform events by state.",
           [({"state": "pending"}, outbox["pending"]), ({"state": "dead"}, outbox["dead"])])
    metric("fenrir_outbox_oldest_due_seconds", "gauge", "How far behind the event outbox is.", [({}, outbox["oldestDueSecondsAgo"] or 0)])
    storage = checks.get("storage", {})
    if "freeBytes" in storage:
        metric("fenrir_artifact_storage_bytes", "gauge", "Artifact volume size.",
               [({"kind": "free"}, storage["freeBytes"]), ({"kind": "total"}, storage["totalBytes"])])
    total = db.execute(select(func.count()).select_from(Device)).scalar() or 0
    recent = db.execute(select(func.count()).select_from(Device)
                        .where(Device.last_seen_at >= now - timedelta(minutes=15))).scalar() or 0
    metric("fenrir_devices", "gauge", "Enrolled devices, and those seen in the last 15 minutes.",
           [({"state": "enrolled"}, total), ({"state": "seen_15m"}, recent)])
    metric("fenrir_agent_connections", "gauge", "Agents holding a live connection to this process.", [({}, connected_agents)])
    return "\n".join(out) + "\n"
