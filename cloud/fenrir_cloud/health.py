"""Is background work actually happening? Used by GET /health/background (for uptime monitors), the worker
container's healthcheck (``python -m fenrir_cloud.worker --check``) and the platform status page.

The report names jobs and counts, never errors or customers: the endpoint needs no sign-in.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import Settings
from .models import BackgroundJob, PlatformEvent, utcnow

SCHEDULER_STALE = timedelta(minutes=5)  # it passes every 30 seconds
MAINTENANCE_STALE = timedelta(hours=2, minutes=30)  # hourly
STUCK_AFTER = timedelta(minutes=30)
OUTBOX_LATE = timedelta(minutes=10)
FAILING_IN_A_ROW = 3


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

    return {"ok": not problems, "role": settings.role, "problems": problems, "checks": checks,
            "checkedAt": now.isoformat(timespec="seconds") + "Z"}
