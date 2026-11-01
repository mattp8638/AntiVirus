"""Service health (CORE-08): heartbeats from the background components, queue and feed freshness, storage, and an
alert (outbox event, delivered to webhooks) whenever a component degrades or recovers. A stopped scanner or a stale
feed shows as degraded instead of silently leaving coverage green."""
from __future__ import annotations

import shutil
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import PlatformEvent, ServiceHeartbeat, utcnow

# component -> how old its last success may be before it counts as stale
EXPECTED = {
    "scheduler": timedelta(minutes=5),          # every 30 s
    "maintenance": timedelta(hours=3),          # hourly
    "vuln-intel": timedelta(hours=1),           # every 15 min
    "signature-feed": timedelta(hours=3),       # hourly when enabled
}
OUTBOX_STALE = timedelta(minutes=15)
DISK_LOW_FRACTION = 0.10


def beat(db: Session, name: str, ok: bool = True, error: str = "", **detail) -> None:
    """Record a run. Commits on its own so a later failure in the caller does not lose it."""
    row = db.get(ServiceHeartbeat, name)
    if row is None:
        row = ServiceHeartbeat(name=name, detail={})
        db.add(row)
    now = utcnow()
    if ok:
        row.last_ok_at, row.detail = now, detail
    else:
        row.last_error_at, row.last_error = now, error[:500]
    db.commit()


def report(db: Session, enabled: dict[str, bool] | None = None, artifact_dir=None, now: datetime | None = None) -> dict:
    now = now or utcnow()
    enabled = enabled or {}
    components = []
    rows = {r.name: r for r in db.execute(select(ServiceHeartbeat)).scalars()}
    for name, limit in EXPECTED.items():
        if enabled.get(name) is False:
            components.append({"name": name, "status": "disabled"})
            continue
        row = rows.get(name)
        last = row.last_ok_at if row else None
        if last is None:
            status, reason = "missing", "has not run yet"
        elif now - last > limit:
            status, reason = "stale", f"last succeeded {int((now - last).total_seconds() // 60)} minutes ago"
        else:
            status, reason = "ok", ""
        if row and row.last_error_at and (last is None or row.last_error_at > last):
            status, reason = ("failing" if status == "ok" else status), f"last error: {row.last_error}"
        components.append({"name": name, "status": status, "reason": reason, "lastOkAt": last.isoformat() + "Z" if last else None,
                           "detail": row.detail if row else {}})
    pending = db.execute(select(func.count(), func.min(PlatformEvent.created_at)).where(PlatformEvent.status == "pending")).one()
    dead = db.execute(select(func.count()).where(PlatformEvent.status == "dead")).scalar() or 0
    oldest = pending[1]
    queue = {"pending": pending[0] or 0, "dead": dead, "oldestPendingAt": oldest.isoformat() + "Z" if oldest else None,
             "status": "stale" if oldest and now - oldest > OUTBOX_STALE else ("failing" if dead else "ok")}
    storage = None
    if artifact_dir is not None:
        try:
            usage = shutil.disk_usage(artifact_dir)
            storage = {"freeBytes": usage.free, "totalBytes": usage.total,
                       "status": "low" if usage.total and usage.free / usage.total < DISK_LOW_FRACTION else "ok"}
        except OSError:
            storage = {"status": "unknown"}
    from . import exposure

    kev_at = exposure._KEV_CACHE[0] if getattr(exposure, "_KEV_CACHE", None) else 0
    feeds = {"kev": {"ageMinutes": int((now.timestamp() - kev_at) // 60) if kev_at else None}}
    degraded = [c["name"] for c in components if c["status"] not in ("ok", "disabled")]
    if queue["status"] != "ok":
        degraded.append("event-queue")
    if storage and storage["status"] == "low":
        degraded.append("storage")
    return {"status": "degraded" if degraded else "ok", "degraded": degraded, "components": components, "queue": queue,
            "storage": storage, "feeds": feeds, "checkedAt": now.isoformat() + "Z"}


def alert_on_change(db: Session, current: dict) -> list[str]:
    """Publish platform.health.degraded / .recovered once per change of a component's state."""
    from . import events

    changed = []
    for component in current["components"]:
        if component["status"] == "disabled":
            continue
        state = "ok" if component["status"] == "ok" else "degraded"
        row = db.get(ServiceHeartbeat, component["name"])
        if row is None:
            row = ServiceHeartbeat(name=component["name"], detail={}, alerted_state="ok")
            db.add(row)
        if row.alerted_state != state:
            row.alerted_state = state
            events.publish(db, f"platform.health.{'degraded' if state == 'degraded' else 'recovered'}",
                           {"component": component["name"], "status": component["status"], "reason": component.get("reason", "")})
            changed.append(component["name"])
    return changed


def prometheus(current: dict) -> str:
    lines = ["# HELP fenrir_component_up 1 when the background component ran recently", "# TYPE fenrir_component_up gauge"]
    for c in current["components"]:
        if c["status"] != "disabled":
            lines.append(f'fenrir_component_up{{component="{c["name"]}"}} {1 if c["status"] == "ok" else 0}')
    lines += ["# TYPE fenrir_outbox_pending gauge", f"fenrir_outbox_pending {current['queue']['pending']}",
              "# TYPE fenrir_outbox_dead gauge", f"fenrir_outbox_dead {current['queue']['dead']}",
              "# TYPE fenrir_degraded gauge", f"fenrir_degraded {1 if current['status'] == 'degraded' else 0}"]
    if current.get("storage") and "freeBytes" in current["storage"]:
        lines += ["# TYPE fenrir_artifact_free_bytes gauge", f"fenrir_artifact_free_bytes {current['storage']['freeBytes']}"]
    return "\n".join(lines) + "\n"
