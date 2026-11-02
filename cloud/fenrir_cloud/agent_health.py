"""Agent health across the fleet: whether each agent is on the current build (and why not), and what it reported
failing recently (profile collection, updates, commands, protection components, monitors).

Agents already report their failures as telemetry (``*.failed``, ``*.error``, ``*.degraded`` ...). Before this view
those reports were stored but shown nowhere, so a broken component looked the same as a quiet one.
"""
from __future__ import annotations

import json
from datetime import timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from . import presence, rollouts
from .models import AgentRollout, Command, Device, Event, utcnow

FAILURE_SUFFIXES = ("failed", "error", "degraded", "rejected", "unavailable", "timeout", "refused", "stopped")
WINDOW = timedelta(days=7)
MAX_EVENTS = 20000


def _family(event_type: str) -> str:
    """'inventory.profile.failed' -> 'inventory.profile' (the component the outcome belongs to)."""
    return event_type.rsplit(".", 1)[0] if "." in event_type else event_type


def _is_failure(event_type: str) -> bool:
    return event_type.rsplit(".", 1)[-1] in FAILURE_SUFFIXES


def current_builds() -> dict[str, str]:
    """The agent build this server offers per platform ('' when it ships none or cannot tell)."""
    from . import deployment_installers
    from .routers.agent_api import _windows_build

    builds = {"windows": "", "linux": "", "macos": ""}
    try:
        windows = _windows_build()
        builds["windows"] = windows["buildId"] if windows else ""
    except Exception:  # noqa: BLE001 - a broken image manifest shows as "unknown", not as an error page
        pass
    meta_file = deployment_installers.release_file("linux-build.json")
    if meta_file is not None:
        try:
            build = str(json.loads(meta_file.read_text()).get("buildId") or "")
            builds["linux"] = builds["macos"] = build
        except (OSError, ValueError):
            pass
    return builds


def _error_text(event: Event) -> str:
    fields = event.fields or {}
    for key in ("error", "reason", "message", "detail"):
        value = fields.get(key)
        if value not in (None, ""):
            return str(value)[:500]
    return ""


def report(db: Session, tenant_ids: list[str]) -> dict:
    now = utcnow()
    since = now - WINDOW
    devices = [d for d in db.execute(select(Device).where(Device.tenant_id.in_(tenant_ids), Device.approved.is_(True))
                                     .order_by(Device.hostname)).scalars()
               if d.api_key_hash != f"retired-{d.id}"]
    ids = [d.id for d in devices]
    builds = current_builds()

    # Every failure-like report in the window, newest first, and every later report from the same component (a
    # later success means the problem cleared).
    events_by_device: dict[str, list[Event]] = {}
    if ids:
        rows = db.execute(select(Event).where(Event.device_id.in_(ids), Event.occurred_at >= since,
                                              or_(*[Event.event_type.like(f"%.{s}") for s in FAILURE_SUFFIXES]))
                          .order_by(Event.occurred_at.desc()).limit(MAX_EVENTS)).scalars().all()
        families = {_family(e.event_type) for e in rows}
        later = []
        if families:
            later = db.execute(select(Event.device_id, Event.event_type, Event.occurred_at)
                               .where(Event.device_id.in_(ids), Event.occurred_at >= since,
                                      or_(*[Event.event_type.like(f"{f}.%") for f in families]))
                               .limit(MAX_EVENTS)).all()
        cleared: dict[tuple[str, str], object] = {}
        for device_id, event_type, at in later:
            if not _is_failure(event_type):
                key = (device_id, _family(event_type))
                if key not in cleared or at > cleared[key]:
                    cleared[key] = at
        for event in rows:
            if not _is_failure(event.event_type):
                continue
            events_by_device.setdefault(event.device_id, []).append(event)
    else:
        cleared = {}

    failed_commands: dict[str, list[Command]] = {}
    if ids:
        for command in db.execute(select(Command).where(Command.device_id.in_(ids), Command.status == "failed",
                                                        Command.updated_at >= since)
                                  .order_by(Command.updated_at.desc()).limit(2000)).scalars():
            failed_commands.setdefault(command.device_id, []).append(command)

    rows_out, totals = [], {"devices": len(devices), "online": 0, "current": 0, "outdated": 0, "withProblems": 0}
    for device in devices:
        online = presence.is_up(device, now)
        current_build = builds.get(device.platform, "")
        on_current = bool(current_build) and device.agent_build == current_build
        update = "" if on_current or not current_build else rollouts.update_status(db, device, device.platform, current_build)
        problems: dict[str, dict] = {}
        for event in events_by_device.get(device.id, []):
            family = _family(event.event_type)
            entry = problems.get(family)
            if entry is None:
                cleared_at = cleared.get((device.id, family))
                problems[family] = {"component": family, "type": event.event_type, "summary": event.summary,
                                    "error": _error_text(event), "at": event.occurred_at.isoformat() + "Z", "count": 1,
                                    "resolved": bool(cleared_at and cleared_at > event.occurred_at)}
            else:
                entry["count"] += 1
        open_problems = [p for p in problems.values() if not p["resolved"]]
        commands = [{"id": c.id, "type": c.type, "at": (c.completed_at or c.updated_at).isoformat() + "Z",
                     "error": str((c.result or {}).get("error") or (c.result or {}).get("message") or c.reason or "")[:500]}
                    for c in failed_commands.get(device.id, [])[:10]]
        totals["online"] += online
        totals["current"] += on_current
        totals["outdated"] += bool(current_build) and not on_current
        totals["withProblems"] += bool(open_problems)
        rows_out.append({"deviceId": device.id, "tenantId": device.tenant_id, "hostname": device.hostname, "platform": device.platform,
                         "online": online, "lastSeenAt": device.last_seen_at.isoformat() + "Z" if device.last_seen_at else None,
                         "agentVersion": device.agent_version or None, "agentBuild": device.agent_build or None,
                         "currentBuild": current_build or None, "onCurrentBuild": on_current if current_build else None,
                         "update": update, "problems": sorted(problems.values(), key=lambda p: (p["resolved"], p["at"]), reverse=False),
                         "openProblems": len(open_problems), "failedCommands": commands})
    # Open problems first, newest first within each device.
    for row in rows_out:
        row["problems"].sort(key=lambda p: p["at"], reverse=True)
        row["problems"].sort(key=lambda p: p["resolved"])
    stalled = [{"id": r.id, "platform": r.platform, "build": r.build, "version": r.version, "state": r.state, "reason": r.reason}
               for r in db.execute(select(AgentRollout).where(AgentRollout.state.in_(("paused", "stopped")))).scalars()]
    return {"builds": builds, "totals": totals, "stalledRollouts": stalled, "devices": rows_out}
