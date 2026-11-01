"""Endpoint protection health: one view of whether every endpoint is protected, current and reporting.

Signals come from data the agents already send: heartbeat health state, agent version, policy
revision, scan and quarantine telemetry, and alerts. A device whose agent reports degraded or
unprotected health raises an alert; the alert resolves itself when the agent reports healthy again.
"""

from __future__ import annotations

import re
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit, presence
from .models import AgentRelease, Alert, Device, Event, utcnow

UNHEALTHY = {"degraded", "unprotected", "disabled", "error", "tampered"}
HEALTH_RULE = "fenrir.health.protection-degraded"
STALE_AFTER = timedelta(days=7)


def _version(value: str) -> tuple:
    return tuple(int(part) if part.isdigit() else 0 for part in re.split(r"[.\-+]", value or "0"))


def on_heartbeat(db: Session, device: Device, previous_state: str) -> None:
    """Raise or clear the protection-health alert when the reported state crosses healthy/unhealthy."""
    now_bad = (device.health_state or "").lower() in UNHEALTHY
    was_bad = (previous_state or "").lower() in UNHEALTHY
    open_alert = db.execute(select(Alert).where(Alert.device_id == device.id, Alert.rule_id == HEALTH_RULE,
                                                Alert.status.in_(("new", "triaged")))).scalars().first()
    if now_bad and open_alert is None:
        db.add(Alert(tenant_id=device.tenant_id, device_id=device.id, rule_id=HEALTH_RULE,
                     title=f"Endpoint protection {device.health_state} on {device.hostname}", severity="high",
                     mitre=["T1562.001"], event_ids=[],
                     details={"description": "The agent reports that protection is not fully working (for example a stopped "
                                             "component, failed hardening check or unreachable cloud). Check the device.",
                              "healthState": device.health_state, "source": "native"}))
        audit.record(db, f"device:{device.hostname}", "endpoint.protection_degraded", device.id, device.tenant_id,
                     state=device.health_state)
    elif not now_bad and was_bad and open_alert is not None:
        open_alert.status, open_alert.updated_at = "resolved", utcnow()
        open_alert.details = {**(open_alert.details or {}), "resolvedBy": "agent reported healthy"}


def summary(db: Session, tenant_ids: list[str]) -> dict:
    now = utcnow()
    devices = db.execute(select(Device).where(Device.tenant_id.in_(tenant_ids), Device.approved.is_(True))).scalars().all()
    ids = [d.id for d in devices]
    latest: dict[str, str] = {}
    for release in db.execute(select(AgentRelease)).scalars():
        if _version(release.version) > _version(latest.get(release.platform, "0")):
            latest[release.platform] = release.version
    since = now - timedelta(days=30)
    last_scan = dict(db.execute(select(Event.device_id, func.max(Event.occurred_at)).where(
        Event.device_id.in_(ids), Event.event_type.like("scan.%")).group_by(Event.device_id)).all()) if ids else {}
    quarantined = dict(db.execute(select(Event.device_id, func.count()).where(
        Event.device_id.in_(ids), Event.event_type.like("%quarantin%"), Event.occurred_at >= since).group_by(Event.device_id)).all()) if ids else {}
    detections = dict(db.execute(select(Alert.device_id, func.count()).where(
        Alert.device_id.in_(ids), Alert.created_at >= since, Alert.rule_id != HEALTH_RULE).group_by(Alert.device_id)).all()) if ids else {}
    rows = []
    for d in devices:
        online = presence.is_up(d, now)
        stale = not d.last_seen_at or d.last_seen_at < now - STALE_AFTER
        newest = latest.get(d.platform)
        outdated = bool(newest and d.agent_version and _version(d.agent_version) < _version(newest))
        unhealthy = (d.health_state or "").lower() in UNHEALTHY
        status = "unprotected" if unhealthy else "stale" if stale else "outdated" if outdated else "protected"
        scan_at = last_scan.get(d.id)
        rows.append({"deviceId": d.id, "hostname": d.hostname, "tenantId": d.tenant_id, "platform": d.platform,
                     "healthState": d.health_state, "online": online, "stale": stale, "agentVersion": d.agent_version,
                     "latestAgentVersion": newest, "outdated": outdated, "isolated": d.isolated, "status": status,
                     "lastSeenAt": d.last_seen_at.isoformat(timespec="seconds") + "Z" if d.last_seen_at else None,
                     "lastScanAt": scan_at.isoformat(timespec="seconds") + "Z" if scan_at else None,
                     "noRecentScan": not scan_at or scan_at < now - timedelta(days=7),
                     "quarantined30d": quarantined.get(d.id, 0), "detections30d": detections.get(d.id, 0)})
    totals = {key: sum(1 for r in rows if r["status"] == key) for key in ("protected", "outdated", "stale", "unprotected")}
    totals.update({"devices": len(rows), "online": sum(1 for r in rows if r["online"]),
                   "noRecentScan": sum(1 for r in rows if r["noRecentScan"]), "isolated": sum(1 for r in rows if r["isolated"])})
    order = {"unprotected": 0, "stale": 1, "outdated": 2, "protected": 3}
    rows.sort(key=lambda r: (order[r["status"]], r["hostname"].lower()))
    return {"totals": totals, "devices": rows}
