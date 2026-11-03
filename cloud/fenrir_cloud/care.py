"""Looked-after phones: tracking level, carers, SOS, quiet/low-battery/location-off alerts, acknowledgement and
escalation.

A phone's ``care`` settings (set on its Location tab) say:

- ``tracking``: ``close`` (location every minute while moving, near a safe-zone edge or during an SOS; every 5 minutes
  when still), ``standard`` (every 5 minutes) or ``saver`` (every 15 minutes). The phone gets it in each heartbeat.
- ``carers``: the people (console users, typically with the ``carer`` role) notified of this phone's care alerts.
- ``quietMinutes``: alert when the phone has not checked in for this long (switched off, flat, no signal). 0 = off.
- ``lowBattery``: alert at or below this charge while not charging. 0 = off. Location turned off always alerts.
- ``escalateAfter`` / ``escalateTo``: if nobody acknowledges a care alert within this many minutes, notify these
  people too. 0 = off.
- ``emails``: also email these addresses (when email is set up).

SOS: the person presses Help in the phone app; Fenrir opens a critical alert with their location, notifies carers at
once and switches the phone to minute-by-minute tracking until a carer acknowledges or the person says they are OK.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, mailer, services, webpush
from .models import Alert, Device, utcnow

TRACKING = {"close": 60, "standard": 300, "saver": 900}
RULE_SOS = "android:sos"
RULE_QUIET = "android:quiet"
RULE_BATTERY = "android:battery"
RULE_LOCATION = "android:location-off"
CARE_RULES = (RULE_SOS, RULE_QUIET, RULE_BATTERY, RULE_LOCATION, "android:geofence")
OPEN = ("new", "triaged")
DEFAULTS = {"tracking": "standard", "carers": [], "quietMinutes": 0, "lowBattery": 0, "escalateAfter": 0, "escalateTo": [],
            "emails": []}


def settings(device: Device) -> dict:
    stored = device.care or {}
    return {**DEFAULTS, **{k: v for k, v in stored.items() if k in DEFAULTS}}


def sos_state(device: Device) -> dict:
    return dict((device.care or {}).get("sos") or {"active": False})


def validate(body: dict) -> dict:
    out = {}
    if "tracking" in body:
        if body["tracking"] not in TRACKING:
            raise ValueError("tracking must be close, standard or saver")
        out["tracking"] = body["tracking"]
    for key, low, high in (("quietMinutes", 0, 24 * 60), ("lowBattery", 0, 50), ("escalateAfter", 0, 24 * 60)):
        if key in body:
            value = body[key]
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError(f"{key} must be a whole number from {low} to {high}")
            if key == "quietMinutes" and 0 < value < 10:
                raise ValueError("quietMinutes must be at least 10 (or 0 for off)")
            out[key] = value
    for key in ("carers", "escalateTo"):
        if key in body:
            out[key] = [str(u)[:32] for u in body[key] or [] if str(u).strip()][:20]
    if "emails" in body:
        out["emails"] = [str(e).strip()[:200] for e in body["emails"] or [] if "@" in str(e)][:10]
    return out


def tracking_reply(device: Device) -> dict:
    """What the phone needs to pace its location reports."""
    sos = sos_state(device).get("active", False)
    if not sos and not device.care:  # not looked after: the phone's own pace (15 minutes, 5 with safe zones)
        return {"mode": "default", "intervalSeconds": 900, "adaptive": False, "sos": False}
    mode = "close" if sos else settings(device)["tracking"]
    return {"mode": mode, "intervalSeconds": TRACKING[mode], "adaptive": mode == "close" and not sos, "sos": sos}


def notify(db: Session, device: Device, users: list[str], title: str, body: str, tag: str, emails: list[str] | None = None) -> int:
    link = f"/care?device={device.id}"
    pushed = webpush.notify_users(db, users, title, body, link, tag=tag, tenant_id=device.tenant_id)
    if mailer.configured():
        for address in emails or []:
            mailer.send(address, f"[Fenrir] {title}", f"{body}\n\nOpen Fenrir's Care page to see where they are.")
    return pushed


def _open(db: Session, device: Device, rule: str) -> Alert | None:
    return db.execute(select(Alert).where(Alert.device_id == device.id, Alert.rule_id == rule, Alert.status.in_(OPEN))
                      .order_by(Alert.created_at.desc())).scalars().first()


def _raise(db: Session, device: Device, rule: str, severity: str, title: str, description: str, extra: dict | None = None) -> Alert | None:
    """Open one alert for this rule on this phone and notify its carers; nothing if one is already open."""
    if _open(db, device, rule) is not None:
        return None
    alert = Alert(tenant_id=device.tenant_id, device_id=device.id, rule_id=rule, severity=severity, mitre=[], event_ids=[],
                  title=title[:300], details={"category": "care", "source": "Care", "description": description[:2000], **(extra or {})})
    db.add(alert)
    db.flush()
    care = settings(device)
    notify(db, device, care["carers"], title, description, tag=f"{rule}-{device.id}", emails=care["emails"])
    services.fire_webhooks(db, device.tenant_id, f"care.{rule.split(':', 1)[1]}", {
        "title": title, "severity": severity, "device": device.hostname, "deviceId": device.id, "description": description})
    return alert


def _clear(db: Session, device: Device, rule: str, why: str) -> None:
    alert = _open(db, device, rule)
    if alert is not None:
        alert.status, alert.updated_at = "resolved", utcnow()
        alert.details = {**(alert.details or {}), "autoResolved": why}


# --------------------------------------------------------------------------- heartbeat and the minute job


def on_heartbeat(db: Session, device: Device, metrics: dict | None) -> None:
    """A phone checked in: it is no longer quiet; check battery and location services."""
    if device.platform != "android" or not device.care:
        return
    _clear(db, device, RULE_QUIET, "The phone checked in again.")
    if not isinstance(metrics, dict):
        return
    care = settings(device)
    battery, charging = metrics.get("batteryPercent"), bool(metrics.get("charging"))
    if care["lowBattery"] and isinstance(battery, (int, float)):
        if battery <= care["lowBattery"] and not charging:
            _raise(db, device, RULE_BATTERY, "medium", f"{device.hostname}'s battery is low ({int(battery)}%)",
                   f"{device.hostname} is at {int(battery)}% and not charging. When it runs out, its location stops.")
        elif charging or battery >= care["lowBattery"] + 5:
            _clear(db, device, RULE_BATTERY, "Charging, or charged again.")
    if metrics.get("locationEnabled") is False:
        _raise(db, device, RULE_LOCATION, "high", f"Location is turned off on {device.hostname}",
               f"{device.hostname} has location turned off, so where it is cannot be seen. Ask them to turn it back on.")
    elif metrics.get("locationEnabled") is True:
        _clear(db, device, RULE_LOCATION, "Location is on again.")


def tick(db: Session) -> None:
    """Every minute: phones gone quiet, and care alerts nobody has acknowledged."""
    now = utcnow()
    phones = db.execute(select(Device).where(Device.platform == "android", Device.care.is_not(None),
                                             Device.api_key_hash != ("retired-" + Device.id))).scalars().all()
    for device in phones:
        care = settings(device)
        seen = device.last_seen_at
        if care["quietMinutes"] and seen is not None and now - seen > timedelta(minutes=care["quietMinutes"]):
            minutes = int((now - seen).total_seconds() // 60)
            _raise(db, device, RULE_QUIET, "high", f"{device.hostname} has gone quiet",
                   f"{device.hostname} has not been in touch for {minutes} minutes: it may be switched off, out of battery "
                   f"or without signal. Its last location is on the Care page.")
        if care["escalateAfter"] and care["escalateTo"]:
            cutoff = now - timedelta(minutes=care["escalateAfter"])
            waiting = db.execute(select(Alert).where(Alert.device_id == device.id, Alert.rule_id.in_(CARE_RULES),
                                                     Alert.status == "new", Alert.acknowledged_by.is_(None),
                                                     Alert.created_at <= cutoff)).scalars().all()
            for alert in waiting:
                if (alert.details or {}).get("escalatedAt"):
                    continue
                alert.details = {**(alert.details or {}), "escalatedAt": now.isoformat() + "Z"}
                notify(db, device, care["escalateTo"], f"Nobody has responded: {alert.title}",
                       f"No one has acknowledged this for {care['escalateAfter']} minutes.", tag=f"escalate-{alert.id}")
                audit.record(db, "system:care", "care.escalated", alert.title, device.tenant_id, alert=alert.id)


# --------------------------------------------------------------------------- SOS and acknowledgement


def sos(db: Session, device: Device, point: dict | None) -> Alert | None:
    where = ""
    extra: dict = {}
    if point:
        maps = f"https://www.openstreetmap.org/?mlat={point['lat']:.6f}&mlon={point['lon']:.6f}#map=17/{point['lat']:.6f}/{point['lon']:.6f}"
        where = f" Location (±{int(point.get('accuracy') or 0)} m): {maps}"
        extra = {"latitude": point["lat"], "longitude": point["lon"], "accuracy": point.get("accuracy"), "mapUrl": maps}
    device.care = {**(device.care or {}), "sos": {"active": True, "since": utcnow().isoformat() + "Z"}}
    alert = _raise(db, device, RULE_SOS, "critical", f"{device.hostname} asked for help",
                   f"{device.hostname} pressed Help.{where} Their phone now shares its location every minute until someone "
                   f"acknowledges.", extra)
    audit.record(db, f"device:{device.hostname}", "care.sos", device.hostname, device.tenant_id)
    return alert


def sos_cancelled(db: Session, device: Device) -> None:
    """The person said they are OK."""
    device.care = {**(device.care or {}), "sos": {"active": False}}
    alert = _open(db, device, RULE_SOS)
    if alert is not None:
        alert.status, alert.updated_at = "resolved", utcnow()
        alert.details = {**(alert.details or {}), "autoResolved": "They said they are OK."}
        care = settings(device)
        notify(db, device, care["carers"], f"{device.hostname} is OK", "They cancelled their request for help.", tag=f"{RULE_SOS}-{device.id}")
    audit.record(db, f"device:{device.hostname}", "care.sos.cancelled", device.hostname, device.tenant_id)


def acknowledge(db: Session, device: Device, alert: Alert, actor: str, actor_id: str, resolve: bool = False) -> None:
    now = utcnow()
    alert.acknowledged_by, alert.acknowledged_at = alert.acknowledged_by or actor, alert.acknowledged_at or now
    alert.assignee = alert.assignee or actor
    alert.status, alert.updated_at = ("resolved" if resolve else "triaged"), now
    if alert.rule_id == RULE_SOS:
        device.care = {**(device.care or {}), "sos": {"active": False, "handledBy": actor, "handledAt": now.isoformat() + "Z"}}
    care = settings(device)
    others = [u for u in {*care["carers"], *care["escalateTo"]} if u != actor_id]
    notify(db, device, others, f"{actor} is handling it", alert.title, tag=f"ack-{alert.id}")
    audit.record(db, actor, "care.alert.resolved" if resolve else "care.alert.acknowledged", alert.title, device.tenant_id, alert=alert.id)
