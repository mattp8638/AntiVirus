"""Safe zones (geofences) for phones: alert when someone leaves or arrives somewhere, for example an older relative
leaving home at night or a child leaving school during the day.

Each zone is a circle on one phone with ``alert_on`` (exit, enter or both) and optional active days and hours in
the MSP's time zone. Every location fix the phone reports is checked here, oldest first. A zone's state changes
only when the fix is clearly on one side: inside means within the radius, outside means beyond the radius plus the
fix's uncertainty (capped), so GPS drift at the edge does not flap. Fixes less precise than ``MAX_ACCURACY_M`` are
ignored. On a change that should alert (in the active hours, at most once per ``COOLDOWN``) Fenrir:

- opens an alert on the phone (``android:geofence``); a "left" alert is resolved when the phone is back inside;
- pushes a notification to the console app of each chosen person, and emails the chosen addresses (when email is
  set up), with a map link;
- sends ``geofence.exited`` / ``geofence.entered`` to webhooks (Slack, Teams, ntfy, your own).

The phone is sent its zones in each heartbeat reply, reports location every 5 minutes while it has any, and asks
Android for proximity alerts so a crossing is reported straight away.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, mailer, regional, services, webpush
from .models import Alert, Device, Geofence, utcnow

RULE = "android:geofence"
MAX_ACCURACY_M = 500
EDGE_MARGIN_CAP_M = 150
COOLDOWN = timedelta(minutes=10)
MIN_RADIUS_M, MAX_RADIUS_M = 50, 50_000
MAX_PER_DEVICE = 20
ALERT_ON = {"exit", "enter", "both"}
SEVERITIES = {"low", "medium", "high", "critical"}


def distance_m(a: tuple[float, float], b: tuple[float, float]) -> float:
    from .routers.mobile import distance_m as great_circle

    return great_circle(a, b)


def _clock(value) -> str | None:
    text = str(value or "").strip()
    try:
        hours, minutes = text.split(":")
        if 0 <= int(hours) <= 23 and 0 <= int(minutes) <= 59:
            return f"{int(hours):02d}:{int(minutes):02d}"
    except ValueError:
        pass
    return None


def validate(body: dict, existing: Geofence | None = None) -> dict:
    """Clean a create/update body. Raises ValueError with a message for the person."""
    out: dict = {}
    if existing is None or "name" in body:
        name = " ".join(str(body.get("name") or "").split())[:120]
        if not name:
            raise ValueError("Give the safe zone a name, such as Home or School")
        out["name"] = name
    for key, low, high in (("latitude", -90, 90), ("longitude", -180, 180)):
        if existing is None or key in body:
            value = body.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
                raise ValueError(f"{key} must be a number between {low} and {high}")
            out[key] = float(value)
    if existing is None or "radius" in body:
        radius = body.get("radius", 200)
        if isinstance(radius, bool) or not isinstance(radius, (int, float)) or not MIN_RADIUS_M <= radius <= MAX_RADIUS_M:
            raise ValueError(f"radius must be between {MIN_RADIUS_M} m and {MAX_RADIUS_M // 1000} km")
        out["radius_m"] = float(radius)
    if existing is None or "alertOn" in body:
        alert_on = str(body.get("alertOn") or "exit")
        if alert_on not in ALERT_ON:
            raise ValueError("alertOn must be exit, enter or both")
        out["alert_on"] = alert_on
    if existing is None or "severity" in body:
        severity = str(body.get("severity") or "high")
        if severity not in SEVERITIES:
            raise ValueError("severity must be low, medium, high or critical")
        out["severity"] = severity
    if existing is None or "schedule" in body:
        schedule = body.get("schedule") or {}
        if not isinstance(schedule, dict):
            raise ValueError("schedule must be an object")
        if schedule:
            days = sorted({int(d) for d in schedule.get("days", range(7)) if isinstance(d, int) and 0 <= d <= 6})
            start, end = _clock(schedule.get("start")), _clock(schedule.get("end"))
            if not days or not start or not end:
                raise ValueError("schedule needs days (0 = Monday) and start and end times as HH:MM")
            schedule = {"days": days, "start": start, "end": end}
        out["schedule"] = schedule
    if existing is None or "notify" in body:
        notify = body.get("notify") or {}
        users = [str(u)[:32] for u in notify.get("users") or [] if str(u).strip()][:20]
        emails = [str(e).strip()[:200] for e in notify.get("emails") or [] if "@" in str(e)][:10]
        out["notify"] = {"users": users, "emails": emails, "phone": bool(notify.get("phone", False))}
    if "enabled" in body:
        out["enabled"] = bool(body["enabled"])
    return out


def view(fence: Geofence) -> dict:
    return {"id": fence.id, "deviceId": fence.device_id, "name": fence.name, "latitude": fence.latitude,
            "longitude": fence.longitude, "radius": fence.radius_m, "alertOn": fence.alert_on, "severity": fence.severity,
            "schedule": fence.schedule or {}, "notify": fence.notify or {"users": [], "emails": [], "phone": False},
            "enabled": fence.enabled, "state": fence.state, "stateAt": _iso(fence.state_at),
            "lastAlertAt": _iso(fence.last_alert_at), "createdBy": fence.created_by}


def for_phone(db: Session, device: Device) -> list[dict]:
    """What the phone needs: the circles, to ask Android for proximity alerts and to report crossings at once."""
    rows = db.execute(select(Geofence).where(Geofence.device_id == device.id, Geofence.enabled.is_(True))).scalars().all()
    return [{"id": f.id, "name": f.name, "lat": f.latitude, "lon": f.longitude, "radius": f.radius_m,
             "notifyPhone": bool((f.notify or {}).get("phone"))} for f in rows]


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def active(fence: Geofence, db: Session, at: datetime) -> bool:
    """Whether alerts are on at this UTC time (in the MSP's time zone). An overnight window (22:00-07:00) is fine."""
    schedule = fence.schedule or {}
    if not schedule:
        return True
    try:
        from zoneinfo import ZoneInfo

        zone = ZoneInfo(regional.get(db, fence.tenant_id).get("timeZone") or "UTC")
    except Exception:  # noqa: BLE001 - an unknown zone falls back to UTC rather than never alerting
        from zoneinfo import ZoneInfo

        zone = ZoneInfo("UTC")
    from datetime import timezone

    local = at.replace(tzinfo=timezone.utc).astimezone(zone)
    now = local.strftime("%H:%M")
    start, end = schedule["start"], schedule["end"]
    if start <= end:
        return local.weekday() in schedule["days"] and start <= now < end
    # Overnight: the evening belongs to today, the early hours to the day the window started.
    if now >= start:
        return local.weekday() in schedule["days"]
    return now < end and (local.weekday() - 1) % 7 in schedule["days"]


def check(db: Session, device: Device, points: list[dict]) -> list[dict]:
    """Check new fixes ({lat, lon, accuracy, at}) against the phone's zones. Returns the crossings that alerted."""
    fences = db.execute(select(Geofence).where(Geofence.device_id == device.id, Geofence.enabled.is_(True))).scalars().all()
    if not fences or not points:
        return []
    alerted = []
    for point in sorted(points, key=lambda p: p["at"]):
        accuracy = point.get("accuracy")
        if accuracy is not None and accuracy > MAX_ACCURACY_M:
            continue
        for fence in fences:
            if fence.state_at is not None and point["at"] <= fence.state_at:
                continue  # older than what we already know
            distance = distance_m((fence.latitude, fence.longitude), (point["lat"], point["lon"]))
            margin = min(accuracy or 0, EDGE_MARGIN_CAP_M)
            if distance <= fence.radius_m:
                now_state = "inside"
            elif distance > fence.radius_m + margin:
                now_state = "outside"
            else:
                continue  # on the edge: keep the current state
            previous = fence.state
            if previous == now_state:
                fence.state_at = point["at"]
                continue
            fence.state, fence.state_at = now_state, point["at"]
            if previous == "unknown":
                continue  # the first fix after creating a zone sets its state; it is not a crossing
            crossing = "exit" if now_state == "outside" else "enter"
            result = _crossed(db, device, fence, crossing, point)
            if result:
                alerted.append(result)
    return alerted


def _crossed(db: Session, device: Device, fence: Geofence, crossing: str, point: dict) -> dict | None:
    now = utcnow()
    at = point["at"]
    open_exit = db.execute(select(Alert).where(Alert.device_id == device.id, Alert.rule_id == RULE, Alert.status.in_(("new", "triaged")))
                           .order_by(Alert.created_at.desc())).scalars().all()
    open_exit = [a for a in open_exit if (a.details or {}).get("geofenceId") == fence.id and (a.details or {}).get("crossing") == "exit"]
    who = device.hostname
    when = at.strftime("%H:%M UTC")
    maps = f"https://www.openstreetmap.org/?mlat={point['lat']:.6f}&mlon={point['lon']:.6f}#map=16/{point['lat']:.6f}/{point['lon']:.6f}"
    link = f"/devices/{device.id}?tab=location"
    if crossing == "enter":
        for alert in open_exit:  # back inside: the "left" alert is over
            alert.status, alert.updated_at = "resolved", now
            alert.details = {**(alert.details or {}), "autoResolved": f"Back inside {fence.name} at {when}."}
    wanted = fence.alert_on in (crossing, "both")
    returning = crossing == "enter" and bool(open_exit)
    if not wanted and not returning:
        _event(db, device, fence, crossing, point, maps, alerted=False)
        return None
    if not active(fence, db, at) and not returning:
        _event(db, device, fence, crossing, point, maps, alerted=False)
        return None
    if fence.last_alert_at and now - fence.last_alert_at < COOLDOWN and not returning:
        return None
    fence.last_alert_at = now
    title = f"{who} left {fence.name}" if crossing == "exit" else (f"{who} is back at {fence.name}" if returning else f"{who} arrived at {fence.name}")
    text = f"{title} at {when}. Location: {maps}"
    if wanted and not (returning and fence.alert_on == "exit"):
        db.add(Alert(tenant_id=device.tenant_id, device_id=device.id, rule_id=RULE, severity=fence.severity, mitre=[], event_ids=[],
                     title=title[:300], details={"category": "location", "source": "Safe zone", "description": text[:2000],
                                                 "geofenceId": fence.id, "crossing": crossing, "latitude": point["lat"],
                                                 "longitude": point["lon"], "accuracy": point.get("accuracy"), "mapUrl": maps}))
    notify = fence.notify or {}
    pushed = webpush.notify_users(db, notify.get("users") or [], title, f"At {when}. Tap to see where.", link,
                                  tag=f"geofence-{fence.id}", tenant_id=device.tenant_id)
    emailed = 0
    if mailer.configured():
        for address in notify.get("emails") or []:
            mailer.send(address, f"[Fenrir] {title}", f"{text}\n\nOpen the phone's location in Fenrir to see its route.")
            emailed += 1
    _event(db, device, fence, crossing, point, maps, alerted=True, title=title)
    audit.record(db, "system:geofence", f"geofence.{'exited' if crossing == 'exit' else 'entered'}", fence.name, device.tenant_id,
                 device=device.hostname, pushed=pushed, emailed=emailed)
    return {"geofenceId": fence.id, "crossing": crossing, "title": title, "pushed": pushed, "emailed": emailed}


def _event(db: Session, device: Device, fence: Geofence, crossing: str, point: dict, maps: str, *, alerted: bool, title: str = "") -> None:
    name = "geofence.exited" if crossing == "exit" else "geofence.entered"
    body = {"title": title or f"{device.hostname} {'left' if crossing == 'exit' else 'arrived at'} {fence.name}",
            "severity": fence.severity, "device": device.hostname, "deviceId": device.id, "zone": fence.name,
            "zoneId": fence.id, "latitude": point["lat"], "longitude": point["lon"], "at": _iso(point["at"]), "url": maps,
            "alerted": alerted}
    if alerted:
        services.fire_webhooks(db, device.tenant_id, name, body)


def recipients(db: Session, tenant_id: str) -> list[dict]:
    """Staff and customer users who can see this customer: the people a zone can notify."""
    from .deps import tenant_subtree
    from .models import PushSubscription, User

    people = []
    for user in db.execute(select(User).where(User.active.is_(True), User.role.notin_(("client", "service")))).scalars().all():
        if user.role != "platform_admin":
            scope = tenant_subtree(db, user.tenant_id)
            if user.assigned_tenant_ids:
                scope = set().union(*(tenant_subtree(db, t) for t in user.assigned_tenant_ids if t in scope)) if scope else set()
            if tenant_id not in scope:
                continue
        devices = db.execute(select(PushSubscription.id).where(PushSubscription.user_id == user.id)).all()
        people.append({"id": user.id, "name": user.name or user.email, "email": user.email, "pushDevices": len(devices)})
    return sorted(people, key=lambda p: p["name"].lower())
