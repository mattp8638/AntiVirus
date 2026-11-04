"""Phones: location history, lost mode and the anti-theft actions (locate, lock, alarm, erase).

The Android agent posts location fixes; the console shows them on the device's Location tab and turns lost mode
on and off. Lost mode is stored on the device and echoed in every heartbeat reply, so the phone converges even if
it missed the command.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .. import audit, ratelimit, services
from ..db import get_db
from ..deps import Principal, current_device, current_principal
from ..models import Device, DeviceLocation, Geofence, utcnow

agent = APIRouter(prefix="/api/v1/devices/{device_id}", tags=["Mobile agent"])
console = APIRouter(prefix="/api/console/devices/{device_id}", tags=["Mobile"])

RETENTION = timedelta(days=90)
MAX_POINTS_PER_REPORT = 200
SOURCES = {"gps", "network", "fused", "passive", "wifi"}
REASONS = {"periodic", "locate", "lostmode", "boot", "sim", "moved", "geofence", "sos", "tracking"}


def _parse_time(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is None else parsed.astimezone(timezone.utc).replace(tzinfo=None)


def _num(value, low: float, high: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or math.isnan(value) or not low <= value <= high:
        return None
    return float(value)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def _point(row: DeviceLocation) -> dict:
    return {"lat": row.latitude, "lon": row.longitude, "accuracy": row.accuracy_m, "altitude": row.altitude_m,
            "speed": row.speed_mps, "source": row.source, "reason": row.reason, "battery": row.battery_percent,
            "at": _iso(row.recorded_at)}


def distance_m(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Great-circle distance in metres."""
    lat1, lon1, lat2, lon2 = map(math.radians, (*a, *b))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * 6371000 * math.asin(math.sqrt(h))


@agent.post("/location")
def report_location(device_id: str, body: dict = Body(...), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    """Agent: one or more fixes, oldest first: {"points": [{"lat", "lon", "accuracy", "altitude", "speed", "source",
    "reason", "battery", "at"}]}. Invalid points are skipped rather than failing the batch."""
    if device.id != device_id:
        raise HTTPException(403, "Wrong device")
    ratelimit.check(f"location:{device.id}", 120, 3600)
    points = body.get("points")
    if not isinstance(points, list) or not points:
        raise HTTPException(422, "points must be a non-empty list")
    now = utcnow()
    stored = 0
    accepted: list[dict] = []
    for raw in points[:MAX_POINTS_PER_REPORT]:
        if not isinstance(raw, dict):
            continue
        lat, lon = _num(raw.get("lat"), -90, 90), _num(raw.get("lon"), -180, 180)
        if lat is None or lon is None or (lat == 0 and lon == 0):
            continue
        at = _parse_time(raw.get("at")) or now
        if at > now + timedelta(minutes=5) or at < now - RETENTION:
            continue
        battery = _num(raw.get("battery"), 0, 100)
        source = str(raw.get("source") or "fused").lower()
        reason = str(raw.get("reason") or "periodic").lower()
        db.add(DeviceLocation(tenant_id=device.tenant_id, device_id=device.id, latitude=lat, longitude=lon,
                              accuracy_m=_num(raw.get("accuracy"), 0, 1e6), altitude_m=_num(raw.get("altitude"), -1000, 1e5),
                              speed_mps=_num(raw.get("speed"), 0, 1000), source=source if source in SOURCES else "fused",
                              reason=reason if reason in REASONS else "periodic",
                              battery_percent=int(battery) if battery is not None else None, recorded_at=at))
        stored += 1
        accepted.append({"lat": lat, "lon": lon, "accuracy": _num(raw.get("accuracy"), 0, 1e6), "at": at})
    from .. import geofence

    crossings = geofence.check(db, device, accepted)
    db.execute(delete(DeviceLocation).where(DeviceLocation.device_id == device.id, DeviceLocation.recorded_at < now - RETENTION))
    db.commit()
    return {"stored": stored, "crossings": [{"geofenceId": c["geofenceId"], "crossing": c["crossing"]} for c in crossings]}


@console.get("/locations")
def locations(device_id: str, hours: int = 24, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    device = _device(db, principal, device_id)
    hours = max(1, min(hours, 24 * 90))
    since = utcnow() - timedelta(hours=hours)
    rows = db.execute(select(DeviceLocation).where(DeviceLocation.device_id == device.id, DeviceLocation.recorded_at >= since)
                      .order_by(DeviceLocation.recorded_at.desc()).limit(2000)).scalars().all()
    latest = rows[0] if rows else db.execute(select(DeviceLocation).where(DeviceLocation.device_id == device.id)
                                             .order_by(DeviceLocation.recorded_at.desc()).limit(1)).scalar_one_or_none()
    travelled = sum(distance_m((a.latitude, a.longitude), (b.latitude, b.longitude)) for a, b in zip(rows, rows[1:]))
    return {"latest": _point(latest) if latest else None, "points": [_point(r) for r in reversed(rows)],
            "hours": hours, "travelledMeters": round(travelled), "lostMode": _lost_view(device)}


def _lost_view(device: Device) -> dict:
    lost = device.lost_mode or {}
    return {"enabled": bool(lost.get("enabled")), "message": lost.get("message", ""), "phone": lost.get("phone", ""),
            "since": lost.get("since"), "by": lost.get("by")}


def _device(db: Session, principal: Principal, device_id: str) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(device.tenant_id)
    return device


@console.post("/lost-mode")
def set_lost_mode(device_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Turn lost mode on (lock, show a message and number, report location every 5 minutes) or off."""
    principal.require("respond")
    device = _device(db, principal, device_id)
    if device.platform != "android":
        raise HTTPException(400, "Lost mode is for phones running the Fenrir Android agent")
    enabled = bool(body.get("enabled"))
    message = " ".join(str(body.get("message") or "").split())[:300]
    phone = " ".join(str(body.get("phone") or "").split())[:40]
    if enabled and not message:
        message = "This phone has been reported lost. Please contact the owner."
    previous = device.lost_mode or {}
    since = None
    if enabled:
        since = previous.get("since") if previous.get("enabled") else None
        since = since or _iso(utcnow())
    device.lost_mode = {"enabled": enabled, "message": message if enabled else "", "phone": phone if enabled else "",
                        "since": since, "by": principal.actor}
    try:
        command = services.enqueue_command(db, device, "device.lostmode", principal.actor,
                                           payload={"enabled": enabled, "message": device.lost_mode["message"], "phone": device.lost_mode["phone"]},
                                           reason="Lost mode on" if enabled else "Lost mode off")
    except services.CommandError as exc:
        raise HTTPException(409, str(exc)) from None
    audit.record(db, principal.actor, "device.lostmode.enabled" if enabled else "device.lostmode.disabled", device.hostname, device.tenant_id)
    db.commit()
    return {"lostMode": _lost_view(device), "commandId": command.id}


@agent.post("/sos")
def sos(device_id: str, body: dict = Body(default={}), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    """The person pressed Help ({lat, lon, accuracy, at} when the phone has a fix), or said they are OK ({cancel: true})."""
    from .. import care

    if device.id != device_id:
        raise HTTPException(403, "Wrong device")
    ratelimit.check(f"sos:{device.id}", 20, 3600)
    if body.get("cancel"):
        care.sos_cancelled(db, device)
        db.commit()
        return {"sos": False}
    point = None
    lat, lon = _num(body.get("lat"), -90, 90), _num(body.get("lon"), -180, 180)
    if lat is not None and lon is not None and not (lat == 0 and lon == 0):
        at = _parse_time(body.get("at")) or utcnow()
        point = {"lat": lat, "lon": lon, "accuracy": _num(body.get("accuracy"), 0, 1e6), "at": at}
        db.add(DeviceLocation(tenant_id=device.tenant_id, device_id=device.id, latitude=lat, longitude=lon, accuracy_m=point["accuracy"],
                              source="fused", reason="sos", recorded_at=at))
    alert = care.sos(db, device, point)
    db.commit()
    return {"sos": True, "alertId": alert.id if alert else None}


@console.get("/care")
def get_care(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    from .. import care, geofence

    principal.require("read")
    device = _device(db, principal, device_id)
    return {"care": care.settings(device), "enabled": bool(device.care), "sos": care.sos_state(device),
            "recipients": geofence.recipients(db, device.tenant_id)}


@console.put("/care")
def set_care(device_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Turn care on (or change it) for a phone; {"enabled": false} turns it off."""
    from .. import care

    principal.require("respond")
    device = _phone(db, principal, device_id)
    if body.get("enabled") is False:
        device.care = None
        audit.record(db, principal.actor, "care.disabled", device.hostname, device.tenant_id)
        db.commit()
        return {"enabled": False}
    try:
        fields = care.validate(body)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    for key in ("carers", "escalateTo"):
        if key in fields:
            _check_recipients(db, device, {"users": fields[key]})
    device.care = {**care.settings(device), **fields, "sos": care.sos_state(device)}
    audit.record(db, principal.actor, "care.updated", device.hostname, device.tenant_id, fields=sorted(fields))
    db.commit()
    return {"care": care.settings(device), "enabled": True}


# --------------------------------------------------------------------------- safe zones (geofences)


def _phone(db: Session, principal: Principal, device_id: str) -> Device:
    device = _device(db, principal, device_id)
    if device.platform != "android":
        raise HTTPException(400, "Safe zones are for phones running the Fenrir Android agent")
    return device


def _fence(db: Session, device: Device, fence_id: str) -> Geofence:
    fence = db.get(Geofence, fence_id)
    if fence is None or fence.device_id != device.id:
        raise HTTPException(404, "Not found")
    return fence


def _check_recipients(db: Session, device: Device, notify: dict) -> None:
    from .. import geofence

    allowed = {p["id"] for p in geofence.recipients(db, device.tenant_id)}
    unknown = [u for u in notify.get("users") or [] if u not in allowed]
    if unknown:
        raise HTTPException(400, "Some of the people chosen cannot see this customer")


@console.get("/geofences")
def list_geofences(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    from .. import geofence, mailer

    principal.require("read")
    device = _device(db, principal, device_id)
    rows = db.execute(select(Geofence).where(Geofence.device_id == device.id).order_by(Geofence.created_at)).scalars().all()
    return {"geofences": [geofence.view(f) for f in rows], "recipients": geofence.recipients(db, device.tenant_id),
            "emailConfigured": mailer.configured()}


@console.post("/geofences")
def create_geofence(device_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    from .. import geofence

    principal.require("respond")
    device = _phone(db, principal, device_id)
    count = db.execute(select(Geofence.id).where(Geofence.device_id == device.id)).all()
    if len(count) >= geofence.MAX_PER_DEVICE:
        raise HTTPException(409, f"A phone can have up to {geofence.MAX_PER_DEVICE} safe zones")
    try:
        fields = geofence.validate(body)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    _check_recipients(db, device, fields["notify"])
    fence = Geofence(tenant_id=device.tenant_id, device_id=device.id, created_by=principal.actor, **fields)
    db.add(fence)
    audit.record(db, principal.actor, "geofence.created", fence.name, device.tenant_id, device=device.hostname, radius=fence.radius_m)
    db.commit()
    return geofence.view(fence)


@console.patch("/geofences/{fence_id}")
def update_geofence(device_id: str, fence_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                    db: Session = Depends(get_db)):
    from .. import geofence

    principal.require("respond")
    device = _phone(db, principal, device_id)
    fence = _fence(db, device, fence_id)
    try:
        fields = geofence.validate(body, existing=fence)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    if "notify" in fields:
        _check_recipients(db, device, fields["notify"])
    moved = any(k in fields for k in ("latitude", "longitude", "radius_m"))
    for key, value in fields.items():
        setattr(fence, key, value)
    if moved:  # the next fix sets the state again rather than counting as a crossing
        fence.state, fence.state_at = "unknown", None
    fence.updated_at = utcnow()
    audit.record(db, principal.actor, "geofence.updated", fence.name, device.tenant_id, device=device.hostname, fields=sorted(fields))
    db.commit()
    return geofence.view(fence)


@console.delete("/geofences/{fence_id}")
def delete_geofence(device_id: str, fence_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    device = _phone(db, principal, device_id)
    fence = _fence(db, device, fence_id)
    db.delete(fence)
    audit.record(db, principal.actor, "geofence.deleted", fence.name, device.tenant_id, device=device.hostname)
    db.commit()
    return {"ok": True}
