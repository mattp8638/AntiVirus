"""The Care page: looked-after phones with where they are, their safe zones and care alerts (SOS, left a zone, gone
quiet, low battery, location off). Used by staff and by family/carer accounts (role ``carer``, which can reach only
this page, push notifications and their own account)."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import care, geofence, services
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import Alert, Device, DeviceLocation, Geofence, Tenant, utcnow

router = APIRouter(prefix="/api/console/care", tags=["Care"])
ONLINE_AFTER = timedelta(minutes=3)


def _iso(value) -> str | None:
    return value.isoformat() + "Z" if value else None


def _phone(db: Session, principal: Principal, device_id: str) -> Device:
    principal.require("care")
    device = db.get(Device, device_id)
    if device is None or device.platform != "android":
        raise HTTPException(404, "Not found")
    principal.check_tenant(device.tenant_id)
    return device


def _point(row: DeviceLocation | None) -> dict | None:
    if row is None:
        return None
    return {"lat": row.latitude, "lon": row.longitude, "accuracy": row.accuracy_m, "battery": row.battery_percent,
            "reason": row.reason, "at": _iso(row.recorded_at)}


def _alert(a: Alert) -> dict:
    return {"id": a.id, "rule": a.rule_id, "title": a.title, "severity": a.severity, "status": a.status,
            "description": (a.details or {}).get("description", ""), "mapUrl": (a.details or {}).get("mapUrl"),
            "createdAt": _iso(a.created_at), "acknowledgedBy": a.acknowledged_by, "acknowledgedAt": _iso(a.acknowledged_at)}


def _person(db: Session, device: Device, names: dict, staff: bool) -> dict:
    now = utcnow()
    latest = db.execute(select(DeviceLocation).where(DeviceLocation.device_id == device.id)
                        .order_by(DeviceLocation.recorded_at.desc()).limit(1)).scalar_one_or_none()
    zones = db.execute(select(Geofence).where(Geofence.device_id == device.id).order_by(Geofence.created_at)).scalars().all()
    alerts = db.execute(select(Alert).where(Alert.device_id == device.id, Alert.rule_id.in_(care.CARE_RULES),
                                            Alert.status.in_(care.OPEN)).order_by(Alert.created_at.desc()).limit(20)).scalars().all()
    metrics = device.metrics or {}
    out = {"id": device.id, "name": device.hostname, "customer": names.get(device.tenant_id, ""),
           "online": bool(device.last_seen_at and now - device.last_seen_at < ONLINE_AFTER), "lastSeenAt": _iso(device.last_seen_at),
           "battery": metrics.get("batteryPercent"), "charging": metrics.get("charging"), "locationEnabled": metrics.get("locationEnabled"),
           "latest": _point(latest), "zones": [geofence.view(z) for z in zones], "alerts": [_alert(a) for a in alerts],
           "sos": care.sos_state(device), "tracking": care.settings(device)["tracking"], "cared": bool(device.care)}
    if staff:
        out["care"] = care.settings(device)
    return out


@router.get("/people")
def people(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Every phone this person may see, SOS and open alerts first."""
    principal.require("care")
    phones = db.execute(select(Device).where(Device.platform == "android", Device.tenant_id.in_(principal.tenant_ids),
                                             Device.api_key_hash != ("retired-" + Device.id))).scalars().all()
    if principal.user.role == "carer":  # family accounts see only phones someone set care up for
        phones = [d for d in phones if d.care]
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    rows = [_person(db, d, names, principal.can("read")) for d in phones]
    rows.sort(key=lambda p: (not p["sos"].get("active"), not p["alerts"], p["name"].lower()))
    return rows


@router.get("/people/{device_id}/locations")
def locations(device_id: str, hours: int = 24, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    device = _phone(db, principal, device_id)
    hours = max(1, min(hours, 24 * 30))
    rows = db.execute(select(DeviceLocation).where(DeviceLocation.device_id == device.id,
                                                   DeviceLocation.recorded_at >= utcnow() - timedelta(hours=hours))
                      .order_by(DeviceLocation.recorded_at).limit(2000)).scalars().all()
    return {"points": [_point(r) for r in rows], "hours": hours}


@router.post("/people/{device_id}/locate")
def locate(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Ask the phone for its location now."""
    device = _phone(db, principal, device_id)
    try:
        command = services.enqueue_command(db, device, "device.locate", principal.actor, payload={}, reason="Locate from the Care page")
    except services.CommandError as exc:
        raise HTTPException(409, str(exc)) from None
    db.commit()
    return {"commandId": command.id}


@router.post("/alerts/{alert_id}/ack")
def acknowledge(alert_id: str, body: dict = Body(default={}), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """"I've got this" (and, with resolve, "all sorted"). Acknowledging an SOS ends minute-by-minute tracking."""
    alert = db.get(Alert, alert_id)
    if alert is None or alert.rule_id not in care.CARE_RULES or not alert.device_id:
        raise HTTPException(404, "Not found")
    device = _phone(db, principal, alert.device_id)
    care.acknowledge(db, device, alert, principal.actor, principal.user.id, resolve=bool(body.get("resolve")))
    db.commit()
    return _alert(alert)
