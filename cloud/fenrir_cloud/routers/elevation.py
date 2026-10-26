"""Temporary local admin rights on request (privilege.elevationRequests, Windows).

A signed-in user asks from the agent window. The policy decides: "off" refuses, "auto-approve" grants straight
away, "approval" waits for a technician in the console. A grant queues elevation.grant; the agent adds the user
to the local Administrators group for privilege.elevationMinutes and removes them afterwards.
"""
from __future__ import annotations

import re
from datetime import timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, ratelimit, services
from ..db import get_db
from ..deps import Principal, current_device, current_principal
from ..models import Command, Device, ElevationRequest, utcnow

agent = APIRouter(prefix="/api/v1/devices/{device_id}/elevation-requests", tags=["Agent"])
console = APIRouter(prefix="/api/console/elevation-requests", tags=["Devices"])

_SID = re.compile(r"S-1-(5-21|12-1)(-\d{1,10}){3,8}")


def _privilege(db: Session, device: Device) -> dict:
    resolution, _ = services.effective_policy(db, device)
    return resolution["settings"].get("privilege", {})


def _view(row: ElevationRequest, device: Device | None) -> dict:
    status = row.status
    expires = row.granted_at + timedelta(minutes=row.minutes) if row.granted_at else None
    if status == "granted" and expires and expires < utcnow():
        status = "expired"
    return {"id": row.id, "deviceId": row.device_id, "hostname": device.hostname if device else "", "user": row.user,
            "reason": row.reason, "minutes": row.minutes, "status": status, "decidedBy": row.decided_by,
            "note": row.note, "createdAt": row.created_at.isoformat() + "Z",
            "decidedAt": row.decided_at.isoformat() + "Z" if row.decided_at else None,
            "expiresAt": expires.isoformat() + "Z" if expires else None}


def _grant(db: Session, device: Device, row: ElevationRequest, actor: str) -> None:
    command = services.enqueue_command(db, device, "elevation.grant", actor, reason=f"Elevation for {row.user}",
                                       payload={"requestId": row.id, "userSid": row.user_sid, "user": row.user,
                                                "minutes": row.minutes})
    row.status, row.command_id = "approved", command.id
    row.decided_by, row.decided_at = actor, utcnow()


@agent.post("")
def request_elevation(body: dict = Body(...), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    user = str(body.get("user") or "")[:200]
    sid = str(body.get("userSid") or "")
    reason = str(body.get("reason") or "").strip()[:1000]
    if not user or not _SID.fullmatch(sid):
        raise HTTPException(422, "A signed-in local or domain user is required")
    if (device.platform or "windows").lower() != "windows":
        raise HTTPException(422, "Elevation requests are available on Windows")
    privilege = _privilege(db, device)
    mode = privilege.get("elevationRequests", "approval") if privilege.get("enabled") else "off"
    if mode == "off":
        raise HTTPException(403, "Admin access requests are turned off for this device")
    ratelimit.check(f"elevation:{device.id}", 6, 3600)
    open_request = db.execute(select(ElevationRequest).where(
        ElevationRequest.device_id == device.id, ElevationRequest.user_sid == sid,
        ElevationRequest.status.in_(("pending", "approved")))).scalars().first()
    if open_request is not None:
        return {"id": open_request.id, "status": open_request.status, "minutes": open_request.minutes}
    minutes = max(5, min(480, int(privilege.get("elevationMinutes", 30) or 30)))
    row = ElevationRequest(tenant_id=device.tenant_id, device_id=device.id, user=user, user_sid=sid, reason=reason,
                           minutes=minutes)
    db.add(row)
    db.flush()
    if mode == "auto-approve":
        _grant(db, device, row, "policy:auto-approve")
    else:
        services.fire_webhooks(db, device.tenant_id, "elevation.requested",
                               {"id": row.id, "hostname": device.hostname, "user": user, "reason": reason, "minutes": minutes})
    audit.record(db, f"device:{device.hostname}", "elevation.requested", user, device.tenant_id, request=row.id, mode=mode)
    db.commit()
    return {"id": row.id, "status": row.status, "minutes": minutes}


@console.get("")
def list_requests(status: str = Query(""), tenant_id: str = Query(""), principal: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    principal.require("respond")
    tenants = [tenant_id] if tenant_id else list(principal.tenant_ids)
    if tenant_id and tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Tenant not found")
    query = select(ElevationRequest).where(ElevationRequest.tenant_id.in_(tenants))
    if status:
        query = query.where(ElevationRequest.status == status)
    rows = db.execute(query.order_by(ElevationRequest.created_at.desc()).limit(200)).scalars().all()
    devices = {d.id: d for d in db.execute(select(Device).where(Device.id.in_({r.device_id for r in rows}))).scalars()} if rows else {}
    return [_view(r, devices.get(r.device_id)) for r in rows]


def _owned(db: Session, principal: Principal, request_id: str) -> tuple[ElevationRequest, Device]:
    row = db.get(ElevationRequest, request_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Request not found")
    device = db.get(Device, row.device_id)
    if device is None:
        raise HTTPException(404, "Device not found")
    return row, device


@console.post("/{request_id}/approve")
def approve(request_id: str, body: dict = Body(default={}), principal: Principal = Depends(current_principal),
            db: Session = Depends(get_db)):
    principal.require("configure")
    row, device = _owned(db, principal, request_id)
    if row.status != "pending":
        raise HTTPException(409, f"This request is already {row.status}")
    if isinstance(body.get("minutes"), int):
        row.minutes = max(5, min(480, body["minutes"]))
    row.note = str(body.get("note") or "")[:500]
    try:
        _grant(db, device, row, principal.actor)
    except services.CommandError as exc:
        raise HTTPException(409, str(exc)) from None
    audit.record(db, principal.actor, "elevation.approved", f"{device.hostname}:{row.user}", device.tenant_id,
                 request=row.id, minutes=row.minutes)
    db.commit()
    return _view(row, device)


@console.post("/{request_id}/deny")
def deny(request_id: str, body: dict = Body(default={}), principal: Principal = Depends(current_principal),
         db: Session = Depends(get_db)):
    principal.require("respond")
    row, device = _owned(db, principal, request_id)
    if row.status != "pending":
        raise HTTPException(409, f"This request is already {row.status}")
    row.status, row.decided_by, row.decided_at = "denied", principal.actor, utcnow()
    row.note = str(body.get("note") or "")[:500]
    audit.record(db, principal.actor, "elevation.denied", f"{device.hostname}:{row.user}", device.tenant_id, request=row.id)
    db.commit()
    return _view(row, device)


@console.post("/{request_id}/revoke")
def revoke(request_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row, device = _owned(db, principal, request_id)
    if row.status not in {"approved", "granted"}:
        raise HTTPException(409, f"This request is {row.status}; there is nothing to revoke")
    services.enqueue_command(db, device, "elevation.revoke", principal.actor, reason=f"Revoke elevation for {row.user}",
                             payload={"requestId": row.id, "userSid": row.user_sid, "user": row.user})
    row.status = "revoked"
    audit.record(db, principal.actor, "elevation.revoked", f"{device.hostname}:{row.user}", device.tenant_id, request=row.id)
    db.commit()
    return _view(row, device)


def on_command_complete(db: Session, device: Device, command: Command) -> None:
    """Called when the agent reports an elevation.grant result."""
    if command.type != "elevation.grant":
        return
    request_id = str((command.payload or {}).get("requestId") or "")
    row = db.get(ElevationRequest, request_id) if request_id else None
    if row is None or row.device_id != device.id or row.status != "approved":
        return
    if command.status == "completed":
        row.status, row.granted_at = "granted", utcnow()
    else:
        row.status = "failed"
        row.note = str((command.result or {}).get("error") or "The device could not grant admin rights")[:500]
