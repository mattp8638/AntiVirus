"""Local administrator password rotation (LAPS-style) for Windows devices.

Agent side: the agent escrows a freshly generated password (status "pending") before setting it on the device,
then confirms the result. Console side: technicians list the history, reveal a password (re-authentication,
rate limit and audit) and request an immediate rotation.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crypto, ratelimit, services
from ..db import get_db
from ..deps import Principal, current_device, current_principal, require_reauth
from ..models import Device, LocalAdminPassword, utcnow

agent = APIRouter(prefix="/api/v1/devices/{device_id}/local-admin", tags=["Agent"])
console = APIRouter(prefix="/api/console/devices/{device_id}/local-admin", tags=["Devices"])


def _aad(row: LocalAdminPassword) -> str:
    return f"laps:{row.tenant_id}:{row.device_id}:{row.id}"


@agent.post("/escrow")
def escrow(body: dict = Body(...), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    password = str(body.get("password") or "")
    account = str(body.get("account") or "")[:120]
    if not 14 <= len(password) <= 128 or not account:
        raise HTTPException(422, "account and a 14-128 character password are required")
    ratelimit.check(f"laps-escrow:{device.id}", 10, 3600)
    row = LocalAdminPassword(tenant_id=device.tenant_id, device_id=device.id, account=account, ciphertext={}, status="pending")
    db.add(row)
    db.flush()
    row.ciphertext = crypto.encrypt(password, _aad(row))
    db.commit()
    return {"version": row.id}


@agent.post("/confirm")
def confirm(body: dict = Body(...), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    row = db.get(LocalAdminPassword, str(body.get("version") or ""))
    if row is None or row.device_id != device.id or row.status != "pending":
        raise HTTPException(404, "Unknown pending password")
    if body.get("applied"):
        for older in db.execute(select(LocalAdminPassword).where(LocalAdminPassword.device_id == device.id,
                                                                 LocalAdminPassword.status == "active")).scalars():
            older.status = "superseded"
        row.status, row.confirmed_at = "active", utcnow()
        audit.record(db, f"device:{device.hostname}", "laps.rotated", row.account, device.tenant_id, version=row.id)
    else:
        row.status, row.error = "failed", str(body.get("error") or "")[:300]
    db.commit()
    return {"status": row.status}


def _device(db: Session, principal: Principal, device_id: str) -> Device:
    device = db.get(Device, device_id)
    if device is None or device.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Device not found")
    return device


@console.get("")
def history(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    device = _device(db, principal, device_id)
    rows = db.execute(select(LocalAdminPassword).where(LocalAdminPassword.device_id == device.id)
                      .order_by(LocalAdminPassword.created_at.desc()).limit(20)).scalars().all()
    settings, _ = services.effective_policy(db, device)
    privilege = settings["settings"].get("privilege", {})
    return {
        "enabled": bool(privilege.get("rotateLocalAdminPassword")),
        "rotationDays": privilege.get("localAdminPasswordDays", 30),
        "items": [{"id": r.id, "account": r.account, "status": r.status, "error": r.error,
                   "createdAt": r.created_at.isoformat() + "Z", "confirmedAt": r.confirmed_at.isoformat() + "Z" if r.confirmed_at else None}
                  for r in rows],
    }


@console.post("/{version}/reveal")
def reveal(device_id: str, version: str, request: Request, response: Response,
           principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    device = _device(db, principal, device_id)
    row = db.get(LocalAdminPassword, version)
    if row is None or row.device_id != device.id or row.status == "failed":
        raise HTTPException(404, "Password not found")
    require_reauth(request, principal)
    ratelimit.check(f"laps-reveal:{principal.user.id}", 20, 300)
    password = crypto.decrypt(row.ciphertext, _aad(row))
    audit.record(db, principal.actor, "laps.revealed", f"{device.hostname}:{row.account}", device.tenant_id, version=row.id)
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return {"account": row.account, "password": password, "status": row.status}


@console.post("/rotate")
def rotate_now(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    device = _device(db, principal, device_id)
    if (device.platform or "windows").lower() != "windows":
        raise HTTPException(422, "Local admin password rotation is available for Windows devices")
    command = services.enqueue_command(db, device, "localadmin.rotate", principal.actor, reason="Rotate the local admin password")
    audit.record(db, principal.actor, "laps.rotation_requested", device.hostname, device.tenant_id)
    db.commit()
    return {"commandId": command.id}
