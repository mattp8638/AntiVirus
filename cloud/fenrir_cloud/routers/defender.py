"""Managed Microsoft Defender API (defender.py): a device's Defender state, a check on request, and the fleet view."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, defender, services
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import DefenderState, Device, Tenant, utcnow
from .fleet import _get_device

router = APIRouter(prefix="/api/console", tags=["Microsoft Defender"])


@router.get("/devices/{device_id}/defender")
def device_defender(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    device = _get_device(db, principal, device_id)
    if (device.platform or "").lower() != "windows":
        raise HTTPException(404, "Microsoft Defender is only on Windows devices")
    return defender.view(db, device)


@router.post("/devices/{device_id}/defender/check")
def check_now(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Apply the policy (when managed) and read Defender's state now, instead of at the next six-hourly check."""
    principal.require("respond")
    device = _get_device(db, principal, device_id)
    if (device.platform or "").lower() != "windows":
        raise HTTPException(404, "Microsoft Defender is only on Windows devices")
    try:
        command = defender.request(db, device, principal.actor)
    except services.CommandError as exc:
        raise HTTPException(400, str(exc)) from None
    audit.record(db, principal.actor, "defender.check", device.hostname, device.tenant_id, command=command.id)
    db.commit()
    return {"commandId": command.id}


@router.get("/defender/fleet")
def fleet(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Every Windows device in scope: is Defender managed, active, current and tamper protected."""
    principal.require("read")
    scope = scoped_tenant(principal, tenant_id)
    devices = db.execute(select(Device).where(Device.tenant_id.in_(scope), Device.platform == "windows", Device.approved.is_(True))
                         .order_by(Device.hostname)).scalars().all()
    devices = [d for d in devices if d.api_key_hash != f"retired-{d.id}"]
    states = {s.device_id: s for s in db.execute(select(DefenderState).where(DefenderState.device_id.in_([d.id for d in devices]))).scalars()}
    names = dict(db.execute(select(Tenant.id, Tenant.name).where(Tenant.id.in_({d.tenant_id for d in devices}))).all())
    rows = []
    for device in devices:
        state = states.get(device.id)
        status = (state.status if state else None) or {}
        settings = defender.settings_for(db, device)
        rev = defender.revision(settings)
        rows.append({"deviceId": device.id, "hostname": device.hostname, "customer": names.get(device.tenant_id, ""),
                     "managed": rev is not None, "checkedAt": state.checked_at.isoformat() + "Z" if state and state.checked_at else None,
                     "mode": status.get("mode"), "realTime": status.get("realTime"), "tamper": status.get("tamper"),
                     "signatureAgeDays": status.get("signatureAgeDays"),
                     "inSync": rev is None or bool(state and state.applied_revision == rev),
                     "problems": defender.problems(status, settings) if status else [],
                     "detections30d": len(status.get("detections") or [])})
    summary = {"devices": len(rows), "managed": sum(r["managed"] for r in rows), "reporting": sum(1 for r in rows if r["checkedAt"]),
               "withProblems": sum(1 for r in rows if r["problems"]), "tamperOff": sum(1 for r in rows if r["tamper"] is False),
               "at": utcnow().isoformat() + "Z"}
    return {"summary": summary, "devices": rows}
