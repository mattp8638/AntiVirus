"""Intune for a Microsoft 365 connection (m365_intune.py)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from .. import audit, crypto, m365_intune as intune, ratelimit
from ..m365_admin import unexpected
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth
from ..models import M365Connection
from .documentation import owned

router = APIRouter(prefix="/api/console/m365/connections/{connection_id}/intune", tags=["Microsoft 365 Intune"])


class DeviceAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(max_length=40)


class AppAssignment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intent: str = Field(max_length=20)
    groupId: str | None = None


class AutopilotImport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    csv: str = Field(max_length=2_000_000)
    groupTag: str = Field(default="", max_length=100)


def _connection(db: Session, ident: str, principal: Principal) -> M365Connection:
    principal.require("m365_admin")
    return owned(db, M365Connection, ident, principal)


def _call(fn, *args):
    try:
        return fn(*args)
    except intune.IntuneError as exc:
        raise HTTPException(400, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, f"Invalid request: {exc}") from None
    except crypto.VaultError:
        raise HTTPException(400, "The connection's credentials cannot be read; reconnect it.") from None
    except Exception as exc:
        raise unexpected(exc, "Intune") from None


@router.get("/devices")
def devices(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return _call(intune.devices, _connection(db, connection_id, principal))


@router.post("/devices/{device_id}/action")
def device_action(connection_id: str, device_id: str, body: DeviceAction, request: Request,
                  principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = _connection(db, connection_id, principal)
    if body.action not in intune.ACTIONS:
        raise HTTPException(422, "Unknown device action")
    destructive = intune.ACTIONS[body.action][2]
    if destructive:
        principal.require("destructive")
        require_reauth(request, principal)
    ratelimit.check(f"intune-action:{principal.user.id}", 60, 300)
    message = _call(intune.device_action, row, device_id, body.action)
    audit.record(db, principal.actor, f"m365.intune.{body.action}", device_id, row.tenant_id, connection=row.id)
    db.commit()
    return {"message": message}


def _reveal(kind: str, fn, connection_id, device_id, request, response, principal, db):
    row = _connection(db, connection_id, principal)
    require_reauth(request, principal)
    ratelimit.check(f"intune-secret:{principal.user.id}", 20, 300)
    result = _call(fn, row, device_id)
    audit.record(db, principal.actor, f"m365.intune.{kind}.revealed", device_id, row.tenant_id, connection=row.id)
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return result


@router.post("/devices/{device_id}/bitlocker")
def bitlocker(connection_id: str, device_id: str, request: Request, response: Response,
              principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The device's BitLocker recovery keys. Shown once; Fenrir does not keep them."""
    return {"keys": _reveal("bitlocker", intune.bitlocker_keys, connection_id, device_id, request, response, principal, db)}


@router.post("/devices/{device_id}/laps")
def laps(connection_id: str, device_id: str, request: Request, response: Response,
         principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The device's current Windows LAPS password. Shown once; Fenrir does not keep it."""
    return _reveal("laps", intune.laps_password, connection_id, device_id, request, response, principal, db)


@router.get("/policies")
def policies(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return _call(intune.policies, _connection(db, connection_id, principal))


@router.get("/apps")
def apps(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return _call(intune.apps, _connection(db, connection_id, principal))


@router.post("/apps/{app_id}/assign")
def assign(connection_id: str, app_id: str, body: AppAssignment, request: Request, principal: Principal = Depends(current_principal),
           db: Session = Depends(get_db)):
    row = _connection(db, connection_id, principal)
    require_reauth(request, principal)
    message = _call(intune.assign_app, row, app_id, body.intent, body.groupId)
    audit.record(db, principal.actor, "m365.intune.app_assigned", message, row.tenant_id, connection=row.id)
    db.commit()
    return {"message": message}


@router.get("/autopilot")
def autopilot(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return _call(intune.autopilot, _connection(db, connection_id, principal))


@router.post("/autopilot/import")
def autopilot_import(connection_id: str, body: AutopilotImport, request: Request, principal: Principal = Depends(current_principal),
                     db: Session = Depends(get_db)):
    row = _connection(db, connection_id, principal)
    require_reauth(request, principal)
    result = _call(intune.import_autopilot, row, body.csv, body.groupTag)
    audit.record(db, principal.actor, "m365.intune.autopilot_import", f"{result['imported']} device(s)", row.tenant_id, connection=row.id)
    db.commit()
    return result
