"""Enterprise apps, app registrations, consent and directory extensions (M365-11)."""
from __future__ import annotations

from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from .. import audit, crypto, m365_apps as apps, m365_permissions, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth
from ..models import M365Connection

router = APIRouter(prefix="/api/console/m365/connections", tags=["Microsoft 365 apps"])


def _connection(db: Session, connection_id: str, principal: Principal) -> M365Connection:
    row = db.get(M365Connection, connection_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Connection not found")
    return row


@router.get("/{connection_id}/apps")
def report(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    conn = _connection(db, connection_id, principal)
    last = apps.latest(db, conn.id)
    return {"takenAt": last.taken_at if last else None, **(last.data if last else {}),
            "canManage": m365_permissions.feature_available(conn.snapshot, "apps.manage") is not False}


@router.post("/{connection_id}/apps/refresh")
def refresh(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    conn = _connection(db, connection_id, principal)
    ratelimit.check(f"m365-apps:{principal.user.id}", 6, 300)
    try:
        apps.refresh(db, conn, principal.actor)
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError):
        db.rollback()
        raise HTTPException(502, "Microsoft request failed. Check the connection's consent and permissions.") from None
    db.commit()
    return report(connection_id, principal, db)


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["sp.disable", "sp.enable", "credential.remove", "grant.revoke"]
    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    keyId: str | None = Field(default=None, max_length=64)
    confirmName: str = Field(max_length=300)  # the app's name, typed by the technician


@router.post("/{connection_id}/apps/actions")
def act(connection_id: str, body: Action, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("m365_admin")
    conn = _connection(db, connection_id, principal)
    require_reauth(request, principal)
    ratelimit.check(f"m365-apps-act:{principal.user.id}", 20, 300)
    last = apps.latest(db, conn.id)
    data = last.data if last else {}
    names = {x["id"]: x["displayName"] for x in data.get("servicePrincipals", []) + data.get("registrations", [])}
    names.update({p["grantId"]: s["displayName"] for s in data.get("servicePrincipals", []) for p in s["permissions"] if p.get("grantId")})
    expected = names.get(body.id)
    if expected is None:
        raise HTTPException(404, "Not in the latest inventory; refresh it first")
    if body.confirmName.strip() != expected:
        raise HTTPException(409, f"Type the app's name ({expected}) to confirm")
    try:
        result = apps.act(conn, body.action, {"id": body.id, "keyId": body.keyId})
    except apps.AppsError as exc:
        audit.record(db, principal.actor, "m365.app_action_refused", body.id, conn.tenant_id, action_id=body.action, reason=str(exc))
        db.commit()
        raise HTTPException(409, str(exc)) from None
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError):
        raise HTTPException(502, "Microsoft request failed; check the tenant before trying again.") from None
    audit.record(db, principal.actor, "m365.app_action", body.id, conn.tenant_id, action_id=body.action, app=expected, keyId=body.keyId,
                 result=result["message"])
    db.commit()
    return result
