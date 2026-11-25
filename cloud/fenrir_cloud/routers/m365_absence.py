"""Scheduled absences of Microsoft 365 users (M365-09)."""
from __future__ import annotations

from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crypto, m365_absence as absence_mod, m365_admin as provider, m365_permissions, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth
from ..models import M365Absence, M365Connection
from ..serialize import to_dict

router = APIRouter(prefix="/api/console/m365", tags=["Microsoft 365 absences"])


def _connection(db: Session, connection_id: str, principal: Principal) -> M365Connection:
    row = db.get(M365Connection, connection_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Connection not found")
    return row


def _naive(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


class AutoReply(BaseModel):
    model_config = ConfigDict(extra="forbid")
    internal: str = Field(max_length=4000)
    external: str = Field(default="", max_length=4000)
    externalAudience: str = "all"


class Delegate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(max_length=254)
    role: str = "read"


class NewAbsence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    userId: str = Field(min_length=1, max_length=64)
    startsAt: datetime
    endsAt: datetime
    autoReply: AutoReply | None = None
    forwardTo: str | None = Field(default=None, max_length=254)
    keepCopy: bool = True
    delegates: list[Delegate] = Field(default_factory=list)


@router.get("/connections/{connection_id}/absences")
def list_absences(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    conn = _connection(db, connection_id, principal)
    rows = db.scalars(select(M365Absence).where(M365Absence.connection_id == conn.id).order_by(M365Absence.starts_at.desc()).limit(500))
    return [{**to_dict(a), "stillInPlace": absence_mod.still_in_place(a)} for a in rows]


@router.post("/connections/{connection_id}/absences")
def create(connection_id: str, body: NewAbsence, request: Request, principal: Principal = Depends(current_principal),
           db: Session = Depends(get_db)):
    principal.require("m365_admin")
    conn = _connection(db, connection_id, principal)
    if body.forwardTo or body.delegates:
        require_reauth(request, principal)  # forwarding and calendar access expose the user's data to someone else
    ratelimit.check(f"m365-absence:{principal.user.id}", 20, 300)
    if m365_permissions.feature_available(conn.snapshot, "user.absence") is False:
        raise HTTPException(400, "This connection is not granted mailbox settings and calendar access (Microsoft 365 > Permissions)")
    starts, ends = _naive(body.startsAt), _naive(body.endsAt)
    try:
        settings = absence_mod.validate({"autoReply": body.autoReply.model_dump() if body.autoReply else None, "forwardTo": body.forwardTo,
                                         "keepCopy": body.keepCopy, "delegates": [d.model_dump() for d in body.delegates]}, starts, ends)
        with provider.session(conn) as (client, headers):
            person = provider.user(client, headers, body.userId)
    except absence_mod.AbsenceError as exc:
        raise HTTPException(400, str(exc)) from None
    except provider.ProviderError as exc:
        raise HTTPException(400, str(exc)) from None
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError):
        raise HTTPException(502, "Microsoft request failed: check the user and the connection's permissions") from None
    overlapping = db.scalars(select(M365Absence).where(M365Absence.connection_id == conn.id, M365Absence.user_id == person["id"],
                                                       M365Absence.status.in_(("scheduled", "active")),
                                                       M365Absence.starts_at < ends, M365Absence.ends_at > starts)).first()
    if overlapping:
        raise HTTPException(409, "This user already has an absence in that period")
    row = M365Absence(tenant_id=conn.tenant_id, connection_id=conn.id, user_id=person["id"],
                      user_label=person.get("userPrincipalName") or person.get("displayName") or person["id"],
                      starts_at=starts, ends_at=ends, settings=settings, created_by=principal.actor)
    db.add(row)
    db.flush()
    audit.record(db, principal.actor, "m365.absence_scheduled", row.id, conn.tenant_id, user=row.user_label,
                 startsAt=starts.isoformat(), endsAt=ends.isoformat(), forwardTo=settings.get("forwardTo"),
                 delegates=[d["email"] for d in settings["delegates"]], autoReply=bool(settings.get("autoReply")))
    db.commit()
    if starts <= datetime.now(timezone.utc).replace(tzinfo=None):
        absence_mod.tick(db)  # starts now: apply straight away rather than at the next pass
        db.refresh(row)
    return {**to_dict(row), "stillInPlace": absence_mod.still_in_place(row)}


@router.post("/absences/{absence_id}/end")
def end(absence_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Cancel a scheduled absence, or end an active (or failed) one now and revert it."""
    principal.require("m365_admin")
    row = db.get(M365Absence, absence_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Absence not found")
    try:
        absence_mod.end_now(db, row, principal.actor)
    except absence_mod.AbsenceError as exc:
        raise HTTPException(409, str(exc)) from None
    return {**to_dict(row), "stillInPlace": absence_mod.still_in_place(row)}
