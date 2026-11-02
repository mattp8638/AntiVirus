"""Hybrid identity: the customer's Active Directory as seen from Microsoft 365 administration, and the agent's
one-time secret release for ad.directory commands (hybrid_identity.py)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import hybrid_identity, ratelimit
from ..db import get_db
from ..deps import Principal, current_device, current_principal
from ..models import Command, Device, M365Connection
from .documentation import owned

router = APIRouter(prefix="/api/console/m365", tags=["Hybrid identity"])
agent_router = APIRouter(prefix="/api/v1", tags=["Agent API"])


@router.get("/connections/{connection_id}/directory")
def directory(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The customer's Active Directory: domain controllers, the Entra Connect server, and OUs, groups and UPN suffixes
    for onboarding (read by the domain controller on request)."""
    principal.require("configure")
    row = owned(db, M365Connection, connection_id, principal)
    hybrid_identity.collect_options(db, row.tenant_id)
    db.commit()
    return hybrid_identity.context(db, row.tenant_id)


@router.post("/connections/{connection_id}/directory/refresh")
def refresh_directory(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("m365_admin")
    row = owned(db, M365Connection, connection_id, principal)
    ratelimit.check(f"ad-options:{row.tenant_id}", 6, 300)
    try:
        hybrid_identity.refresh_options(db, row.tenant_id, principal.actor)
    except hybrid_identity.HybridError as exc:
        raise HTTPException(409, str(exc)) from None
    db.commit()
    return hybrid_identity.context(db, row.tenant_id)


@agent_router.post("/devices/{device_id}/commands/{command_id}/secret")
def release_secret(command_id: str, device: Device = Depends(current_device), db: Session = Depends(get_db)):
    """The one-time secret of one ad.directory command, released once, only to the device it was sent to."""
    command = db.get(Command, command_id)
    if command is None:
        raise HTTPException(404, "Not found")
    try:
        secret = hybrid_identity.release_secret(db, device, command)
    except hybrid_identity.HybridError as exc:
        db.commit()
        raise HTTPException(404, str(exc)) from None
    db.commit()
    return {"secret": secret}
