"""Tenant-scoped Microsoft 365 connections and snapshots."""
from uuid import UUID
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .. import audit, crypto, m365, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth, scoped_tenant
from ..models import M365Connection, new_id, utcnow
from ..serialize import to_dict
from .documentation import owned

router = APIRouter(prefix="/api/console/m365", tags=["Microsoft 365"])
crypto.register_encrypted(M365Connection, "credentials_envelope", lambda row: f"m365:{row.tenant_id}:{row.id}")

class ConnectionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    name: str = Field(min_length=1, max_length=200)
    directoryId: UUID
    clientId: UUID
    clientSecret: str = Field(min_length=1, max_length=10000)

class SecretInput(BaseModel):
    clientSecret: str = Field(min_length=1, max_length=10000)

@router.get("/connections")
def connections(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    return [to_dict(row) for row in db.scalars(select(M365Connection).where(M365Connection.tenant_id.in_(scoped_tenant(principal, tenant_id))).limit(1000))]

@router.post("/connections")
def create(body: ConnectionInput, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    principal.check_tenant(body.tenantId)
    require_reauth(request, principal)
    row = M365Connection(id=new_id("m365"), tenant_id=body.tenantId, name=body.name,
                         directory_id=str(body.directoryId), client_id=str(body.clientId))
    row.credentials_envelope = crypto.encrypt(body.clientSecret, f"m365:{row.tenant_id}:{row.id}")
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "This directory is already connected for this customer")
    audit.record(db, principal.actor, "m365.connected", row.id, row.tenant_id)
    db.commit()
    return to_dict(row)

@router.put("/connections/{connection_id}/secret")
def replace_secret(connection_id: str, body: SecretInput, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = owned(db, M365Connection, connection_id, principal)
    require_reauth(request, principal)
    row.credentials_envelope = crypto.encrypt(body.clientSecret, f"m365:{row.tenant_id}:{row.id}")
    row.updated_at = utcnow()
    audit.record(db, principal.actor, "m365.secret_replaced", row.id, row.tenant_id)
    db.commit()
    return {"ok": True}

@router.post("/connections/{connection_id}/sync")
def sync(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = owned(db, M365Connection, connection_id, principal)
    ratelimit.check(f"m365-sync:{row.id}", 3, 300)
    try:
        snapshot = m365.synchronize(row)
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError):
        # Never return provider bodies, token URLs with secrets, or raw exceptions.
        row.status, row.last_error = "failed", "Sync failed. Check application credentials, Graph permissions and connectivity."
        audit.record(db, principal.actor, "m365.sync_failed", row.id, row.tenant_id)
        db.commit()
        raise HTTPException(502, row.last_error)
    row.snapshot, row.status, row.last_error, row.synced_at = snapshot, "synced", "", utcnow()
    audit.record(db, principal.actor, "m365.synced", row.id, row.tenant_id, users=len(snapshot["users"]), licenses=len(snapshot["licenses"]))
    db.commit()
    return to_dict(row)
