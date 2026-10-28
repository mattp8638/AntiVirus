"""Scoped API credentials (CORE-04): create, list, rotate and revoke. Creating or rotating one shows the token once
and needs a fresh password check; an API credential can never create or rotate credentials itself."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import apikeys, audit
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth, scoped_tenant
from ..models import ApiCredential, utcnow

router = APIRouter(prefix="/api/console/api-credentials", tags=["API credentials"])


def _view(cred: ApiCredential) -> dict:
    now = utcnow()
    state = "revoked" if cred.revoked_at else "expired" if cred.expires_at <= now else "active"
    iso = lambda d: d.isoformat() + "Z" if d else None  # noqa: E731
    return {"id": cred.id, "tenantId": cred.tenant_id, "name": cred.name, "scopes": cred.scopes, "prefix": cred.prefix, "state": state,
            "createdBy": cred.created_by, "createdAt": iso(cred.created_at), "expiresAt": iso(cred.expires_at),
            "rotatedAt": iso(cred.rotated_at), "revokedAt": iso(cred.revoked_at), "lastUsedAt": iso(cred.last_used_at),
            "lastUsedIp": cred.last_used_ip, "useCount": cred.use_count}


def _human(principal: Principal) -> None:
    if principal.credential_id:
        raise HTTPException(403, "API credentials cannot manage API credentials")


def _owned(db: Session, principal: Principal, cred_id: str) -> ApiCredential:
    cred = db.get(ApiCredential, cred_id)
    if cred is None or cred.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    return cred


@router.get("")
def list_credentials(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    rows = db.execute(select(ApiCredential).where(ApiCredential.tenant_id.in_(scoped_tenant(principal, tenant_id)))
                      .order_by(ApiCredential.created_at.desc())).scalars().all()
    return {"grantable": [s for s in apikeys.GRANTABLE if principal.can(s)], "credentials": [_view(c) for c in rows]}


class CredentialInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    name: str = Field(min_length=1, max_length=200)
    scopes: list[str] = Field(min_length=1, max_length=len(apikeys.GRANTABLE))
    expiresDays: int = Field(default=90, ge=1, le=apikeys.MAX_DAYS)


@router.post("")
def create_credential(body: CredentialInput, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    _human(principal)
    principal.check_tenant(body.tenantId)
    bad = [s for s in body.scopes if s not in apikeys.GRANTABLE]
    if bad:
        raise HTTPException(400, f"These permissions cannot be given to an API credential: {', '.join(bad)}")
    beyond = [s for s in body.scopes if not principal.can(s)]
    if beyond:
        raise HTTPException(400, f"You cannot grant permissions you do not have: {', '.join(beyond)}")
    require_reauth(request, principal)
    cred, token = apikeys.issue(db, body.tenantId, body.name.strip(), body.scopes, body.expiresDays, principal.actor)
    audit.record(db, principal.actor, "api_credential.created", cred.id, cred.tenant_id, name=cred.name, scopes=cred.scopes,
                 expiresAt=cred.expires_at.isoformat())
    db.commit()
    return {**_view(cred), "token": token}


@router.post("/{cred_id}/rotate")
def rotate_credential(cred_id: str, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    _human(principal)
    cred = _owned(db, principal, cred_id)
    if cred.revoked_at:
        raise HTTPException(409, "A revoked credential cannot be rotated")
    require_reauth(request, principal)
    token = apikeys.rotate(db, cred)
    audit.record(db, principal.actor, "api_credential.rotated", cred.id, cred.tenant_id)
    db.commit()
    return {**_view(cred), "token": token}


@router.post("/{cred_id}/revoke")
def revoke_credential(cred_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    cred = _owned(db, principal, cred_id)
    if cred.revoked_at is None:
        apikeys.revoke(db, cred, principal.actor)
        audit.record(db, principal.actor, "api_credential.revoked", cred.id, cred.tenant_id)
        db.commit()
    return _view(cred)
