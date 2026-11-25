"""Google Workspace posture assessment and safe remediation (VULN-12)."""
from __future__ import annotations

import json
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crypto, google_workspace as gw, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth
from ..models import GoogleWorkspaceConnection, GoogleWorkspacePosture
from ..serialize import to_dict

router = APIRouter(prefix="/api/console/google-workspace", tags=["Google Workspace"])


def _out(c: GoogleWorkspaceConnection) -> dict:
    d = to_dict(c)
    d.pop("credentialsEnvelope", None)
    d["scopes"] = gw.scopes(c)
    return d


def _conn(db: Session, ident: str, p: Principal) -> GoogleWorkspaceConnection:
    c = db.get(GoogleWorkspaceConnection, ident)
    if c is None or c.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Connection not found")
    return c


class NewConnection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    domain: str = Field(max_length=253, pattern=r"^[a-z0-9.-]+\.[a-z]{2,63}$")
    adminEmail: str = Field(max_length=320, pattern=r"^[^@\s]+@[^@\s]+$")
    serviceAccountKey: str = Field(max_length=10000)
    allowChanges: bool = False


@router.get("/scopes")
def scope_list(p: Principal = Depends(current_principal)):
    p.require("read")
    return {"read": gw.READ_SCOPES, "write": gw.WRITE_SCOPES}


@router.post("/connections")
def create(body: NewConnection, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    p.check_tenant(body.tenantId)
    require_reauth(request, p)
    try:
        key = gw.parse_key(body.serviceAccountKey)
    except gw.WorkspaceError as exc:
        raise HTTPException(400, str(exc)) from None
    c = GoogleWorkspaceConnection(tenant_id=body.tenantId, domain=body.domain, admin_email=body.adminEmail, client_email=key["client_email"],
                                  credentials_envelope={}, allow_changes=body.allowChanges, created_by=p.actor)
    db.add(c)
    db.flush()
    c.credentials_envelope = crypto.encrypt(json.dumps(key), f"google-workspace:{c.id}")
    audit.record(db, p.actor, "google_workspace.connected", c.id, body.tenantId, domain=body.domain, allowChanges=body.allowChanges)
    db.commit()
    return _out(c)


@router.get("/connections")
def list_connections(tenantId: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    p.check_tenant(tenantId)
    return [_out(c) for c in db.scalars(select(GoogleWorkspaceConnection).where(GoogleWorkspaceConnection.tenant_id == tenantId))]


@router.post("/connections/{ident}/assess")
def assess(ident: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    c = _conn(db, ident, p)
    ratelimit.check(f"gws-assess:{c.id}", 10, 3600)
    try:
        row = gw.assess(db, c, p.actor)
    except (gw.WorkspaceError, httpx.HTTPError, crypto.VaultError, ValueError) as exc:
        db.rollback()
        c = _conn(db, ident, p)
        c.status, c.last_error = "error", str(exc)[:500]
        db.commit()
        raise HTTPException(502, str(exc) if isinstance(exc, gw.WorkspaceError) else "Google request failed") from None
    db.commit()
    return to_dict(row)


@router.get("/connections/{ident}/assessments")
def assessments(ident: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    c = _conn(db, ident, p)
    rows = db.scalars(select(GoogleWorkspacePosture).where(GoogleWorkspacePosture.connection_id == c.id)
                      .order_by(GoogleWorkspacePosture.created_at.desc()).limit(50))
    return [to_dict(r) for r in rows]


class Remedy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["signout", "require-password-change", "suspend"]
    email: str = Field(max_length=320, pattern=r"^[^@\s/]+@[^@\s/]+$")
    confirmEmail: str


@router.post("/connections/{ident}/remediate")
def remediate(ident: str, body: Remedy, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    c = _conn(db, ident, p)
    require_reauth(request, p)
    if body.confirmEmail.strip().lower() != body.email.lower():
        raise HTTPException(409, "Type the account's address to confirm")
    try:
        out = gw.remediate(c, body.action, body.email)
    except gw.WorkspaceError as exc:
        audit.record(db, p.actor, "google_workspace.remediation_refused", c.id, c.tenant_id, action_id=body.action, user=body.email, reason=str(exc))
        db.commit()
        raise HTTPException(409, str(exc)) from None
    except (httpx.HTTPError, crypto.VaultError, ValueError):
        raise HTTPException(502, "Google request failed; check the account before trying again") from None
    audit.record(db, p.actor, "google_workspace.remediated", c.id, c.tenant_id, action_id=body.action, user=body.email, verified=out["verified"])
    db.commit()
    return out
