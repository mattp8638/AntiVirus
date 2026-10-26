"""Reviewed Microsoft writes with a durable claim committed before provider dispatch."""
from datetime import timedelta
from typing import Literal
from uuid import UUID
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .. import audit, crypto, events, m365_admin as provider, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth
from ..models import M365Action, M365Connection, utcnow
from ..serialize import to_dict
from .documentation import owned

router = APIRouter(prefix="/api/console/m365/connections", tags=["Microsoft administration"])

class NewUserProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    displayName: str = Field(min_length=1, max_length=128)
    userPrincipalName: str = Field(min_length=3, max_length=113, pattern=r"^[A-Za-z0-9._!#^~'-]+@[A-Za-z0-9.-]+$")
    mailNickname: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    usageLocation: str = Field(pattern=r"^[A-Z]{2}$")
    givenName: str = Field(default="", max_length=64)
    surname: str = Field(default="", max_length=64)
    department: str = Field(default="", max_length=64)
    jobTitle: str = Field(default="", max_length=128)


class ActionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requestId: UUID
    operation: Literal["user.create", "user.revoke_sessions", "user.update", "user.signin", "license.add", "license.remove", "group.add_member", "group.remove_member"]
    targetId: UUID | None = None
    parameters: dict

    @model_validator(mode="after")
    def validate_parameters(self):
        p = self.parameters
        if self.operation == "user.create":
            if self.targetId is not None:
                raise ValueError("New users do not have an existing target ID")
            self.parameters = NewUserProfile(**p).model_dump(exclude_defaults=True)
            return self
        if self.targetId is None:
            raise ValueError("An existing user ID is required")
        if self.operation == "user.revoke_sessions":
            if p:
                raise ValueError("Session revocation takes no parameters")
        elif self.operation == "user.update":
            allowed = {"displayName", "department", "jobTitle", "usageLocation"}
            if not p or set(p) - allowed:
                raise ValueError("Choose supported profile fields")
            for key, value in p.items():
                if not isinstance(value, str) or len(value) > 128 or (key == "displayName" and not value.strip()):
                    raise ValueError("Invalid profile field")
                if key == "usageLocation" and (len(value) != 2 or not value.isascii() or not value.isalpha() or value != value.upper()):
                    raise ValueError("Usage location must be a two-letter uppercase country code")
        elif self.operation == "user.signin":
            if set(p) != {"accountEnabled"} or type(p["accountEnabled"]) is not bool:
                raise ValueError("accountEnabled must be a boolean")
        else:
            key = "skuId" if self.operation.startswith("license.") else "groupId"
            if set(p) != {key}:
                raise ValueError("Unexpected action parameters")
            p[key] = str(UUID(str(p[key])))
        return self

def connection(db, ident, principal, permission="m365_admin"):
    principal.require(permission)
    return owned(db, M365Connection, ident, principal)

def provider_failure():
    return HTTPException(502, "Microsoft request failed. Check connection credentials, consent and service availability.")

@router.get("/{connection_id}/inventory/{collection}")
def inventory(connection_id: str, collection: Literal["users", "groups", "licenses"], principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = connection(db, connection_id, principal, "configure")
    ratelimit.check(f"m365-read:{principal.user.id}", 60, 60)
    try:
        return provider.inventory(row, collection)
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError):
        raise provider_failure() from None

@router.post("/{connection_id}/diagnostics")
def diagnostics(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = connection(db, connection_id, principal, "configure")
    ratelimit.check(f"m365-diagnostics:{principal.user.id}", 10, 300)
    try:
        return provider.diagnostics(row)
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError):
        raise provider_failure() from None

@router.get("/{connection_id}/actions")
def actions(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = connection(db, connection_id, principal)
    return [to_dict(x) for x in db.scalars(select(M365Action).where(M365Action.connection_id == row.id).order_by(M365Action.created_at.desc()).limit(200))]

@router.post("/{connection_id}/actions")
def prepare(connection_id: str, body: ActionInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = connection(db, connection_id, principal)
    existing = db.scalar(select(M365Action).where(M365Action.connection_id == row.id, M365Action.request_id == str(body.requestId)))
    if existing:
        if (existing.operation, existing.target_id, existing.parameters) != (body.operation, str(body.targetId or body.requestId), body.parameters):
            raise HTTPException(409, "Request ID already belongs to another action")
        return to_dict(existing)
    ratelimit.check(f"m365-prepare:{principal.user.id}", 30, 300)
    try:
        preview = provider.preview(row, body.operation, str(body.targetId or body.requestId), body.parameters)
    except provider.ProviderError as exc:
        raise HTTPException(400, str(exc)) from None
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError):
        raise provider_failure() from None
    job = M365Action(connection_id=row.id, tenant_id=row.tenant_id, request_id=str(body.requestId),
        operation=body.operation, target_id=str(body.targetId or body.requestId), parameters=body.parameters, preview=preview, requested_by=principal.actor)
    db.add(job)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Request already recorded; retry with the same request ID") from None
    audit.record(db, principal.actor, "m365.action_prepared", job.id, row.tenant_id, operation=job.operation, targetId=job.target_id)
    db.commit()
    return to_dict(job)

class Confirmation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmed: Literal[True]
    temporaryPassword: SecretStr | None = None

@router.post("/{connection_id}/actions/{action_id}/execute")
def execute(connection_id: str, action_id: str, body: Confirmation, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    conn = connection(db, connection_id, principal)
    job = owned(db, M365Action, action_id, principal)
    if job.connection_id != conn.id:
        raise HTTPException(404, "Action not found")
    require_reauth(request, principal)
    if job.status != "prepared":
        return to_dict(job)  # Never replay running, failed, unknown or completed provider writes.
    if job.operation == "user.create":
        password = body.temporaryPassword.get_secret_value() if body.temporaryPassword else ""
        if not 12 <= len(password) <= 128:
            raise HTTPException(422, "Enter a temporary password of 12 to 128 characters")
    elif body.temporaryPassword is not None:
        raise HTTPException(422, "This action does not accept a temporary password")
    ratelimit.check(f"m365-execute:{principal.user.id}", 20, 300)
    claimed = db.execute(update(M365Action).where(M365Action.id == job.id, M365Action.status == "prepared",
        M365Action.created_at > utcnow() - timedelta(minutes=10)).values(status="running", started_at=utcnow(), executed_by=principal.actor)
        .execution_options(synchronize_session=False)).rowcount
    if not claimed:
        db.rollback()
        raise HTTPException(409, "Action was already claimed or its ten-minute preview expired")
    audit.record(db, principal.actor, "m365.action_started", job.id, job.tenant_id, operation=job.operation)
    db.commit()  # Durable boundary: a crash after this point requires manual reconciliation.
    db.refresh(job)
    try:
        if job.operation == "user.create":
            job.status, job.result = provider.create_user(conn, job.parameters, password)
        else:
            job.status, job.result = provider.execute(conn, job.operation, job.target_id, job.parameters)
    except provider.ProviderError as exc:
        job.status, job.result = ("unknown" if exc.uncertain else "failed"), {"message": str(exc)}
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError):
        job.status, job.result = "failed", {"message": "Pre-dispatch validation failed. Check connection, consent and target."}
    except Exception:
        job.status, job.result = "unknown", {"message": "Outcome requires manual verification. This action will not be replayed."}
    job.completed_at = utcnow()
    audit.record(db, principal.actor, "m365.action_finished", job.id, job.tenant_id, status=job.status, operation=job.operation)
    events.publish(db, "m365.action_finished", {"actionId": job.id, "status": job.status}, job.tenant_id, key="m365-action:" + job.id)
    db.commit()
    return to_dict(job)
