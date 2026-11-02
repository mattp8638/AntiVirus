"""Offboarding, onboarding and bulk user import for Microsoft 365 (m365_lifecycle.py)."""
from __future__ import annotations

from typing import Literal
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import crypto, m365_admin, m365_lifecycle as lifecycle, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth
from ..models import M365Connection, M365Workflow
from ..serialize import to_dict
from .documentation import owned
from .m365_admin import NewUserProfile

router = APIRouter(prefix="/api/console/m365", tags=["Microsoft 365 lifecycle"])


class OffboardOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    blockSignIn: bool = True
    revokeSessions: bool = True
    resetPassword: bool = True
    removeMfa: bool = True
    outOfOffice: bool = False
    outOfOfficeMessage: str = Field(default="", max_length=4000)
    removeGroups: bool = True
    removeRoles: bool = True
    removeLicences: bool = False
    markContact: bool = True
    openTicket: bool = True
    # AD-synced users only: move the account to this OU (a distinguished name) and hide it from the address book.
    adMoveOu: str = Field(default="", max_length=512)
    hideFromAddressBook: bool = False
    # Fenrir's side: devices they used, their stored credentials (flagged for rotation) and the billing effect.
    reviewEstate: bool = True
    # Exchange: keep the mailbox (shared, no licence needed), give a colleague access, forward new mail.
    convertToShared: bool = False
    mailboxDelegate: str = Field(default="", max_length=254, pattern=r"^$|^[^@\s'\"`;|&$<>(){}]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
    forwardTo: str = Field(default="", max_length=254, pattern=r"^$|^[^@\s'\"`;|&$<>(){}]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
    onedriveDelegate: str = Field(default="", max_length=254, pattern=r"^$|^[^@\s'\"`;|&$<>(){}]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class AdPlacement(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    sam: str = Field(default="", max_length=20, pattern=r"^[A-Za-z0-9._-]*$")
    ou: str = Field(default="", max_length=512)
    groups: list[str] = Field(default_factory=list, max_length=50)


class OnboardOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    createIn: Literal["cloud", "ad"] = "cloud"  # ad: created in Active Directory and synced by Entra Connect
    ad: AdPlacement | None = None
    profile: NewUserProfile
    managerId: UUID | None = None
    skuIds: list[UUID] = Field(default_factory=list, max_length=10)
    groupIds: list[UUID] = Field(default_factory=list, max_length=50)
    addContact: bool = True
    openTicket: bool = True


class BulkOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rows: list[NewUserProfile] = Field(min_length=1, max_length=lifecycle.BULK_MAX)
    skuIds: list[UUID] = Field(default_factory=list, max_length=10)
    groupIds: list[UUID] = Field(default_factory=list, max_length=50)
    openTicket: bool = False


class WorkflowInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["offboard", "onboard", "bulk_create"]
    targetId: UUID | None = None
    options: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def check(self):
        if self.kind == "offboard":
            if self.targetId is None:
                raise ValueError("Choose the user to offboard")
            if self.options.get("outOfOffice") and not str(self.options.get("outOfOfficeMessage") or "").strip():
                raise ValueError("Write the out-of-office message")
            self.options = OffboardOptions(**self.options).model_dump(mode="json")
        elif self.kind == "onboard":
            self.options = OnboardOptions(**self.options).model_dump(mode="json", exclude_none=True)
            self.options["profile"] = {k: v for k, v in self.options["profile"].items() if v != ""}
        else:
            self.options = BulkOptions(**self.options).model_dump(mode="json")
            self.options["rows"] = [{k: v for k, v in r.items() if v != ""} for r in self.options["rows"]]
        return self


class RunInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmed: Literal[True]


class ResolveInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: Literal["done", "retry", "skip"]


def _connection(db: Session, ident: str, principal: Principal) -> M365Connection:
    principal.require("m365_admin")
    return owned(db, M365Connection, ident, principal)


def _workflow(db: Session, ident: str, principal: Principal) -> M365Workflow:
    principal.require("m365_admin")
    return owned(db, M365Workflow, ident, principal)


def _failure(exc: Exception) -> HTTPException:
    if isinstance(exc, (lifecycle.PlanError, m365_admin.ProviderError)):
        return HTTPException(400, str(exc))
    if isinstance(exc, httpx.HTTPStatusError):
        return HTTPException(502, "Microsoft refused." + m365_admin.microsoft_said(exc.response))
    return HTTPException(502, "Microsoft request failed. Check the connection's credentials, consent and service availability.")


@router.get("/connections/{connection_id}/workflows")
def workflows(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = _connection(db, connection_id, principal)
    return [to_dict(w) for w in db.execute(select(M365Workflow).where(M365Workflow.connection_id == row.id)
                                            .order_by(M365Workflow.created_at.desc()).limit(100)).scalars()]


@router.post("/connections/{connection_id}/workflows")
def plan(connection_id: str, body: WorkflowInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Plan only: reads the tenant and lists every change. Nothing changes until the plan is run."""
    row = _connection(db, connection_id, principal)
    ratelimit.check(f"m365-workflow-plan:{principal.user.id}", 20, 300)
    try:
        flow = lifecycle.plan(db, row, body.kind, str(body.targetId) if body.targetId else None, body.options, principal.actor)
    except (lifecycle.PlanError, m365_admin.ProviderError, httpx.HTTPError, ValueError, KeyError, crypto.VaultError) as exc:
        db.rollback()
        raise _failure(exc) from None
    db.commit()
    return to_dict(flow)


@router.get("/workflows/{workflow_id}")
def get_workflow(workflow_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return to_dict(_workflow(db, workflow_id, principal))


@router.post("/workflows/{workflow_id}/run")
def run(workflow_id: str, body: RunInput, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Run (or continue) a workflow. Answers with ``more`` when time ran out and the console should call again; any
    passwords for users created in this call come back here once and are not stored."""
    flow = _workflow(db, workflow_id, principal)
    require_reauth(request, principal)
    connection = db.get(M365Connection, flow.connection_id)
    if connection is None:
        raise HTTPException(404, "Connection not found")
    ratelimit.check(f"m365-workflow-run:{principal.user.id}", 60, 300)
    if flow.status == "completed":
        return {"workflow": to_dict(flow), "secrets": [], "more": False}
    if not lifecycle.claim(db, flow, principal.actor):
        raise HTTPException(409, "This plan is already running, or it is more than 30 minutes old: plan it again.")
    try:
        outcome = lifecycle.run(db, connection, flow, principal.actor)
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError) as exc:
        raise _failure(exc) from None
    return {"workflow": to_dict(outcome["workflow"]), "secrets": outcome["secrets"], "more": outcome["more"],
            "waiting": outcome.get("waiting", "")}


@router.post("/workflows/{workflow_id}/steps/{index}/resolve")
def resolve(workflow_id: str, index: int, body: ResolveInput, request: Request, principal: Principal = Depends(current_principal),
            db: Session = Depends(get_db)):
    """After checking Microsoft: mark a step done, to retry, or skipped."""
    flow = _workflow(db, workflow_id, principal)
    require_reauth(request, principal)
    try:
        lifecycle.resolve(db, flow, index, body.outcome, principal.actor)
    except lifecycle.PlanError as exc:
        raise HTTPException(409, str(exc)) from None
    db.commit()
    return to_dict(flow)
