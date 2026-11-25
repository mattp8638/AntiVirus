"""Sandbox analysis with approval and confidential-data controls (AV-15)."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, sandbox
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth, scoped_tenant
from ..models import Alert, SandboxProvider, SandboxSubmission, Tenant
from ..serialize import to_dict

router = APIRouter(prefix="/api/console/sandbox", tags=["Sandbox analysis"])


def _out(p: SandboxProvider) -> dict:
    d = to_dict(p)
    d.pop("credentialsEnvelope", None)
    return d


class NewProvider(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    name: str = Field(min_length=1, max_length=200)
    baseUrl: str = Field(max_length=300, pattern=r"^https://[^/?#@]+$")
    apiKey: str = Field(min_length=1, max_length=500)


@router.post("/providers")
def add_provider(body: NewProvider, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    p.check_tenant(body.tenantId)
    require_reauth(request, p)
    row = SandboxProvider(tenant_id=body.tenantId, name=body.name, base_url=body.baseUrl, created_by=p.actor)
    db.add(row)
    db.flush()
    sandbox.store_key(row, body.apiKey)
    audit.record(db, p.actor, "sandbox.provider_added", row.id, body.tenantId, baseUrl=body.baseUrl)
    db.commit()
    return _out(row)


@router.get("/providers")
def providers(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    return [_out(x) for x in db.scalars(select(SandboxProvider).where(SandboxProvider.tenant_id.in_(list(p.tenant_ids))))]


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    mode: Literal["file", "hash"] = "hash"
    autoApproveExecutables: bool = False
    neverSubmit: list[str] = Field(default_factory=list, max_length=100)


@router.put("/policy/{tenant_id}")
def save_policy(tenant_id: str, body: Policy, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    p.check_tenant(tenant_id)
    t = db.get(Tenant, tenant_id)
    t.settings = {**(t.settings or {}), "sandbox": body.model_dump()}
    audit.record(db, p.actor, "sandbox.policy_saved", tenant_id, tenant_id, **body.model_dump())
    db.commit()
    return body.model_dump()


@router.get("/policy/{tenant_id}")
def get_policy(tenant_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    p.check_tenant(tenant_id)
    return {**sandbox.settings(db, tenant_id), "provider": bool(sandbox.provider_for(db, tenant_id))}


class Submit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alertId: str | None = None
    tenantId: str | None = None
    sha256: str | None = Field(default=None, max_length=64)
    filename: str = Field(default="", max_length=300)
    path: str = Field(default="", max_length=1000)
    deviceId: str | None = None
    quarantineRecord: str = Field(default="", max_length=100)


@router.post("/submissions")
def submit(body: Submit, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("respond")
    if body.alertId:
        alert = db.get(Alert, body.alertId)
        if alert is None or alert.tenant_id not in p.tenant_ids:
            raise HTTPException(404, "Alert not found")
        d = alert.details or {}
        args = {"tenant_id": alert.tenant_id, "sha256": body.sha256 or d.get("sha256") or "", "filename": body.filename or d.get("fileName") or "",
                "path": body.path or d.get("path") or d.get("filePath") or "", "device_id": alert.device_id,
                "quarantine_record": body.quarantineRecord or d.get("recordId") or d.get("quarantineRecord") or "",
                "alert_id": alert.id, "incident_id": alert.incident_id}
    else:
        p.check_tenant(body.tenantId)
        args = {"tenant_id": body.tenantId, "sha256": body.sha256 or "", "filename": body.filename, "path": body.path, "device_id": body.deviceId,
                "quarantine_record": body.quarantineRecord}
    try:
        sub = sandbox.request(db, actor=p.actor, **args)
    except sandbox.SandboxError as exc:
        raise HTTPException(400, str(exc)) from None
    db.commit()
    return to_dict(sub)


@router.get("/submissions")
def list_submissions(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    rows = db.scalars(select(SandboxSubmission).where(SandboxSubmission.tenant_id.in_(scoped_tenant(p, tenantId)))
                      .order_by(SandboxSubmission.created_at.desc()).limit(200))
    return [to_dict(r) for r in rows]


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approve: bool
    note: str = Field(default="", max_length=500)


@router.post("/submissions/{sub_id}/review")
def review(sub_id: str, body: Review, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("respond")
    sub = db.get(SandboxSubmission, sub_id)
    if sub is None or sub.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Submission not found")
    try:
        sandbox.approve(db, sub, p.actor, body.approve, body.note)
    except sandbox.SandboxError as exc:
        raise HTTPException(409, str(exc)) from None
    db.commit()
    return to_dict(sub)


class EmailSubmit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sha256: str = Field(min_length=64, max_length=64)


@router.post("/email/{scan_id}")
def submit_email(scan_id: str, body: EmailSubmit, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Submit one attachment of a scanned email (AV-16): uploaded from the gateway quarantine, or looked up by hash."""
    from ..models import EmailScan

    p.require("respond")
    scan = db.get(EmailScan, scan_id)
    if scan is None or scan.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Message not found")
    try:
        sub = sandbox.request_email(db, scan, body.sha256, p.actor)
    except sandbox.SandboxError as exc:
        raise HTTPException(400, str(exc)) from None
    db.commit()
    return to_dict(sub)
