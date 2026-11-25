"""Cross-tenant Microsoft 365 bulk and scheduled actions (M365-30)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import m365_bulk as bulk
from .. import m365_standards, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth
from ..models import M365BulkItem, M365BulkJob
from ..serialize import to_dict

router = APIRouter(prefix="/api/console/m365/bulk-jobs", tags=["Microsoft 365 bulk actions"])


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    connectionId: str = Field(min_length=1, max_length=32)
    targetId: str = Field(default="", max_length=64)
    label: str = Field(default="", max_length=300)


class Draft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: str
    parameters: dict = Field(default_factory=dict)
    targets: list[Target] = Field(min_length=1, max_length=bulk.MAX_TARGETS)


class NewJob(Draft):
    name: str = Field(default="", max_length=200)
    scheduledFor: datetime | None = None
    # The technician types how many targets the job will change; a mismatch means the list changed under them.
    confirmCount: int


def _naive_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _job(db: Session, job_id: str, principal: Principal) -> M365BulkJob:
    job = db.get(M365BulkJob, job_id)
    if job is None or not bulk.visible(job, principal):
        raise HTTPException(404, "Bulk job not found")
    return job


def _out(db: Session, job: M365BulkJob, with_items: bool = False) -> dict:
    out = to_dict(job)
    out["title"] = bulk.OPERATIONS.get(job.operation, {}).get("title", job.operation)
    out["write"] = bulk.OPERATIONS.get(job.operation, {}).get("write", True)
    if with_items:
        out["summary"] = bulk.summarise(db, job)
        out["items"] = [to_dict(i) for i in bulk.items(db, job)]
    return out


@router.get("/operations")
def operations(principal: Principal = Depends(current_principal)):
    principal.require("configure")
    return {"operations": [{"key": k, **{x: v[x] for x in ("title", "target", "write", "permission")}} for k, v in bulk.OPERATIONS.items()],
            "standards": [{"key": k, "title": m365_standards.display_name(k)} for k in m365_standards.STANDARDS]}


@router.post("/preview")
def preview(body: Draft, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Which targets a job would use and which it would leave out, and why. Nothing is written."""
    ratelimit.check(f"m365-bulk-preview:{principal.user.id}", 30, 300)
    try:
        parameters = bulk.validate_parameters(body.operation, body.parameters)
        eligible, excluded = bulk.check_targets(db, principal, body.operation, [t.model_dump() for t in body.targets])
    except bulk.BulkError as exc:
        raise HTTPException(400, str(exc)) from None
    return {"operation": body.operation, "parameters": parameters, "eligible": eligible, "excluded": excluded,
            "tenants": sorted({t["tenantId"] for t in eligible}), "write": bulk.OPERATIONS[body.operation]["write"]}


@router.post("")
def create(body: NewJob, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    if principal.credential_id:
        raise HTTPException(403, "Bulk jobs are created by a signed-in technician")
    if body.operation in bulk.OPERATIONS and bulk.OPERATIONS[body.operation]["write"]:
        require_reauth(request, principal)
    ratelimit.check(f"m365-bulk-create:{principal.user.id}", 10, 300)
    scheduled = _naive_utc(body.scheduledFor)
    if scheduled and scheduled > datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=90):
        raise HTTPException(400, "Schedule a job at most 90 days ahead")
    try:
        bulk.validate_parameters(body.operation, body.parameters)
        eligible, _ = bulk.check_targets(db, principal, body.operation, [t.model_dump() for t in body.targets])
        if body.confirmCount != len(eligible):
            raise HTTPException(409, f"Type the number of targets the job will use ({len(eligible)}) to confirm")
        job = bulk.create(db, principal, body.name, body.operation, body.parameters, [t.model_dump() for t in body.targets], scheduled)
    except bulk.BulkError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from None
    db.commit()
    return _out(db, job, with_items=True)


@router.get("")
def list_jobs(status: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    query = select(M365BulkJob).order_by(M365BulkJob.created_at.desc()).limit(500)
    if status:
        query = query.where(M365BulkJob.status == status)
    return [_out(db, j) for j in db.scalars(query) if bulk.visible(j, principal)][:200]


@router.get("/{job_id}")
def get_job(job_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    return _out(db, _job(db, job_id, principal), with_items=True)


@router.post("/{job_id}/run")
def run(job_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Work on the job now for up to RUN_BUDGET seconds; call again while ``more`` is true. The scheduler also runs it."""
    job = _job(db, job_id, principal)
    principal.require(bulk.OPERATIONS[job.operation]["permission"])
    ratelimit.check(f"m365-bulk-run:{principal.user.id}", 60, 300)
    if job.status == "scheduled":
        raise HTTPException(409, "This job is scheduled; it starts by itself at the scheduled time")
    outcome = bulk.run(db, job, principal.actor)
    return {**outcome, "job": _out(db, job, with_items=True)}


@router.post("/{job_id}/cancel")
def cancel(job_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    job = _job(db, job_id, principal)
    principal.require(bulk.OPERATIONS[job.operation]["permission"])
    try:
        bulk.cancel(db, job, principal.actor)
    except bulk.BulkError as exc:
        raise HTTPException(409, str(exc)) from None
    return _out(db, job, with_items=True)


@router.post("/{job_id}/reconcile")
def reconcile(job_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    job = _job(db, job_id, principal)
    principal.require(bulk.OPERATIONS[job.operation]["permission"])
    ratelimit.check(f"m365-bulk-reconcile:{principal.user.id}", 10, 300)
    outcome = bulk.reconcile(db, job, principal.actor)
    return {**outcome, "job": _out(db, job, with_items=True)}


class Resolution(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: Literal["succeeded", "failed", "retry"]


@router.post("/{job_id}/items/{item_id}/resolve")
def resolve(job_id: str, item_id: str, body: Resolution, request: Request, principal: Principal = Depends(current_principal),
            db: Session = Depends(get_db)):
    job = _job(db, job_id, principal)
    principal.require(bulk.OPERATIONS[job.operation]["permission"])
    item = db.get(M365BulkItem, item_id)
    if item is None or item.job_id != job.id:
        raise HTTPException(404, "Item not found")
    if body.outcome == "retry" and bulk.OPERATIONS[job.operation]["write"]:
        require_reauth(request, principal)
    try:
        bulk.resolve(db, job, item, body.outcome, principal.actor)
    except bulk.BulkError as exc:
        raise HTTPException(409, str(exc)) from None
    return _out(db, job, with_items=True)
