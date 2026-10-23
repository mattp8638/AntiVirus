"""Backup oversight and audited recovery exercises; provider execution stays external."""
from datetime import datetime, timedelta, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import select, func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .. import audit, events
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth, scoped_tenant
from ..models import BackupPlan, BackupRun, RecoveryExercise, Configuration, KbArticle, utcnow
from ..serialize import to_dict
from .documentation import owned

router = APIRouter(prefix="/api/console/backup", tags=["Backup and disaster recovery"])

def utc(value):
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value

class PlanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    name: str = Field(min_length=1, max_length=200)
    provider: str = Field(min_length=1, max_length=100)
    configurationId: str | None = None
    runbookId: str | None = None
    rpoHours: int = Field(default=24, ge=1, le=8760)
    rtoMinutes: int = Field(default=240, ge=1, le=43200)

class RunInput(BaseModel):
    externalId: str = Field(min_length=1, max_length=200)
    status: Literal["success", "failed"]
    completedAt: datetime
    bytesProtected: int = Field(default=0, ge=0, le=9223372036854775807)
    evidence: str = Field(default="", max_length=20000)

class ExerciseInput(BaseModel):
    target: str = Field(min_length=1, max_length=500)

class ExerciseUpdate(BaseModel):
    status: Literal["approved", "completed", "failed", "cancelled"]
    evidence: str = Field(default="", max_length=20000)
    durationMinutes: int | None = Field(default=None, ge=0, le=43200)

def plan_summary(db, row):
    last = db.scalar(select(func.max(BackupRun.completed_at)).where(BackupRun.plan_id == row.id, BackupRun.status == "success"))
    latest = db.scalars(select(BackupRun).where(BackupRun.plan_id == row.id).order_by(BackupRun.completed_at.desc()).limit(1)).first()
    health = "unknown" if last is None else ("stale" if last < utcnow() - timedelta(hours=row.rpo_hours) else "protected")
    if latest and latest.status == "failed":
        health = "failed"
    return {**to_dict(row), "health": health, "lastSuccessAt": last.isoformat() + "Z" if last else None}

@router.get("/plans")
def plans(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    return [plan_summary(db, row) for row in db.scalars(select(BackupPlan).where(BackupPlan.tenant_id.in_(scoped_tenant(principal, tenant_id))).limit(2000))]

@router.post("/plans")
def create(body: PlanInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    principal.check_tenant(body.tenantId)
    if body.configurationId:
        config = db.get(Configuration, body.configurationId)
        if config is None or config.account_tenant_id != body.tenantId:
            raise HTTPException(404, "Configuration not found in this tenant")
    if body.runbookId:
        doc = owned(db, KbArticle, body.runbookId, principal)
        if doc.tenant_id != body.tenantId:
            raise HTTPException(400, "Runbook must belong to the same customer")
    row = BackupPlan(tenant_id=body.tenantId, name=body.name, provider=body.provider, configuration_id=body.configurationId,
                     runbook_id=body.runbookId, rpo_hours=body.rpoHours, rto_minutes=body.rtoMinutes)
    db.add(row)
    db.flush()
    audit.record(db, principal.actor, "backup.plan_created", row.id, row.tenant_id)
    db.commit()
    return plan_summary(db, row)

@router.get("/plans/{plan_id}/runs")
def runs(plan_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    plan = owned(db, BackupPlan, plan_id, principal)
    return [to_dict(row) for row in db.scalars(select(BackupRun).where(BackupRun.plan_id == plan.id).order_by(BackupRun.completed_at.desc()).limit(500))]

@router.post("/plans/{plan_id}/runs")
def report(plan_id: str, body: RunInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    plan = owned(db, BackupPlan, plan_id, principal)
    when = utc(body.completedAt)
    if when > utcnow() + timedelta(minutes=5):
        raise HTTPException(400, "Completion time cannot be in the future")
    existing = db.scalar(select(BackupRun).where(BackupRun.plan_id == plan.id, BackupRun.external_id == body.externalId))
    if existing:
        if existing.status != body.status or existing.completed_at != when or existing.evidence != body.evidence or existing.bytes_protected != body.bytesProtected:
            raise HTTPException(409, "Run ID already exists with different results")
        return to_dict(existing)
    row = BackupRun(plan_id=plan.id, tenant_id=plan.tenant_id, external_id=body.externalId, status=body.status,
                    completed_at=when, bytes_protected=body.bytesProtected, evidence=body.evidence, recorded_by=principal.actor)
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Run ID already exists; retry to read the recorded result")
    audit.record(db, principal.actor, "backup.run_recorded", row.id, row.tenant_id, status=row.status)
    events.publish(db, "backup." + row.status, {"planId": plan.id, "runId": row.id}, row.tenant_id, key="backup:" + row.id)
    db.commit()
    return to_dict(row)

@router.get("/exercises")
def exercises(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    return [to_dict(row) for row in db.scalars(select(RecoveryExercise).where(RecoveryExercise.tenant_id.in_(scoped_tenant(principal, tenant_id))).order_by(RecoveryExercise.created_at.desc()).limit(1000))]

@router.post("/plans/{plan_id}/exercises")
def request_exercise(plan_id: str, body: ExerciseInput, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    plan = owned(db, BackupPlan, plan_id, principal)
    require_reauth(request, principal)
    row = RecoveryExercise(plan_id=plan.id, tenant_id=plan.tenant_id, requested_by=principal.actor, target=body.target)
    db.add(row)
    db.flush()
    audit.record(db, principal.actor, "recovery.requested", row.id, row.tenant_id)
    db.commit()
    return to_dict(row)

@router.patch("/exercises/{exercise_id}")
def update_exercise(exercise_id: str, body: ExerciseUpdate, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = owned(db, RecoveryExercise, exercise_id, principal)
    require_reauth(request, principal)
    # Lock before inspecting state so concurrent approvals cannot reopen a finished exercise.
    db.execute(update(RecoveryExercise).where(RecoveryExercise.id == row.id).values(status=RecoveryExercise.status))
    db.refresh(row)
    transitions = {"requested": {"approved", "cancelled"}, "approved": {"completed", "failed", "cancelled"}}
    if body.status not in transitions.get(row.status, set()):
        raise HTTPException(409, "Invalid recovery exercise transition")
    if body.status in {"completed", "failed"} and (not body.evidence.strip() or body.durationMinutes is None):
        raise HTTPException(400, "A finished exercise needs evidence and an actual duration")
    row.status = body.status
    if body.status == "approved":
        row.approved_by = principal.actor
    if body.status in {"completed", "failed"}:
        row.evidence, row.duration_minutes, row.completed_at = body.evidence, body.durationMinutes, utcnow()
    audit.record(db, principal.actor, "recovery." + row.status, row.id, row.tenant_id)
    db.commit()
    plan = db.get(BackupPlan, row.plan_id)
    return {**to_dict(row), "rtoMet": row.status == "completed" and row.duration_minutes <= plan.rto_minutes}
