"""Business continuity plans and exercises (GRC-17), fenrir_cloud/continuity.py."""
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from .. import continuity as bc
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import ContinuityExercise, ContinuityPlan, DrRun, utcnow

router = APIRouter(prefix="/api/console/grc/continuity", tags=["Business continuity"])


def bad(msg: str):
    raise HTTPException(400, msg)


def _iso(d):
    return d.isoformat() if d else None


def _plan(db: Session, p: Principal, plan_id: str) -> ContinuityPlan:
    plan = db.get(ContinuityPlan, plan_id)
    if plan is None or plan.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "no such plan")
    return plan


def _out(plan: ContinuityPlan) -> dict:
    return {"id": plan.id, "tenantId": plan.tenant_id, "name": plan.name, "scope": plan.scope, "owner": plan.owner,
            "status": plan.status, "version": plan.version, "approvedVersion": plan.approved_version,
            "approvedBy": plan.approved_by, "approvedAt": _iso(plan.approved_at), "reviewDue": _iso(plan.review_due),
            "services": plan.services or [], "updatedBy": plan.updated_by, "updatedAt": _iso(plan.updated_at),
            "changedSinceApproval": plan.status == "approved" and plan.approved_version != plan.version,
            "approvedSha256": (plan.approved_snapshot or {}).get("sha256")}


def _ex_out(e: ContinuityExercise) -> dict:
    return {"id": e.id, "planId": e.plan_id, "planVersion": e.plan_version, "kind": e.kind, "title": e.title,
            "scenario": e.scenario, "heldOn": _iso(e.held_on), "participants": e.participants, "services": e.services,
            "drRunId": e.dr_run_id, "outcome": e.outcome, "results": e.results, "lessons": e.lessons,
            "actions": e.actions, "createdBy": e.created_by}


def _date(v) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(str(v).replace("Z", "")).replace(tzinfo=None)
    except ValueError:
        bad("dates are YYYY-MM-DD")


@router.get("/plans")
def list_plans(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    rows = db.execute(select(ContinuityPlan).where(ContinuityPlan.tenant_id.in_(scoped_tenant(p, tenantId)))
                      .order_by(ContinuityPlan.name)).scalars()
    return [_out(x) for x in rows]


@router.post("/plans")
def create_plan(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    tenant = str(body.get("tenantId") or "")
    p.check_tenant(tenant)
    name = str(body.get("name") or "").strip()
    if not 3 <= len(name) <= 200:
        bad("name the plan (3 to 200 characters)")
    try:
        services = bc.clean_services(body.get("services") or [], bc.runbook_ids(db, tenant))
    except ValueError as e:
        bad(str(e))
    plan = ContinuityPlan(tenant_id=tenant, name=name, scope=str(body.get("scope") or "")[:5000],
                          owner=str(body.get("owner") or "")[:200], services=services, updated_by=p.actor,
                          review_due=_date(body.get("reviewDue")))
    db.add(plan)
    db.flush()
    audit.record(db, p.actor, "grc.continuity.plan_created", plan.name, tenant, plan=plan.id, services=len(services))
    db.commit()
    return _out(plan)


@router.get("/plans/{plan_id}")
def get_plan(plan_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    return _out(_plan(db, p, plan_id))


@router.patch("/plans/{plan_id}")
def update_plan(plan_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Any change makes a new version; an approved plan keeps its approved snapshot until approved again."""
    p.require("grc")
    plan = _plan(db, p, plan_id)
    if plan.status == "retired":
        bad("the plan is retired")
    if "services" in body:
        try:
            plan.services = bc.clean_services(body["services"], bc.runbook_ids(db, plan.tenant_id))
        except ValueError as e:
            bad(str(e))
    for k, attr, n in (("scope", "scope", 5000), ("owner", "owner", 200)):
        if k in body:
            setattr(plan, attr, str(body[k] or "")[:n])
    if "reviewDue" in body:
        plan.review_due = _date(body["reviewDue"])
    plan.version += 1
    plan.updated_by, plan.updated_at = p.actor, utcnow()
    audit.record(db, p.actor, "grc.continuity.plan_updated", plan.name, plan.tenant_id, plan=plan.id, version=plan.version)
    db.commit()
    return _out(plan)


@router.post("/plans/{plan_id}/approve")
def approve_plan(plan_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    plan = _plan(db, p, plan_id)
    if not plan.services:
        bad("a plan needs at least one service before it is approved")
    plan.status, plan.approved_version = "approved", plan.version
    plan.approved_by, plan.approved_at = p.actor, utcnow()
    plan.approved_snapshot = bc.snapshot(plan)
    audit.record(db, p.actor, "grc.continuity.plan_approved", plan.name, plan.tenant_id, plan=plan.id,
                 version=plan.version, sha256=plan.approved_snapshot["sha256"])
    db.commit()
    return _out(plan)


@router.get("/plans/{plan_id}/assessment")
def assessment(plan_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    return bc.assess(db, _plan(db, p, plan_id))


@router.get("/plans/{plan_id}/exercises")
def list_exercises(plan_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    plan = _plan(db, p, plan_id)
    rows = db.execute(select(ContinuityExercise).where(ContinuityExercise.plan_id == plan.id)
                      .order_by(ContinuityExercise.held_on.desc())).scalars()
    return [_ex_out(e) for e in rows]


@router.post("/plans/{plan_id}/exercises")
def record_exercise(plan_id: str, body: dict = Body(...), p: Principal = Depends(current_principal),
                    db: Session = Depends(get_db)):
    """A tabletop exercise (outcome from the people who held it) or a technical one, whose outcome comes from a
    finished DR runbook run: each exercised service's measured recovery time against its RTO."""
    p.require("grc")
    plan = _plan(db, p, plan_id)
    kind = body.get("kind")
    if kind not in ("tabletop", "technical"):
        bad("an exercise is tabletop or technical")
    title = str(body.get("title") or "").strip()[:300]
    if not title:
        bad("give the exercise a title")
    known = {s["id"] for s in plan.services or []}
    services = [s for s in body.get("services") or [] if s in known] or sorted(known)
    ex = ContinuityExercise(tenant_id=plan.tenant_id, plan_id=plan.id, plan_version=plan.version, kind=kind,
                            title=title, scenario=str(body.get("scenario") or "")[:8000],
                            held_on=_date(body.get("heldOn")) or utcnow(),
                            participants=[str(x)[:200] for x in body.get("participants") or []][:100],
                            services=services, lessons=str(body.get("lessons") or "")[:20000], created_by=p.actor,
                            actions=[{"id": uuid.uuid4().hex[:10], "text": str(a.get("text") or "")[:1000],
                                      "owner": str(a.get("owner") or "")[:200], "due": str(a.get("due") or "")[:10],
                                      "done": False, "doneAt": None}
                                     for a in body.get("actions") or [] if isinstance(a, dict) and a.get("text")][:100])
    if kind == "technical":
        run = db.get(DrRun, str(body.get("drRunId") or ""))
        if run is None or run.tenant_id != plan.tenant_id:
            bad("a technical exercise is a DR runbook run of this customer: choose it")
        if run.state == "running":
            bad("that DR run has not finished yet")
        ex.dr_run_id = run.id
        ex.outcome, ex.results = bc.exercise_results(db, plan, run, services)
    else:
        outcome = body.get("outcome")
        if outcome not in ("passed", "partial", "failed"):
            bad("a tabletop exercise's outcome is passed, partial or failed")
        ex.outcome = outcome
    db.add(ex)
    db.flush()
    audit.record(db, p.actor, "grc.continuity.exercise_recorded", ex.title, plan.tenant_id, plan=plan.id,
                 exercise=ex.id, kind=kind, outcome=ex.outcome, dr_run=ex.dr_run_id)
    db.commit()
    return _ex_out(ex)


@router.patch("/exercises/{exercise_id}/actions/{action_id}")
def update_action(exercise_id: str, action_id: str, body: dict = Body(...), p: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    p.require("grc")
    ex = db.get(ContinuityExercise, exercise_id)
    if ex is None or ex.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "no such exercise")
    actions = [dict(a) for a in ex.actions or []]
    a = next((a for a in actions if a["id"] == action_id), None)
    if a is None:
        raise HTTPException(404, "no such action")
    if "done" in body:
        a["done"] = bool(body["done"])
        a["doneAt"] = utcnow().isoformat() if a["done"] else None
    if "owner" in body:
        a["owner"] = str(body["owner"] or "")[:200]
    ex.actions = actions
    audit.record(db, p.actor, "grc.continuity.action_updated", ex.title, ex.tenant_id, exercise=ex.id, action_id=action_id,
                 done=a["done"])
    db.commit()
    return _ex_out(ex)


@router.get("/plans/{plan_id}/report")
def report(plan_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The plan as approved, how it stands now, its exercises and open actions: one pack for a review."""
    p.require("read")
    plan = _plan(db, p, plan_id)
    exercises = db.execute(select(ContinuityExercise).where(ContinuityExercise.plan_id == plan.id)
                           .order_by(ContinuityExercise.held_on.desc())).scalars().all()
    open_actions = [{**a, "exercise": e.title} for e in exercises for a in e.actions or [] if not a.get("done")]
    return {"plan": _out(plan), "approved": plan.approved_snapshot, "assessment": bc.assess(db, plan),
            "exercises": [_ex_out(e) for e in exercises], "openActions": open_actions}
