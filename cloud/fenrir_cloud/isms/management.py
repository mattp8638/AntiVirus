"""Improvement (ISO 27001 10.1, 10.2), objectives and metrics (6.2, 9.1) and the ISMS change log (6.3).

Workflow rules come from the pure functions in ``domain/improvement.py`` and ``domain/objectives.py``. Nonconformities
are never deleted: they close through an effectiveness check (improvement opportunities with a note) or are cancelled.
Every change is audited.
"""

from __future__ import annotations

import math
import re
from datetime import date

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..models import User, utcnow
from .domain._js import js_trim
from .domain.improvement import NC_STAGE_TEXT, NcState, effectiveness_blockers, nc_stage
from .domain.objectives import Measurement, summarize_objective
from .models import IsmsChange, IsmsCorrectiveAction, IsmsMetricValue, IsmsNonconformity, IsmsObjective

NC_SOURCES = ("internal_audit", "external_audit", "incident", "management_review", "monitoring", "complaint", "other")
FREQUENCIES = ("monthly", "quarterly", "six-monthly", "annual")
CHANGE_STATUSES = ("planned", "in_progress", "done", "cancelled")


def _error(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status, message)


def _date(value, what: str, required: bool = False) -> date | None:
    if not value:
        if required:
            raise _error(f"Enter {what}.")
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        raise _error(f"Enter {what}.") from None


def _member(owner: str | None, members: set[str]) -> str | None:
    if owner and owner not in members:
        raise _error("The owner must be an active member of this organization.")
    return owner or None


def _names(db: Session, ids) -> dict[str, str]:
    ids = {i for i in ids if i}
    return {u.id: (u.name or u.email) for u in db.execute(select(User).where(User.id.in_(ids))).scalars()} if ids else {}


def _next_ref(db: Session, model, tenant_id: str, prefix: str) -> str:
    refs = db.execute(select(model.ref).where(model.tenant_id == tenant_id)).scalars()
    n = max((int(r.split("-")[1]) for r in refs if re.fullmatch(rf"{prefix}-\d+", r)), default=0) + 1
    return f"{prefix}-{n:03d}"


# Improvement ------------------------------------------------------------------------------------------------

def _actions(db: Session, nc_ids: list[str]) -> dict[str, list[IsmsCorrectiveAction]]:
    out: dict[str, list[IsmsCorrectiveAction]] = {}
    if nc_ids:
        for a in db.execute(select(IsmsCorrectiveAction).where(IsmsCorrectiveAction.nonconformity_id.in_(nc_ids))
                            .order_by(IsmsCorrectiveAction.due_on, IsmsCorrectiveAction.id)).scalars():
            out.setdefault(a.nonconformity_id, []).append(a)
    return out


def nonconformity_rows(db: Session, tenant_id: str, status: str = "open", nc_id: str | None = None) -> list[dict]:
    q = select(IsmsNonconformity).where(IsmsNonconformity.tenant_id == tenant_id)
    if status != "all":
        q = q.where(IsmsNonconformity.status == status)
    if nc_id:
        q = q.where(IsmsNonconformity.id == nc_id)
    rows = list(db.execute(q.order_by(IsmsNonconformity.raised_on.desc(), IsmsNonconformity.ref.desc())).scalars())
    actions = _actions(db, [r.id for r in rows])
    names = _names(db, [r.owner_user_id for r in rows] + [a.owner_user_id for v in actions.values() for a in v])
    today = utcnow().date()
    out = []
    for r in rows:
        acts = actions.get(r.id, [])
        stage = nc_stage(NcState(r.kind, r.status, r.root_cause), [a.done_at is not None for a in acts])
        out.append({
            "id": r.id, "ref": r.ref, "kind": r.kind, "title": r.title, "description": r.description, "source": r.source,
            "severity": r.severity, "requirementRef": r.requirement_ref, "raisedOn": r.raised_on.isoformat(),
            "ownerId": r.owner_user_id, "ownerName": names.get(r.owner_user_id), "correction": r.correction,
            "rootCause": r.root_cause, "dueOn": r.due_on.isoformat() if r.due_on else None, "status": r.status,
            "stage": stage, "stageText": NC_STAGE_TEXT[stage],
            "overdue": bool(r.status == "open" and r.due_on and r.due_on < today),
            "effective": r.effective, "effectivenessNote": r.effectiveness_note, "closureNote": r.closure_note,
            "closedAt": r.closed_at.isoformat() + "Z" if r.closed_at else None,
            "blockers": effectiveness_blockers(NcState(r.kind, r.status, r.root_cause),
                                               [a.done_at is not None for a in acts]),
            "actions": [{"id": a.id, "description": a.description, "ownerId": a.owner_user_id,
                         "ownerName": names.get(a.owner_user_id), "dueOn": a.due_on.isoformat(),
                         "done": a.done_at is not None, "doneNote": a.done_note,
                         "overdue": a.done_at is None and a.due_on < today} for a in acts]})
    return out


def _nc_values(data: dict, members: set[str], kind: str) -> dict:
    title = js_trim(str(data.get("title") or ""))
    if not 3 <= len(title) <= 200:
        raise _error("Give it a title of 3 to 200 characters.")
    source = data.get("source")
    if source not in NC_SOURCES:
        raise _error("Choose where it came from.")
    severity = data.get("severity")
    if kind == "nonconformity" and severity not in ("minor", "major"):
        raise _error("Choose minor or major for a nonconformity.")
    return {"title": title, "description": js_trim(str(data.get("description") or ""))[:8000], "source": source,
            "severity": severity if kind == "nonconformity" else None,
            "requirement_ref": js_trim(str(data.get("requirementRef") or ""))[:80] or None,
            "owner_user_id": _member(data.get("ownerId"), members),
            "correction": js_trim(str(data.get("correction") or ""))[:8000],
            "root_cause": js_trim(str(data.get("rootCause") or ""))[:8000],
            "due_on": _date(data.get("dueOn"), "a valid target date")}


def raise_nc(db: Session, tenant_id: str, actor: str, user_id: str, data: dict, members: set[str],
             audit_finding_id: str | None = None) -> IsmsNonconformity:
    kind = data.get("kind") or "nonconformity"
    if kind not in ("nonconformity", "opportunity"):
        raise _error("Choose a nonconformity or an improvement opportunity.")
    values = _nc_values(data, members, kind)
    row = IsmsNonconformity(tenant_id=tenant_id, kind=kind,
                            ref=_next_ref(db, IsmsNonconformity, tenant_id, "NC" if kind == "nonconformity" else "OFI"),
                            raised_on=utcnow().date(), raised_by_user_id=user_id, audit_finding_id=audit_finding_id,
                            updated_by=actor, **values)
    db.add(row)
    db.flush()
    audit.record(db, actor, "isms.nonconformity_raised", row.ref, tenant_id, id=row.id, kind=kind,
                 severity=row.severity)
    from .notify import emit
    emit(db, tenant_id, "isms.nonconformity_raised", id=row.id, ref=row.ref, kind=kind, severity=row.severity,
         source=row.source, title=row.title)
    return row


def _open(row: IsmsNonconformity) -> None:
    if row.status != "open":
        raise _error(f"{row.ref} is {row.status} and cannot change.")


def update_nc(db: Session, row: IsmsNonconformity, actor: str, data: dict, members: set[str]) -> None:
    _open(row)
    for k, v in _nc_values(data, members, row.kind).items():
        setattr(row, k, v)
    row.updated_at, row.updated_by = utcnow(), actor
    audit.record(db, actor, "isms.nonconformity_updated", row.ref, row.tenant_id, id=row.id)


def add_action(db: Session, row: IsmsNonconformity, actor: str, data: dict, members: set[str]) -> IsmsCorrectiveAction:
    _open(row)
    if row.kind == "opportunity":
        raise _error("Improvement opportunities do not take corrective actions.")
    description = js_trim(str(data.get("description") or ""))
    if len(description) < 3:
        raise _error("Describe the action.")
    a = IsmsCorrectiveAction(tenant_id=row.tenant_id, nonconformity_id=row.id, description=description[:2000],
                             owner_user_id=_member(data.get("ownerId"), members),
                             due_on=_date(data.get("dueOn"), "a due date", required=True), updated_by=actor)
    db.add(a)
    db.flush()
    audit.record(db, actor, "isms.corrective_action_added", row.ref, row.tenant_id, id=a.id)
    return a


def complete_action(db: Session, a: IsmsCorrectiveAction, actor: str, user_id: str, note: str) -> None:
    nc = db.get(IsmsNonconformity, a.nonconformity_id)
    _open(nc)
    if a.done_at is not None:
        raise _error("That action is already done.")
    a.done_at, a.done_by_user_id, a.done_note = utcnow(), user_id, js_trim(note or "")[:2000] or None
    a.updated_at, a.updated_by = utcnow(), actor
    audit.record(db, actor, "isms.corrective_action_done", nc.ref, nc.tenant_id, id=a.id)


def record_effectiveness(db: Session, row: IsmsNonconformity, actor: str, user_id: str, effective: bool,
                         note: str) -> None:
    """The effectiveness check. An effective outcome closes the nonconformity; an ineffective one keeps it open for
    more action."""
    acts = _actions(db, [row.id]).get(row.id, [])
    blockers = effectiveness_blockers(NcState(row.kind, row.status, row.root_cause), [a.done_at is not None for a in acts])
    if blockers:
        raise _error(" ".join(blockers))
    note = js_trim(note or "")
    if len(note) < 3:
        raise _error("Say how effectiveness was checked.")
    now = utcnow()
    row.effective, row.effectiveness_note, row.verified_at, row.verified_by_user_id = effective, note[:4000], now, user_id
    if effective:
        row.status, row.closed_at = "closed", now
    row.updated_at, row.updated_by = now, actor
    audit.record(db, actor, "isms.nonconformity_effectiveness", row.ref, row.tenant_id, id=row.id, effective=effective)
    if row.status == "closed":
        from .notify import emit
        emit(db, row.tenant_id, "isms.nonconformity_closed", id=row.id, ref=row.ref, kind=row.kind, outcome="effective")


def close_with_note(db: Session, row: IsmsNonconformity, actor: str, outcome: str, note: str) -> None:
    """Closes an improvement opportunity, or cancels either kind, with a note."""
    _open(row)
    note = js_trim(note or "")
    if len(note) < 3:
        raise _error("Add a note explaining the outcome.")
    if outcome == "closed" and row.kind == "nonconformity":
        raise _error("A nonconformity closes through its effectiveness check.")
    if outcome not in ("closed", "cancelled"):
        raise _error("Close or cancel.")
    row.status, row.closure_note, row.closed_at = outcome, note[:4000], utcnow()
    row.updated_at, row.updated_by = utcnow(), actor
    audit.record(db, actor, f"isms.nonconformity_{outcome}", row.ref, row.tenant_id, id=row.id)
    from .notify import emit
    emit(db, row.tenant_id, "isms.nonconformity_closed", id=row.id, ref=row.ref, kind=row.kind, outcome=outcome)


# Objectives -------------------------------------------------------------------------------------------------

def objective_rows(db: Session, tenant_id: str, obj_id: str | None = None) -> list[dict]:
    q = select(IsmsObjective).where(IsmsObjective.tenant_id == tenant_id)
    if obj_id:
        q = q.where(IsmsObjective.id == obj_id)
    rows = list(db.execute(q.order_by(IsmsObjective.ref)).scalars())
    values: dict[str, list[IsmsMetricValue]] = {}
    if rows:
        for v in db.execute(select(IsmsMetricValue).where(IsmsMetricValue.objective_id.in_([r.id for r in rows]))
                            .order_by(IsmsMetricValue.measured_on, IsmsMetricValue.id)).scalars():
            values.setdefault(v.objective_id, []).append(v)
    names = _names(db, [r.owner_user_id for r in rows])
    today = utcnow().date().isoformat()
    out = []
    for r in rows:
        vs = values.get(r.id, [])
        s = summarize_objective([Measurement(v.measured_on.isoformat(), v.value) for v in vs], r.direction, r.target,
                                r.frequency, today)
        out.append({"id": r.id, "ref": r.ref, "title": r.title, "measure": r.measure, "unit": r.unit,
                    "direction": r.direction, "target": r.target, "baseline": r.baseline, "plan": r.plan,
                    "resources": r.resources, "ownerId": r.owner_user_id, "ownerName": names.get(r.owner_user_id),
                    "frequency": r.frequency, "dueOn": r.due_on.isoformat() if r.due_on else None, "status": r.status,
                    "statusNote": r.status_note,
                    "summary": {"latest": {"measuredOn": s.latest.measured_on, "value": s.latest.value} if s.latest else None,
                                "health": s.health, "trend": s.trend, "stale": s.stale},
                    "values": [{"id": v.id, "measuredOn": v.measured_on.isoformat(), "value": v.value, "note": v.note}
                               for v in vs]})
    return out


def _number(v, what: str, required: bool = True) -> float | None:
    if v is None or v == "":
        if required:
            raise _error(f"Enter a numeric {what}.")
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise _error(f"Enter a numeric {what}.") from None
    if not math.isfinite(f) or isinstance(v, bool):
        raise _error(f"Enter a numeric {what}.")
    return f


def save_objective(db: Session, tenant_id: str, actor: str, data: dict, members: set[str],
                   row: IsmsObjective | None = None) -> IsmsObjective:
    title = js_trim(str(data.get("title") or ""))
    if not 3 <= len(title) <= 200:
        raise _error("Give the objective a title of 3 to 200 characters.")
    measure = js_trim(str(data.get("measure") or ""))
    if not measure:
        raise _error("Say how the objective is measured.")
    if data.get("direction") not in ("at_least", "at_most"):
        raise _error("Choose whether the target is a minimum or a maximum.")
    if data.get("frequency", "monthly") not in FREQUENCIES:
        raise _error("Choose how often it is measured.")
    values = {"title": title, "measure": measure[:2000], "unit": js_trim(str(data.get("unit") or ""))[:40],
              "direction": data["direction"], "target": _number(data.get("target"), "target"),
              "baseline": _number(data.get("baseline"), "baseline", required=False),
              "plan": js_trim(str(data.get("plan") or ""))[:8000],
              "resources": js_trim(str(data.get("resources") or ""))[:4000],
              "owner_user_id": _member(data.get("ownerId"), members), "frequency": data.get("frequency", "monthly"),
              "due_on": _date(data.get("dueOn"), "a valid target date")}
    if row is None:
        row = IsmsObjective(tenant_id=tenant_id, ref=_next_ref(db, IsmsObjective, tenant_id, "OBJ"), updated_by=actor,
                            **values)
        db.add(row)
        db.flush()
        audit.record(db, actor, "isms.objective_added", row.ref, tenant_id, id=row.id)
    else:
        for k, v in values.items():
            setattr(row, k, v)
        row.updated_at, row.updated_by = utcnow(), actor
        audit.record(db, actor, "isms.objective_updated", row.ref, tenant_id, id=row.id)
    return row


def record_value(db: Session, row: IsmsObjective, actor: str, data: dict) -> IsmsMetricValue:
    if row.status != "active":
        raise _error("Values are recorded on active objectives only.")
    measured = _date(data.get("measuredOn"), "the date it was measured (not in the future)", required=True)
    if measured > utcnow().date():
        raise _error("Enter the date it was measured (not in the future).")
    v = IsmsMetricValue(tenant_id=row.tenant_id, objective_id=row.id, measured_on=measured,
                        value=_number(data.get("value"), "value"), note=js_trim(str(data.get("note") or ""))[:2000],
                        updated_by=actor)
    db.add(v)
    db.flush()
    audit.record(db, actor, "isms.metric_recorded", row.ref, row.tenant_id, id=v.id, value=v.value,
                 measuredOn=measured.isoformat())
    return v


def set_objective_status(db: Session, row: IsmsObjective, actor: str, status: str, note: str) -> None:
    if status not in ("active", "achieved", "dropped"):
        raise _error("Choose active, achieved or dropped.")
    note = js_trim(note or "")
    if status != "active" and len(note) < 3:
        raise _error("Add a note explaining the decision.")
    row.status, row.status_note, row.updated_at, row.updated_by = status, note[:4000] or None, utcnow(), actor
    audit.record(db, actor, "isms.objective_status", row.ref, row.tenant_id, id=row.id, status=status)


# ISMS change log --------------------------------------------------------------------------------------------

def change_rows(db: Session, tenant_id: str) -> list[dict]:
    rows = list(db.execute(select(IsmsChange).where(IsmsChange.tenant_id == tenant_id)
                           .order_by(IsmsChange.ref.desc())).scalars())
    names = _names(db, [r.owner_user_id for r in rows])
    return [{"id": r.id, "ref": r.ref, "title": r.title, "purpose": r.purpose, "consequences": r.consequences,
             "resources": r.resources, "ownerId": r.owner_user_id, "ownerName": names.get(r.owner_user_id),
             "plannedOn": r.planned_on.isoformat() if r.planned_on else None, "status": r.status,
             "completedOn": r.completed_on.isoformat() if r.completed_on else None, "outcome": r.outcome} for r in rows]


def save_change(db: Session, tenant_id: str, actor: str, data: dict, members: set[str],
                row: IsmsChange | None = None) -> IsmsChange:
    title = js_trim(str(data.get("title") or ""))
    if len(title) < 3:
        raise _error("Give the change a title.")
    purpose = js_trim(str(data.get("purpose") or ""))
    if not purpose:
        raise _error("Say why the change is being made.")
    status = data.get("status") or "planned"
    if status not in CHANGE_STATUSES:
        raise _error("Choose a status.")
    completed = _date(data.get("completedOn"), "the date it finished")
    outcome = js_trim(str(data.get("outcome") or ""))
    if status in ("done", "cancelled") and (completed is None or not outcome):
        raise _error("Record when it finished and the outcome.")
    values = {"title": title[:200], "purpose": purpose[:8000],
              "consequences": js_trim(str(data.get("consequences") or ""))[:8000],
              "resources": js_trim(str(data.get("resources") or ""))[:4000],
              "owner_user_id": _member(data.get("ownerId"), members),
              "planned_on": _date(data.get("plannedOn"), "a valid planned date"), "status": status,
              "completed_on": completed, "outcome": outcome[:8000]}
    if row is None:
        row = IsmsChange(tenant_id=tenant_id, ref=_next_ref(db, IsmsChange, tenant_id, "CHG"), updated_by=actor, **values)
        db.add(row)
        db.flush()
        audit.record(db, actor, "isms.change_added", row.ref, tenant_id, id=row.id)
    else:
        for k, v in values.items():
            setattr(row, k, v)
        row.updated_at, row.updated_by = utcnow(), actor
        audit.record(db, actor, "isms.change_updated", row.ref, tenant_id, id=row.id, status=status)
    return row
