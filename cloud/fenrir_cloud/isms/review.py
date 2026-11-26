"""Management review (ISO 27001 9.3).

Ported from the standalone app's ``packages/programme/src/review.ts``. The pack is built from live data and covers
every required input (``domain/review.py``); recording the meeting builds it one last time and freezes it with the
minutes and decisions (guard in ``models.py``). Actions are tracked afterwards and feed the next review's first input.
Every change is audited.
"""

from __future__ import annotations

from datetime import date

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..models import AuditLog, User, utcnow
from .domain._js import iso_instant, js_trim
from .domain.review import REVIEW_INPUTS, missing_inputs, review_period_start
from .models import (IsmsAudit, IsmsAuditCheck, IsmsContextIssue, IsmsInterestedParty, IsmsManagementReview,
                     IsmsReviewAction, IsmsRiskSnapshot)


def _error(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status, message)


def _day(value, message: str) -> date:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        raise _error(message) from None


def _names(db: Session, ids) -> dict[str, str]:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return {u.id: (u.name or u.email) for u in db.execute(select(User).where(User.id.in_(ids))).scalars()}


def _register_changes(db: Session, tenant_id: str, model, since: date) -> dict:
    """Additions, changes and removals in a context register since the period start, from the audit log."""
    words = {"isms.register_added": "added", "isms.register_updated": "changed", "isms.register_deleted": "removed"}
    events = db.execute(select(AuditLog).where(AuditLog.tenant_id == tenant_id, AuditLog.action.in_(words),
                                               AuditLog.at >= since).order_by(AuditLog.seq)).scalars()
    current = {r.id: r for r in db.execute(select(model).where(model.tenant_id == tenant_id)).scalars()}
    changes = []
    for e in events:
        d = e.details or {}
        if d.get("table") != model.__tablename__:
            continue
        row = current.get(d.get("id"))
        text = d.get("text") or (getattr(row, "description", None) or getattr(row, "name", "") if row else "")
        changes.append({"action": words[e.action], "text": text, "at": iso_instant(e.at)})
    return {"current": len(current), "changes": changes}


def build_pack(db: Session, tenant_id: str, period_start: date, feedback: str = "",
               exclude_review_id: str | None = None) -> dict:
    """The review pack for the period from ``period_start`` to today."""
    from . import audits, management, programme, risk_register

    today = utcnow().date()
    since = period_start.isoformat()

    def in_period(d: str | None) -> bool:
        return bool(d) and d[:10] >= since

    held = {r.id: r for r in db.execute(select(IsmsManagementReview).where(
        IsmsManagementReview.tenant_id == tenant_id, IsmsManagementReview.status == "held")).scalars()
        if r.id != exclude_review_id}
    prev = [a for a in db.execute(select(IsmsReviewAction).where(IsmsReviewAction.review_id.in_(held))).scalars()
            if a.done_at is None or a.done_at.date() >= period_start] if held else []
    prev.sort(key=lambda a: (held[a.review_id].held_on, a.due_on))
    names = _names(db, [a.owner_user_id for a in prev])
    ncs = management.nonconformity_rows(db, tenant_id, "all")
    objectives = management.objective_rows(db, tenant_id)
    active = [o for o in objectives if o["status"] == "active"]
    options = {f["framework"]: f["name"] for f in programme.framework_options(db, tenant_id)}
    readiness = [{"framework": options.get(r["framework"], r["framework"]), "score": r["score"], "met": r["met"],
                  "applicable": r["applicable"]} for r in programme.readiness(db, tenant_id)]
    programmes = audits.programme_rows(db, tenant_id)
    completed = []
    for a in db.execute(select(IsmsAudit).where(IsmsAudit.tenant_id == tenant_id, IsmsAudit.status == "completed",
                                                IsmsAudit.completed_at >= period_start)
                        .order_by(IsmsAudit.completed_at)).scalars():
        results = [c.result for c in db.execute(select(IsmsAuditCheck).where(IsmsAuditCheck.audit_id == a.id)).scalars()]
        completed.append({"ref": a.ref, "title": a.title, "completedAt": iso_instant(a.completed_at),
                          "minor": results.count("minor"), "major": results.count("major"),
                          "observation": results.count("observation")})
    risks = [r for r in risk_register.risk_views(db, tenant_id) if r["status"] != "closed"]

    def score(r: dict):
        return r["residualScore"] if r["residualScore"] is not None else r["inherentScore"]

    last_snap = db.execute(select(func.max(IsmsRiskSnapshot.taken_at)).where(
        IsmsRiskSnapshot.tenant_id == tenant_id)).scalar()
    return {
        "builtAt": iso_instant(utcnow()), "periodStart": since, "periodEnd": today.isoformat(),
        "inputs": {
            "previous_actions": {
                "open": sum(1 for a in prev if a.done_at is None), "done": sum(1 for a in prev if a.done_at),
                "items": [{"review": held[a.review_id].ref, "description": a.description,
                           "owner": names.get(a.owner_user_id), "dueOn": a.due_on.isoformat(),
                           "done": a.done_at is not None} for a in prev]},
            "issue_changes": _register_changes(db, tenant_id, IsmsContextIssue, period_start),
            "party_changes": _register_changes(db, tenant_id, IsmsInterestedParty, period_start),
            "nonconformities": {
                "raised": sum(1 for n in ncs if n["kind"] == "nonconformity" and in_period(n["raisedOn"])),
                "closed": sum(1 for n in ncs if n["kind"] == "nonconformity" and n["status"] == "closed"
                              and in_period(n["closedAt"])),
                "open": sum(1 for n in ncs if n["kind"] == "nonconformity" and n["status"] == "open"),
                "majorOpen": sum(1 for n in ncs if n["status"] == "open" and n["severity"] == "major"),
                "overdue": sum(1 for n in ncs if n["overdue"]),
                "items": [{"ref": n["ref"], "title": n["title"], "status": n["status"], "severity": n["severity"]}
                          for n in ncs if n["kind"] == "nonconformity" and (
                              n["status"] == "open" or in_period(n["raisedOn"]) or in_period(n["closedAt"]))]},
            "monitoring": {
                "readiness": readiness,
                "objectives": [{"ref": o["ref"], "title": o["title"],
                                "latest": o["summary"]["latest"]["value"] if o["summary"]["latest"] else None,
                                "target": o["target"], "unit": o["unit"], "health": o["summary"]["health"],
                                "trend": o["summary"]["trend"]} for o in active]},
            "audits": {
                "completed": completed,
                "planned": sum(1 for p in programmes for a in p["audits"] if a["status"] != "completed"),
                "coverage": [{"programme": p["title"], "percent": p["coverage"]["percent"]}
                             for p in programmes if p["periodEnd"] >= since]},
            "objectives": {
                "met": sum(1 for o in active if o["summary"]["health"] == "met"),
                "notMet": sum(1 for o in active if o["summary"]["health"] == "not_met"),
                "noData": sum(1 for o in active if o["summary"]["health"] == "no_data"),
                "achieved": sum(1 for o in objectives if o["status"] == "achieved"),
                "dropped": sum(1 for o in objectives if o["status"] == "retired")},
            "party_feedback": {
                "notes": feedback,
                "complaints": [{"ref": n["ref"], "title": n["title"], "status": n["status"]} for n in ncs
                               if n["source"] == "complaint" and (n["status"] == "open" or in_period(n["raisedOn"]))]},
            "risk": {
                "total": len(risks),
                "aboveAppetite": sum(1 for r in risks if score(r) is not None and not r["withinAppetite"]),
                "awaitingAcceptance": sum(1 for r in risks if r["treatment"] and not r["acceptance"]),
                "accepted": sum(1 for r in risks if r["acceptance"]),
                "reviewOverdue": sum(1 for r in risks if r["reviewOverdue"]),
                "lastSnapshot": iso_instant(last_snap) if last_snap else None,
                "top": [{"ref": r["ref"], "title": r["title"], "score": score(r), "withinAppetite": r["withinAppetite"]}
                        for r in sorted(risks, key=lambda r: -(score(r) or 0))[:5]]},
            "opportunities": {"open": [{"ref": n["ref"], "title": n["title"]} for n in ncs
                                       if n["kind"] == "opportunity" and n["status"] == "open"]},
        },
    }


# Reviews ----------------------------------------------------------------------------------------------------------

def review_rows(db: Session, tenant_id: str, review_id: str | None = None) -> list[dict]:
    q = select(IsmsManagementReview).where(IsmsManagementReview.tenant_id == tenant_id)
    if review_id:
        q = q.where(IsmsManagementReview.id == review_id)
    rows = db.execute(q.order_by(IsmsManagementReview.planned_on.desc(), IsmsManagementReview.ref.desc())).scalars().all()
    actions: dict[str, list[IsmsReviewAction]] = {}
    if rows:
        for a in db.execute(select(IsmsReviewAction).where(IsmsReviewAction.review_id.in_([r.id for r in rows]))
                            .order_by(IsmsReviewAction.due_on, IsmsReviewAction.created_at)).scalars():
            actions.setdefault(a.review_id, []).append(a)
    names = _names(db, [r.chair_user_id for r in rows] + [r.recorded_by_user_id for r in rows] +
                   [a.owner_user_id for acts in actions.values() for a in acts])
    today = utcnow().date()
    return [{
        "id": r.id, "ref": r.ref, "title": r.title, "plannedOn": r.planned_on.isoformat(),
        "periodStart": r.period_start.isoformat(), "status": r.status, "pack": r.pack,
        "packBuiltAt": iso_instant(r.pack_built_at) if r.pack_built_at else None,
        "missing": missing_inputs(r.pack["inputs"]) if r.pack else [],
        "interestedPartyFeedback": r.interested_party_feedback,
        "heldOn": r.held_on.isoformat() if r.held_on else None, "chairId": r.chair_user_id,
        "chairName": names.get(r.chair_user_id), "attendees": r.attendees, "minutes": r.minutes,
        "decisions": r.decisions, "changesNeeded": r.changes_needed,
        "recordedAt": iso_instant(r.recorded_at) if r.recorded_at else None,
        "recordedByName": names.get(r.recorded_by_user_id),
        "actions": [{"id": a.id, "description": a.description, "ownerId": a.owner_user_id,
                     "ownerName": names.get(a.owner_user_id), "dueOn": a.due_on.isoformat(),
                     "doneAt": iso_instant(a.done_at) if a.done_at else None, "doneNote": a.done_note,
                     "overdue": a.done_at is None and a.due_on < today} for a in actions.get(r.id, [])],
    } for r in rows]


def inputs() -> list[dict]:
    return [dict(i) for i in REVIEW_INPUTS]


def create_review(db: Session, tenant_id: str, actor: str, data: dict) -> IsmsManagementReview:
    title = js_trim(str(data.get("title") or ""))
    if len(title) < 3:
        raise _error("Give the review a title.")
    planned = _day(data.get("plannedOn"), "Enter the planned date.")
    last = db.execute(select(func.max(IsmsManagementReview.held_on)).where(
        IsmsManagementReview.tenant_id == tenant_id, IsmsManagementReview.status == "held")).scalar()
    refs = db.execute(select(IsmsManagementReview.ref).where(IsmsManagementReview.tenant_id == tenant_id)).scalars()
    n = max((int(r[3:]) for r in refs if r[3:].isdigit()), default=0) + 1
    start = review_period_start(planned.isoformat(), last.isoformat() if last else None)
    row = IsmsManagementReview(tenant_id=tenant_id, ref=f"MR-{n:03d}", title=title[:200], planned_on=planned,
                               period_start=date.fromisoformat(start), updated_by=actor)
    db.add(row)
    db.flush()
    audit.record(db, actor, "isms.review_planned", row.ref, tenant_id, id=row.id, planned_on=planned.isoformat())
    return row


def _draft(row: IsmsManagementReview) -> None:
    if row.status != "draft":
        raise _error("This review has been held and is frozen.")


def refresh_pack(db: Session, row: IsmsManagementReview, actor: str, feedback: str | None = None) -> None:
    _draft(row)
    notes = js_trim(feedback if feedback is not None else row.interested_party_feedback)[:8000]
    row.pack = build_pack(db, row.tenant_id, row.period_start, notes, row.id)
    row.pack_built_at, row.interested_party_feedback, row.updated_by = utcnow(), notes, actor
    audit.record(db, actor, "isms.review_pack_built", row.ref, row.tenant_id, id=row.id)


def record_meeting(db: Session, row: IsmsManagementReview, actor: str, user_id: str, data: dict,
                   members: set[str]) -> None:
    """Records the meeting: the pack is rebuilt one last time and frozen with the minutes and decisions."""
    _draft(row)
    held = _day(data.get("heldOn"), "Enter the date the review was held (not in the future).")
    if held > utcnow().date():
        raise _error("Enter the date the review was held (not in the future).")
    attendees, minutes = js_trim(str(data.get("attendees") or "")), js_trim(str(data.get("minutes") or ""))
    decisions = js_trim(str(data.get("decisions") or ""))
    if not attendees:
        raise _error("List who attended.")
    if not minutes:
        raise _error("Record the minutes.")
    if not decisions:
        raise _error("Record the decisions on improvement and any changes needed to the ISMS.")
    chair = data.get("chairId") or None
    if chair and chair not in members:
        raise _error("The chair must have an ISMS role in this customer.")
    pack = build_pack(db, row.tenant_id, row.period_start, row.interested_party_feedback, row.id)
    missing = missing_inputs(pack["inputs"])
    if missing:
        raise _error(f"The pack is missing inputs: {', '.join(missing)}.")
    row.pack, row.pack_built_at, row.held_on, row.chair_user_id = pack, utcnow(), held, chair
    row.attendees, row.minutes, row.decisions = attendees[:4000], minutes[:20000], decisions[:8000]
    row.changes_needed = js_trim(str(data.get("changesNeeded") or ""))[:8000]
    row.recorded_at, row.recorded_by_user_id, row.status, row.updated_by = utcnow(), user_id, "held", actor
    audit.record(db, actor, "isms.review_held", row.ref, row.tenant_id, id=row.id, held_on=held.isoformat())
    from .notify import emit
    emit(db, row.tenant_id, "isms.review_held", id=row.id, ref=row.ref, title=row.title, heldOn=held.isoformat())


def add_action(db: Session, row: IsmsManagementReview, actor: str, data: dict, members: set[str]) -> IsmsReviewAction:
    description = js_trim(str(data.get("description") or ""))
    if len(description) < 3:
        raise _error("Describe the action.")
    due = _day(data.get("dueOn"), "Enter a due date.")
    owner = data.get("ownerId") or None
    if owner and owner not in members:
        raise _error("The owner must have an ISMS role in this customer.")
    a = IsmsReviewAction(tenant_id=row.tenant_id, review_id=row.id, description=description[:2000],
                         owner_user_id=owner, due_on=due, updated_by=actor)
    db.add(a)
    db.flush()
    audit.record(db, actor, "isms.review_action_added", row.ref, row.tenant_id, id=a.id, owner=owner)
    return a


def complete_action(db: Session, a: IsmsReviewAction, actor: str, user_id: str, note: str) -> None:
    if a.done_at is not None:
        return
    a.done_at, a.done_by_user_id, a.done_note, a.updated_by = utcnow(), user_id, js_trim(note)[:4000] or None, actor
    audit.record(db, actor, "isms.review_action_done", a.id, a.tenant_id, review_id=a.review_id)


def delete_review(db: Session, row: IsmsManagementReview, actor: str) -> None:
    _draft(row)
    for a in db.execute(select(IsmsReviewAction).where(IsmsReviewAction.review_id == row.id)).scalars():
        db.delete(a)
    db.flush()
    db.delete(row)
    audit.record(db, actor, "isms.review_deleted", row.ref, row.tenant_id, id=row.id)
