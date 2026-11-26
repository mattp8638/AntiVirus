"""Tasks (ISO 27001 8.1: show that planned processes ran), generated from the control list:

* implement: one open task for each applicable control not yet implemented (the task plan);
* operate: one open recurring task for each implemented control with a regular test frequency;
* manual: anything else people add.

``sync_control_tasks`` is idempotent and runs after every programme or control change. ``send_reminders`` runs daily:
due within 7 days and overdue go to the assignee, and more than 14 days overdue is escalated to the customer's ISMS
administrators and managers. Each stage is sent once per task.
"""

from __future__ import annotations

from datetime import date, timedelta

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, mailer
from ..config import get_settings
from ..models import Tenant, User, utcnow
from . import library
from .domain._js import js_trim
from .domain.tasks import next_due_date, recurrence_for
from .models import IsmsEvidence, IsmsMembership, IsmsTask, IsmsTenantControl, IsmsTenantFramework

IMPLEMENTATION_DAYS = 90
ESCALATE_AFTER_DAYS = 14


def _today() -> date:
    return utcnow().date()


def _error(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status, message)


def sync_control_tasks(db: Session, tenant_id: str, actor: str = "system:isms") -> dict:
    db.flush()
    controls = list(db.execute(select(IsmsTenantControl).where(IsmsTenantControl.tenant_id == tenant_id)).scalars())
    open_tasks: dict[str, list[IsmsTask]] = {}
    for t in db.execute(select(IsmsTask).where(IsmsTask.tenant_id == tenant_id, IsmsTask.status == "open",
                                               IsmsTask.tenant_control_id.is_not(None))).scalars():
        open_tasks.setdefault(t.tenant_control_id, []).append(t)
    last_done: dict[str, date] = {}
    for t in db.execute(select(IsmsTask).where(IsmsTask.tenant_id == tenant_id, IsmsTask.kind == "operate",
                                               IsmsTask.status == "done")).scalars():
        if t.tenant_control_id not in last_done or t.due_on > last_done[t.tenant_control_id]:
            last_done[t.tenant_control_id] = t.due_on
    procedures = {ref: c.get("test_procedure") for ref, c in library.common_controls(db).items()}
    today = _today()
    now = utcnow()
    created = closed = 0
    for c in controls:
        mine = open_tasks.get(c.id, [])
        implemented = c.state in ("implemented", "implemented_evidenced")
        recurrence = recurrence_for(c.frequency)
        if c.state == "not_applicable":
            for t in mine:
                t.status, t.completion_note, t.updated_at = "cancelled", "The control no longer applies.", now
                closed += 1
            continue
        impl = next((t for t in mine if t.kind == "implement"), None)
        if not implemented and impl is None:
            db.add(IsmsTask(tenant_id=tenant_id, tenant_control_id=c.id, kind="implement",
                            title=f"Put {c.ref} in place: {c.title}"[:300],
                            description="Implement the control, describe how it works in the control assessment, "
                                        "then add evidence.",
                            assignee_user_id=c.owner_user_id, due_on=today + timedelta(days=IMPLEMENTATION_DAYS),
                            updated_by=actor))
            created += 1
        elif implemented and impl is not None:
            impl.status, impl.completed_at, impl.updated_at = "done", now, now
            impl.completion_note = "Closed automatically: the control is now implemented."
            closed += 1
        op = next((t for t in mine if t.kind == "operate"), None)
        if implemented and recurrence and op is None:
            previous = last_done.get(c.id)
            due = next_due_date(recurrence, previous.isoformat() if previous else None, today.isoformat())
            db.add(IsmsTask(tenant_id=tenant_id, tenant_control_id=c.id, kind="operate",
                            title=f"Check {c.ref}: {c.title}"[:300], description=procedures.get(c.ref),
                            assignee_user_id=c.owner_user_id, due_on=date.fromisoformat(due), recurrence=recurrence,
                            updated_by=actor))
            created += 1
        elif op is not None and (not implemented or not recurrence):
            op.status, op.completion_note, op.updated_at = "cancelled", "The control is not in operation.", now
            closed += 1
        for t in mine:  # open tasks follow the control owner
            if t.status == "open" and t.assignee_user_id != c.owner_user_id:
                t.assignee_user_id, t.updated_at = c.owner_user_id, now
    db.flush()
    if created or closed:
        audit.record(db, actor, "isms.tasks_synced", f"{created} created, {closed} closed", tenant_id,
                     created=created, closed=closed)
    return {"created": created, "closed": closed}


def task_rows(db: Session, tenant_id: str, status: str = "open", assignee: str | None = None,
              task_id: str | None = None) -> list[dict]:
    q = select(IsmsTask).where(IsmsTask.tenant_id == tenant_id)
    if status != "all":
        q = q.where(IsmsTask.status == status)
    if assignee:
        q = q.where(IsmsTask.assignee_user_id == assignee)
    if task_id:
        q = q.where(IsmsTask.id == task_id)
    rows = list(db.execute(q.limit(1000)).scalars())
    refs = {c.id: c.ref for c in db.execute(select(IsmsTenantControl).where(
        IsmsTenantControl.tenant_id == tenant_id)).scalars()}
    user_ids = {r.assignee_user_id for r in rows} | {r.completed_by_user_id for r in rows}
    names = {u.id: (u.name or u.email) for u in db.execute(select(User).where(User.id.in_(user_ids - {None}))).scalars()}
    ev_ids = [r.evidence_id for r in rows if r.evidence_id]
    evidence = {e.id: e.title for e in db.execute(select(IsmsEvidence).where(IsmsEvidence.id.in_(ev_ids))).scalars()} \
        if ev_ids else {}
    if status == "done":
        rows.sort(key=lambda r: r.completed_at or utcnow(), reverse=True)
    else:
        rows.sort(key=lambda r: (r.due_on, refs.get(r.tenant_control_id) or "~"))
    today = _today()
    from .domain.tasks import task_urgency

    return [{"id": r.id, "kind": r.kind, "title": r.title, "description": r.description,
             "controlId": r.tenant_control_id, "controlRef": refs.get(r.tenant_control_id),
             "assigneeId": r.assignee_user_id, "assigneeName": names.get(r.assignee_user_id),
             "dueOn": r.due_on.isoformat(), "recurrence": r.recurrence, "status": r.status,
             "urgency": task_urgency(r.due_on.isoformat(), today.isoformat()) if r.status == "open" else None,
             "completedAt": r.completed_at.isoformat() + "Z" if r.completed_at else None,
             "completedByName": names.get(r.completed_by_user_id), "completionNote": r.completion_note,
             "evidenceTitle": evidence.get(r.evidence_id)} for r in rows]


def complete(db: Session, row: IsmsTask, actor: str, user_id: str, note: str, evidence_id: str | None) -> None:
    """An operating task records what was checked (a note, evidence or both) and the next occurrence is scheduled.
    Implementation tasks close themselves when the control is in place."""
    if row.status != "open":
        raise _error("That task is not open.")
    if row.kind == "implement":
        raise _error("This task closes itself when the control is marked as in place in the assessment.")
    note = js_trim(note or "")
    if not note and not evidence_id:
        raise _error("Say what you checked, or attach evidence.")
    if evidence_id and db.execute(select(IsmsEvidence.id).where(IsmsEvidence.id == evidence_id,
                                                               IsmsEvidence.tenant_id == row.tenant_id)).first() is None:
        raise _error("That evidence does not exist.")
    now = utcnow()
    row.status, row.completed_at, row.completed_by_user_id = "done", now, user_id
    row.completion_note, row.evidence_id, row.updated_at, row.updated_by = note[:4000] or None, evidence_id, now, actor
    audit.record(db, actor, "isms.task_completed", row.title, row.tenant_id, id=row.id, evidenceId=evidence_id)
    sync_control_tasks(db, row.tenant_id, actor)


def add_manual(db: Session, tenant_id: str, actor: str, title: str, due_on: str, assignee: str | None,
               description: str | None, members: set[str]) -> IsmsTask:
    title = js_trim(title or "")
    if not title:
        raise _error("Give the task a title.")
    try:
        due = date.fromisoformat(due_on or "")
    except ValueError:
        raise _error("Choose a due date.") from None
    if assignee and assignee not in members:
        raise _error("The assignee must be a member of this organization.")
    row = IsmsTask(tenant_id=tenant_id, kind="manual", title=title[:300],
                   description=js_trim(description or "")[:4000] or None, assignee_user_id=assignee or None,
                   due_on=due, updated_by=actor)
    db.add(row)
    db.flush()
    audit.record(db, actor, "isms.task_added", row.title, tenant_id, id=row.id, dueOn=due.isoformat())
    return row


# Reminders ----------------------------------------------------------------------------------------------------

def _ddmmyyyy(d: date) -> str:
    return d.strftime("%d/%m/%Y")


def _email(kind: str, name: str, tenant: str, lines: list[tuple[str, date]]) -> tuple[str, str]:
    intro = {"due_soon": f"These tasks at {tenant} are due in the next 7 days:",
             "overdue": f"These tasks at {tenant} are now overdue:",
             "escalated": f"These tasks at {tenant} are more than {ESCALATE_AFTER_DAYS} days overdue and need a "
                          f"manager's attention:"}[kind]
    subject = {"due_soon": f"{tenant}: {len(lines)} task(s) due soon", "overdue": f"{tenant}: {len(lines)} task(s) overdue",
               "escalated": f"{tenant}: {len(lines)} task(s) escalated"}[kind]
    url = get_settings().public_base_url.rstrip("/")
    body = "\n".join([f"Hello {name},", "", intro, "", *(f"- {t} (due {_ddmmyyyy(d)})" for t, d in lines), "",
                      f"Open the tasks: {url}/governance?tab=ISMS+tasks", "", "Fenrir"])
    return subject, body


def send_reminders(db: Session) -> dict:
    """Daily reminders and escalation for open tasks of every customer with an ISMS programme."""
    today = _today()
    counts = {"due_soon": 0, "overdue": 0, "escalated": 0}
    tenants = {t.id: t for t in db.execute(select(Tenant).where(Tenant.id.in_(
        select(IsmsTenantFramework.tenant_id)))).scalars()}
    stages = (("due_soon", "reminded_at", lambda t: today <= t.due_on <= today + timedelta(days=7), "assignee"),
              ("overdue", "overdue_notified_at", lambda t: t.due_on < today, "assignee"),
              ("escalated", "escalated_at", lambda t: t.due_on < today - timedelta(days=ESCALATE_AFTER_DAYS), "managers"))
    for tenant_id, tenant in tenants.items():
        tasks = list(db.execute(select(IsmsTask).where(IsmsTask.tenant_id == tenant_id, IsmsTask.status == "open"))
                     .scalars())
        managers = [u for u, in db.execute(select(User).join(IsmsMembership, IsmsMembership.user_id == User.id).where(
            IsmsMembership.tenant_id == tenant_id, IsmsMembership.role.in_(("tenant_admin", "isms_manager")),
            User.active.is_(True))).all()]
        for kind, column, due, to in stages:
            todo = [t for t in tasks if getattr(t, column) is None and due(t)]
            groups: dict[str, tuple[User, list[IsmsTask]]] = {}
            for t in todo:
                recipients = managers if to == "managers" else (
                    [u] if t.assignee_user_id and (u := db.get(User, t.assignee_user_id)) and u.active else [])
                for u in recipients:
                    groups.setdefault(u.id, (u, []))[1].append(t)
            reminded: set[str] = set()
            for u, items in groups.values():
                subject, body = _email(kind, u.name or u.email, tenant.name, [(t.title, t.due_on) for t in items])
                mailer.send(u.email, subject, body)
                counts[kind] += 1
                reminded |= {t.id for t in items}
            for t in todo:  # a task nobody could be told about is left for when it has an assignee
                if t.id in reminded:
                    setattr(t, column, utcnow())
        db.commit()
    return counts
