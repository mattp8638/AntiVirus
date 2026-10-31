"""PSA API: service boards and tickets, time, dispatch, agreements, configurations, products, quotes, workflows, KB."""

from __future__ import annotations

import hmac
import html
import os
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from .. import audit, psa, rmm, services
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import (Board, Configuration, Contact, Contract, Device, Job, KbArticle, Product, Project, Quote, RemoteSession,
                      ScheduleEntry, Site, Tenant, Ticket, TimeEntry, WorkflowRule, utcnow)
from ..serialize import apply_fields, to_dict

router = APIRouter(prefix="/api/console", tags=["PSA"])
inbound = APIRouter(prefix="/api/inbound", tags=["PSA"])


def _msp(principal: Principal, db: Session) -> str:
    return services.msp_tenant_id(db, principal.user.tenant_id)


def _msp_owned(principal: Principal, db: Session) -> str:
    """The MSP tenant, for creating MSP-level records (boards, workflows, quotes, the inbound email token). Staff
    scoped to a customer, and customer-side users, are refused: the MSP's settings are shared by every customer."""
    owner = _msp(principal, db)
    if owner not in principal.tenant_ids:
        raise HTTPException(403, "Only MSP staff can change the MSP's service desk settings")
    return owner


def _owned(db: Session, principal: Principal, model, obj_id: str):
    obj = db.get(model, obj_id)
    if obj is None or (obj.tenant_id not in principal.tenant_ids
                       and getattr(obj, "account_tenant_id", None) not in principal.tenant_ids):
        raise HTTPException(404, "Not found")
    return obj


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(400, f"invalid date/time '{value}'") from exc
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _require_service(principal: Principal) -> None:
    if not (principal.can("crm") or principal.can("respond")):
        raise HTTPException(403, "Your role cannot change service tickets")


# --------------------------------------------------------------------------- members and boards


@router.get("/psa/members")
def list_members(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return psa.members(db, list(principal.tenant_ids))


@router.get("/psa/meta")
def psa_meta(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    owner = _msp(principal, db)
    boards = psa.ensure_default_boards(db, owner)
    db.commit()
    return {"boards": [to_dict(b) for b in boards], "workTypes": psa.WORK_TYPES, "priorityMatrix":
            [{"impact": i, "urgency": u, "priority": p} for (i, u), p in psa.PRIORITY_MATRIX.items()],
            "members": psa.members(db, list(principal.tenant_ids))}


BOARD_FIELDS = {"name", "statuses", "types", "members", "teams", "default_priority", "default_work_type", "mailbox", "auto_assign"}


@router.get("/psa/boards")
def list_boards(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    boards = psa.ensure_default_boards(db, _msp(principal, db))
    db.commit()
    return [to_dict(b) for b in boards]


@router.post("/psa/boards")
def create_board(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    board = Board(tenant_id=_msp_owned(principal, db), name=str(body.get("name") or "New board"),
                  statuses=[dict(s) for s in psa.DEFAULT_STATUSES], types=[dict(t) for t in psa.DEFAULT_TYPES])
    apply_fields(board, body, BOARD_FIELDS)
    db.add(board)
    audit.record(db, principal.actor, "psa.board.created", board.name, board.tenant_id)
    db.commit()
    return to_dict(board)


@router.delete("/psa/boards/{board_id}")
def delete_board(board_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Remove a board nobody uses. Tickets keep their history, so a board with tickets is moved from, not deleted."""
    principal.require("configure")
    board = _owned(db, principal, Board, board_id)
    tickets = db.scalar(select(func.count()).where(Ticket.board_id == board.id)) or 0
    if tickets:
        raise HTTPException(409, f"{tickets} ticket(s) are on this board. Move them to another board first.")
    if (db.scalar(select(func.count()).where(Board.tenant_id == board.tenant_id)) or 0) <= 1:
        raise HTTPException(409, "This is the only board: tickets need somewhere to go")
    db.delete(board)
    audit.record(db, principal.actor, "psa.board.deleted", board.name, board.tenant_id)
    db.commit()
    return {"ok": True}


@router.patch("/psa/boards/{board_id}")
def update_board(board_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    board = _owned(db, principal, Board, board_id)
    if "statuses" in body:
        statuses = body["statuses"]
        if not isinstance(statuses, list) or not statuses or not all(isinstance(s, dict) and s.get("name") for s in statuses):
            raise HTTPException(400, "statuses must be a non-empty list of {name}")
        if not any(s.get("closed") for s in statuses):
            raise HTTPException(400, "a board needs at least one closed status")
    changed = apply_fields(board, body, BOARD_FIELDS)
    audit.record(db, principal.actor, "psa.board.updated", board.name, board.tenant_id, fields=changed)
    db.commit()
    return to_dict(board)


# --------------------------------------------------------------------------- tickets


def _ticket_view(db: Session, ticket: Ticket, names: dict, boards: dict, now: datetime) -> dict:
    board = boards.get(ticket.board_id)
    closed = ticket.status in psa.closed_statuses(board)
    return {**to_dict(ticket), "account": names.get(ticket.account_tenant_id, ""), "board": board.name if board else ticket.queue,
            "closed": closed,
            "slaBreached": bool(ticket.sla_due_at and not closed and ticket.sla_due_at < now),
            "respondBreached": bool(ticket.respond_due_at and not ticket.responded_at and not closed and ticket.respond_due_at < now),
            "hours": round((ticket.time_minutes or 0) / 60, 2)}


@router.get("/tickets")
def list_tickets(tenant_id: str | None = None, status: str | None = None, queue: str | None = None, board_id: str | None = None,
                 assignee: str | None = None, q: str | None = None, project_id: str | None = None,
                 principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    scope = scoped_tenant(principal, tenant_id)
    query = select(Ticket).where(or_(Ticket.account_tenant_id.in_(scope), Ticket.tenant_id.in_(scope)))
    if board_id:
        query = query.where(Ticket.board_id == board_id)
    if queue:
        query = query.where(Ticket.queue == queue)
    if assignee == "me":
        query = query.where(or_(Ticket.assignee == principal.actor, Ticket.resources.contains(principal.actor)))
    elif assignee == "unassigned":
        query = query.where(or_(Ticket.assignee == "", Ticket.assignee.is_(None)))
    elif assignee:
        query = query.where(Ticket.assignee == assignee)
    if project_id:
        query = query.where(Ticket.project_id == project_id)
    if q:
        like = f"%{q}%"
        conditions = [Ticket.subject.ilike(like), Ticket.description.ilike(like), cast(Ticket.custom_fields, String).ilike(like)]
        if q.lstrip("#").isdigit():
            conditions.append(Ticket.number == int(q.lstrip("#")))
        query = query.where(or_(*conditions))
    if status and status not in {"active", "closed"}:
        query = query.where(Ticket.status == status)
    rows = db.execute(query.order_by(Ticket.priority, Ticket.sla_due_at).limit(2000)).scalars().all()
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    boards = {b.id: b for b in db.execute(select(Board)).scalars()}
    now = utcnow()
    out = [_ticket_view(db, t, names, boards, now) for t in rows]
    if status == "active":
        out = [t for t in out if not t["closed"]]
    elif status == "closed":
        out = [t for t in out if t["closed"]]
    return out


TICKET_FIELDS = {"subject", "description", "priority", "assignee", "resources", "team", "type", "subtype", "item", "impact", "urgency",
                 "site_id", "contact_id", "contact_email", "agreement_id", "project_id", "phase", "budget_hours", "required_date",
                 "configuration_ids", "billable", "device_id"}


@router.post("/tickets")
def create_ticket(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    account = body.get("accountTenantId") or principal.user.tenant_id
    principal.check_tenant(account)
    if not body.get("subject"):
        raise HTTPException(400, "subject is required")
    if not (principal.can("crm") or principal.can("respond")):
        # Anyone signed in may ask for help, but only staff route, assign or classify the ticket.
        body = {k: body[k] for k in ("subject", "description", "impact", "urgency", "priority", "deviceId", "accountTenantId") if k in body}
    if body.get("boardId"):
        _owned(db, principal, Board, body["boardId"])
    if body.get("deviceId"):
        device = db.get(Device, body["deviceId"])
        if device is None or device.tenant_id != account:
            raise HTTPException(404, "Device not found for this customer")
    priority = psa.priority_for(body.get("impact"), body.get("urgency")) or str(body.get("priority") or "P3")
    if priority not in services.DEFAULT_SLA_HOURS:
        raise HTTPException(400, "priority must be P1-P4")
    extra = {}
    for key in TICKET_FIELDS - {"subject", "description", "priority"}:
        camel = "".join(p.title() if i else p for i, p in enumerate(key.split("_")))
        if camel in body:
            extra[key] = body[camel]
    if extra.get("contact_id") and not extra.get("contact_email"):
        contact = db.get(Contact, extra["contact_id"])
        extra["contact_email"] = contact.email if contact else ""
    ticket = services.open_ticket(db, account, str(body["subject"]), str(body.get("description") or ""), priority,
                                  str(body.get("source") or "portal"), principal.actor, device_id=body.get("deviceId"),
                                  queue=str(body.get("queue") or "Service Desk"), board_id=body.get("boardId"),
                                  **{k: v for k, v in extra.items() if k != "device_id"})
    record_type = str(body.get("recordType") or "incident")
    if record_type not in ("incident", "service_request", "problem", "change"):
        raise HTTPException(400, "recordType must be incident, service_request, problem or change")
    ticket.record_type = record_type
    ticket.change_state = "Draft" if record_type == "change" else ""
    audit.record(db, principal.actor, "ticket.created", f"#{ticket.number}", account)
    db.commit()
    return to_dict(ticket)


@router.get("/tickets/{ticket_id}")
def get_ticket(ticket_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    ticket = _owned(db, principal, Ticket, ticket_id)
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    boards = {b.id: b for b in db.execute(select(Board)).scalars()}
    view = _ticket_view(db, ticket, names, boards, utcnow())
    view["boardDetail"] = to_dict(boards[ticket.board_id]) if ticket.board_id in boards else None
    view["timeEntries"] = [to_dict(t) for t in db.execute(select(TimeEntry).where(TimeEntry.ticket_id == ticket.id)
                                                          .order_by(TimeEntry.started_at)).scalars()]
    view["schedule"] = [to_dict(s) for s in db.execute(select(ScheduleEntry).where(ScheduleEntry.ticket_id == ticket.id)
                                                       .order_by(ScheduleEntry.start_at)).scalars()]
    view["configurations"] = [to_dict(c) for c in db.execute(select(Configuration).where(
        Configuration.id.in_(ticket.configuration_ids or []))).scalars()] if ticket.configuration_ids else []
    view["device"] = to_dict(db.get(Device, ticket.device_id), exclude={"inventory"}) if ticket.device_id and db.get(Device, ticket.device_id) else None
    view["contact"] = to_dict(db.get(Contact, ticket.contact_id)) if ticket.contact_id and db.get(Contact, ticket.contact_id) else None
    view["agreement"] = to_dict(db.get(Contract, ticket.agreement_id)) if ticket.agreement_id and db.get(Contract, ticket.agreement_id) else None
    view["remoteSessions"] = [to_dict(s) for s in db.execute(select(RemoteSession).where(RemoteSession.ticket_id == ticket.id)).scalars()]
    view["rmmJobs"] = [{**to_dict(j), "summary": rmm.job_summary(db, j)}
                       for j in db.execute(select(Job).where(Job.ticket_id == ticket.id,
                                                            Job.tenant_id == ticket.account_tenant_id)
                                           .order_by(Job.created_at.desc())).scalars()]
    view["children"] = [{"id": c.id, "number": c.number, "subject": c.subject, "status": c.status}
                        for c in db.execute(select(Ticket).where(Ticket.parent_id == ticket.id)).scalars()]
    return view


@router.patch("/tickets/{ticket_id}")
def update_ticket(ticket_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    ticket = _owned(db, principal, Ticket, ticket_id)
    _require_service(principal)  # read-only roles change nothing; customers comment through the portal
    changed: list[str] = []
    if body.get("boardId") and body["boardId"] != ticket.board_id:
        board = _owned(db, principal, Board, body["boardId"])
        ticket.board_id, ticket.queue = board.id, board.name
        if ticket.status not in {s["name"] for s in board.statuses or []}:
            psa.set_status(db, ticket, psa.default_status(board), principal.actor)
        changed.append("board")
    board = db.get(Board, ticket.board_id) if ticket.board_id else None
    if body.get("status"):
        allowed = {s["name"] for s in (board.statuses if board else psa.DEFAULT_STATUSES)} | psa.CLOSED_DEFAULT
        if body["status"] not in allowed:
            raise HTTPException(400, "invalid status for this board")
        psa.set_status(db, ticket, body["status"], principal.actor)
        changed.append("status")
    if "priority" in body and body["priority"] not in services.DEFAULT_SLA_HOURS:
        raise HTTPException(400, "priority must be P1-P4")
    changed += apply_fields(ticket, body, TICKET_FIELDS)
    if {"impact", "urgency"} & set(changed):
        matrix = psa.priority_for(ticket.impact, ticket.urgency)
        if matrix and "priority" not in body:
            ticket.priority = matrix
            changed.append("priority")
    if "priority" in changed or "agreement_id" in changed:
        psa.apply_sla(db, ticket)
    if body.get("contactId") and not body.get("contactEmail"):
        contact = db.get(Contact, body["contactId"])
        ticket.contact_email = contact.email if contact else ticket.contact_email
    if body.get("addMinutes"):
        psa.create_time_entry(db, member=principal.actor, owner_tenant_id=ticket.tenant_id, account_tenant_id=ticket.account_tenant_id,
                              hours=int(body["addMinutes"]) / 60, ticket=ticket,
                              work_type=board.default_work_type if board else "Remote Support")
        changed.append("time")
    if body.get("comment"):
        kind = body.get("kind") or ("internal" if body.get("internal") else "discussion")
        psa.add_note(db, ticket, principal.actor, str(body["comment"]), kind, email_contact=bool(body.get("emailContact")),
                     staff=principal.can("crm") or principal.can("respond"))
        changed.append("note")
    if not changed:  # nothing to do: don't touch the ticket or fire "ticket.updated" workflows
        return to_dict(ticket)
    ticket.updated_at = utcnow()
    psa.run_workflows(db, ticket, "ticket.updated")
    audit.record(db, principal.actor, "ticket.updated", f"#{ticket.number}", ticket.account_tenant_id, fields=changed)
    db.commit()
    return to_dict(ticket)


@router.post("/tickets/{ticket_id}/tasks")
def ticket_task(ticket_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """{"add": "text"} | {"toggle": index} | {"remove": index}"""
    _require_service(principal)
    ticket = _owned(db, principal, Ticket, ticket_id)
    tasks = list(ticket.tasks or [])
    if body.get("add"):
        tasks.append({"text": str(body["add"])[:300], "done": False, "by": principal.actor, "at": utcnow().isoformat()})
    elif isinstance(body.get("toggle"), int) and 0 <= body["toggle"] < len(tasks):
        task = dict(tasks[body["toggle"]])
        task["done"] = not task.get("done")
        task["doneBy"] = principal.actor if task["done"] else ""
        tasks[body["toggle"]] = task
    elif isinstance(body.get("remove"), int) and 0 <= body["remove"] < len(tasks):
        tasks.pop(body["remove"])
    ticket.tasks = tasks
    ticket.updated_at = utcnow()
    db.commit()
    return tasks


@router.post("/tickets/{ticket_id}/merge")
def merge_ticket(ticket_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Merge this ticket into another: notes and time move across, this one closes as a child."""
    _require_service(principal)
    source = _owned(db, principal, Ticket, ticket_id)
    target = _owned(db, principal, Ticket, str(body.get("intoTicketId") or ""))
    if source.id == target.id:
        raise HTTPException(400, "cannot merge a ticket into itself")
    target.comments = (target.comments or []) + [{**c, "text": f"[from #{source.number}] {c.get('text', '')}"} for c in source.comments or []]
    for entry in db.execute(select(TimeEntry).where(TimeEntry.ticket_id == source.id)).scalars():
        entry.ticket_id = target.id
    target.time_minutes = (target.time_minutes or 0) + (source.time_minutes or 0)
    source.time_minutes = 0
    source.parent_id = target.id
    psa.set_status(db, source, "Closed", principal.actor)
    psa.add_note(db, source, principal.actor, f"Merged into ticket #{target.number}", "internal")
    audit.record(db, principal.actor, "ticket.merged", f"#{source.number}->#{target.number}", source.account_tenant_id)
    db.commit()
    return to_dict(target)


# --------------------------------------------------------------------------- time entries and timesheets


@router.get("/psa/time")
def list_time(member: str | None = None, start: str | None = None, end: str | None = None, status: str | None = None,
              ticket_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    query = select(TimeEntry).where(or_(TimeEntry.tenant_id.in_(principal.tenant_ids), TimeEntry.account_tenant_id.in_(principal.tenant_ids)))
    if member == "me":
        member = principal.actor
    if member:
        query = query.where(TimeEntry.member == member)
    if start:
        query = query.where(TimeEntry.started_at >= _parse_dt(start))
    if end:
        query = query.where(TimeEntry.started_at < _parse_dt(end))
    if status:
        query = query.where(TimeEntry.status == status)
    if ticket_id:
        query = query.where(TimeEntry.ticket_id == ticket_id)
    rows = db.execute(query.order_by(TimeEntry.started_at.desc()).limit(2000)).scalars().all()
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    numbers = dict(db.execute(select(Ticket.id, Ticket.number).where(Ticket.id.in_({r.ticket_id for r in rows if r.ticket_id}))).all())
    return [{**to_dict(r), "account": names.get(r.account_tenant_id, ""), "ticketNumber": numbers.get(r.ticket_id)} for r in rows]


@router.post("/psa/time")
def create_time(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    _require_service(principal)
    ticket = _owned(db, principal, Ticket, body["ticketId"]) if body.get("ticketId") else None
    account = ticket.account_tenant_id if ticket else body.get("accountTenantId")
    if account:
        principal.check_tenant(account)
    member = str(body.get("member") or principal.actor)
    if member != principal.actor and not principal.can("manage_tenants"):
        raise HTTPException(403, "Only managers can enter time for someone else")
    try:
        entry = psa.create_time_entry(
            db, member=member, owner_tenant_id=ticket.tenant_id if ticket else _msp(principal, db), account_tenant_id=account,
            hours=float(body["hours"]) if body.get("hours") not in (None, "") else None, started_at=_parse_dt(body.get("startedAt")),
            ended_at=_parse_dt(body.get("endedAt")), ticket=ticket, project_id=body.get("projectId"),
            work_type=str(body.get("workType") or "Remote Support"), notes=str(body.get("notes") or ""),
            internal_notes=str(body.get("internalNotes") or ""), billable=str(body.get("billable") or "Billable"),
            work_role=str(body.get("workRole") or "Engineer"))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    audit.record(db, principal.actor, "psa.time.created", f"{entry.hours}h", account, ticket=ticket.number if ticket else None)
    db.commit()
    return to_dict(entry)


@router.patch("/psa/time/{entry_id}")
def update_time(entry_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    entry = _owned(db, principal, TimeEntry, entry_id)
    if entry.status == "Billed":
        raise HTTPException(409, "Billed time cannot be changed")
    approving = body.get("status") in {"Approved", "Rejected"}
    if approving and not principal.can("manage_tenants"):
        raise HTTPException(403, "Only managers approve timesheets")
    if not approving and entry.member != principal.actor and not principal.can("manage_tenants"):
        raise HTTPException(403, "You can only edit your own time")
    if body.get("status") and body["status"] not in {"Open", "Submitted", "Approved", "Rejected"}:
        raise HTTPException(400, "invalid status")
    if "billable" in body and body["billable"] not in {"Billable", "Do Not Bill", "No Charge"}:
        raise HTTPException(400, "billable must be Billable, Do Not Bill or No Charge")
    if "hours" in body and not (isinstance(body["hours"], (int, float)) and 0 < float(body["hours"]) <= 24):
        raise HTTPException(400, "hours must be between 0 and 24")
    changed = apply_fields(entry, body, {"hours", "hours_billed", "billable", "notes", "internal_notes", "work_type", "work_role", "status"})
    if "hours" in changed and "hours_billed" not in changed:
        entry.hours_billed = psa.round_hours(float(entry.hours))
    audit.record(db, principal.actor, "psa.time.updated", entry.id, entry.account_tenant_id, fields=changed)
    db.commit()
    return to_dict(entry)


@router.delete("/psa/time/{entry_id}")
def delete_time(entry_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Remove a time entry entered by mistake: your own while open or rejected; a manager's any that is not billed."""
    entry = _owned(db, principal, TimeEntry, entry_id)
    if entry.status == "Billed":
        raise HTTPException(409, "Billed time cannot be removed")
    manager = principal.can("manage_tenants")
    if not manager and (entry.member != principal.actor or entry.status not in {"Open", "Rejected"}):
        raise HTTPException(403, "You can remove only your own time that has not been submitted or approved")
    db.delete(entry)
    audit.record(db, principal.actor, "psa.time.deleted", entry.id, entry.account_tenant_id, hours=float(entry.hours or 0))
    db.commit()
    return {"ok": True}


@router.post("/psa/timesheets/submit")
def submit_timesheet(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Submit a member's open time for a week (weekStart = Monday, YYYY-MM-DD)."""
    week = _parse_dt(body.get("weekStart"))
    if week is None:
        raise HTTPException(400, "weekStart is required")
    rows = db.execute(select(TimeEntry).where(TimeEntry.member == principal.actor, TimeEntry.status.in_(("Open", "Rejected")),
                                              TimeEntry.started_at >= week, TimeEntry.started_at < week + timedelta(days=7))).scalars().all()
    for entry in rows:
        entry.status = "Submitted"
    audit.record(db, principal.actor, "psa.timesheet.submitted", week.date().isoformat(), principal.user.tenant_id, entries=len(rows))
    db.commit()
    return {"submitted": len(rows)}


@router.post("/psa/timesheets/approve")
def approve_timesheet(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("manage_tenants")
    week = _parse_dt(body.get("weekStart"))
    member = str(body.get("member") or "")
    decision = "Approved" if body.get("approve", True) else "Rejected"
    rows = db.execute(select(TimeEntry).where(TimeEntry.member == member, TimeEntry.status == "Submitted",
                                              TimeEntry.tenant_id.in_(principal.tenant_ids),
                                              TimeEntry.started_at >= week, TimeEntry.started_at < week + timedelta(days=7))).scalars().all()
    for entry in rows:
        entry.status = decision
    audit.record(db, principal.actor, f"psa.timesheet.{decision.lower()}", f"{member} {week.date()}", principal.user.tenant_id, entries=len(rows))
    db.commit()
    return {decision.lower(): len(rows)}


@router.get("/psa/timesheets")
def timesheets(week_start: str = Query(..., alias="weekStart"), principal: Principal = Depends(current_principal),
               db: Session = Depends(get_db)):
    week = _parse_dt(week_start)
    rows = db.execute(select(TimeEntry).where(TimeEntry.tenant_id.in_(principal.tenant_ids), TimeEntry.started_at >= week,
                                              TimeEntry.started_at < week + timedelta(days=7))).scalars().all()
    sheets: dict[str, dict] = {}
    for entry in rows:
        sheet = sheets.setdefault(entry.member, {"member": entry.member, "days": [0.0] * 7, "total": 0.0, "billable": 0.0,
                                                 "statuses": {}})
        sheet["days"][(entry.started_at - week).days] += entry.hours
        sheet["total"] += entry.hours
        if entry.billable == "Billable":
            sheet["billable"] += entry.hours
        sheet["statuses"][entry.status] = sheet["statuses"].get(entry.status, 0) + 1
    for sheet in sheets.values():
        sheet["days"] = [round(d, 2) for d in sheet["days"]]
        sheet["total"], sheet["billable"] = round(sheet["total"], 2), round(sheet["billable"], 2)
        sheet["utilisation"] = round(100 * sheet["billable"] / 37.5, 1)
    return sorted(sheets.values(), key=lambda s: s["member"])


# --------------------------------------------------------------------------- dispatch / schedule


@router.get("/psa/schedule")
def list_schedule(start: str, end: str, member: str | None = None, principal: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    query = select(ScheduleEntry).where(ScheduleEntry.tenant_id.in_(principal.tenant_ids), ScheduleEntry.end_at > _parse_dt(start),
                                        ScheduleEntry.start_at < _parse_dt(end))
    if member:
        query = query.where(ScheduleEntry.member == member)
    rows = db.execute(query.order_by(ScheduleEntry.start_at)).scalars().all()
    tickets = {t.id: t for t in db.execute(select(Ticket).where(Ticket.id.in_({r.ticket_id for r in rows if r.ticket_id}))).scalars()}
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    out = []
    for row in rows:
        ticket = tickets.get(row.ticket_id)
        out.append({**to_dict(row), "ticketNumber": ticket.number if ticket else None,
                    "account": names.get(ticket.account_tenant_id, "") if ticket else "", "priority": ticket.priority if ticket else ""})
    return out


@router.post("/psa/schedule")
def create_schedule(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    _require_service(principal)
    start, end = _parse_dt(body.get("startAt")), _parse_dt(body.get("endAt"))
    if not start or not end or end <= start:
        raise HTTPException(400, "startAt must be before endAt")
    member = str(body.get("member") or principal.actor)
    ticket = _owned(db, principal, Ticket, body["ticketId"]) if body.get("ticketId") else None
    clash = db.execute(select(ScheduleEntry).where(ScheduleEntry.member == member, ScheduleEntry.status != "Cancelled",
                                                   ScheduleEntry.start_at < end, ScheduleEntry.end_at > start)).scalars().first()
    entry = ScheduleEntry(tenant_id=ticket.tenant_id if ticket else _msp(principal, db), member=member,
                          ticket_id=ticket.id if ticket else None, project_id=body.get("projectId"),
                          title=str(body.get("title") or (f"#{ticket.number} {ticket.subject}" if ticket else "Appointment"))[:300],
                          kind=str(body.get("kind") or "Service"), status=str(body.get("status") or "Firm"),
                          location=str(body.get("location") or ""), start_at=start, end_at=end, created_by=principal.actor)
    db.add(entry)
    if ticket is not None:
        if not ticket.assignee:
            ticket.assignee = member
        elif member != ticket.assignee and member not in (ticket.resources or []):
            ticket.resources = list(ticket.resources or []) + [member]
        board = db.get(Board, ticket.board_id) if ticket.board_id else None
        if board and "Scheduled" in {s["name"] for s in board.statuses or []} and ticket.status in {"New", "Open"}:
            psa.set_status(db, ticket, "Scheduled", principal.actor)
    audit.record(db, principal.actor, "psa.schedule.created", entry.title, ticket.account_tenant_id if ticket else None, member=member)
    db.commit()
    return {**to_dict(entry), "conflict": bool(clash)}


@router.patch("/psa/schedule/{entry_id}")
def update_schedule(entry_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    _require_service(principal)
    entry = _owned(db, principal, ScheduleEntry, entry_id)
    if "startAt" in body:
        entry.start_at = _parse_dt(body["startAt"])
    if "endAt" in body:
        entry.end_at = _parse_dt(body["endAt"])
    if entry.end_at <= entry.start_at:
        raise HTTPException(400, "startAt must be before endAt")
    apply_fields(entry, body, {"member", "status", "kind", "location", "title"})
    db.commit()
    return to_dict(entry)


@router.delete("/psa/schedule/{entry_id}")
def delete_schedule(entry_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    _require_service(principal)
    entry = _owned(db, principal, ScheduleEntry, entry_id)
    db.delete(entry)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- companies, sites, configurations


@router.get("/psa/companies")
def companies(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    tenants = db.execute(select(Tenant).where(Tenant.id.in_(principal.tenant_ids), Tenant.kind != "unassigned")).scalars().all()
    open_tickets = dict(db.execute(select(Ticket.account_tenant_id, func.count()).where(Ticket.status.notin_(tuple(psa.CLOSED_DEFAULT)))
                                   .group_by(Ticket.account_tenant_id)).all())
    devices = dict(db.execute(select(Device.tenant_id, func.count()).group_by(Device.tenant_id)).all())
    contacts = dict(db.execute(select(Contact.account_tenant_id, func.count()).group_by(Contact.account_tenant_id)).all())
    agreements = dict(db.execute(select(Contract.account_tenant_id, func.count()).where(Contract.active.is_(True))
                                 .group_by(Contract.account_tenant_id)).all())
    return [{**to_dict(t), "companyType": (t.settings or {}).get("companyType", "Client" if t.kind == "customer" else t.kind.title()),
             "phone": (t.settings or {}).get("phone", ""), "website": (t.settings or {}).get("website", ""),
             "emailDomains": (t.settings or {}).get("emailDomains", []), "openTickets": open_tickets.get(t.id, 0),
             "devices": devices.get(t.id, 0), "contacts": contacts.get(t.id, 0), "agreements": agreements.get(t.id, 0)}
            for t in tenants]


@router.patch("/psa/companies/{tenant_id}")
def update_company(tenant_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("crm")
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    settings = dict(tenant.settings or {})
    for key in ("companyType", "phone", "website", "address", "emailDomains", "accountManager", "notes"):
        if key in body:
            settings[key] = body[key]
    tenant.settings = settings
    audit.record(db, principal.actor, "psa.company.updated", tenant.name, tenant.id)
    db.commit()
    return {**to_dict(tenant), **settings}


@router.get("/psa/companies/{tenant_id}")
def company_detail(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    now = utcnow()
    names = {tenant.id: tenant.name}
    boards = {b.id: b for b in db.execute(select(Board)).scalars()}
    tickets = db.execute(select(Ticket).where(Ticket.account_tenant_id == tenant_id).order_by(Ticket.created_at.desc()).limit(200)).scalars()
    return {
        "company": {**to_dict(tenant), **(tenant.settings or {})},
        "sites": [to_dict(s) for s in db.execute(select(Site).where(Site.account_tenant_id == tenant_id)).scalars()],
        "contacts": [to_dict(c) for c in db.execute(select(Contact).where(Contact.account_tenant_id == tenant_id)).scalars()],
        "agreements": [to_dict(c) for c in db.execute(select(Contract).where(Contract.account_tenant_id == tenant_id)).scalars()],
        "configurations": [to_dict(c) for c in db.execute(select(Configuration).where(Configuration.account_tenant_id == tenant_id)).scalars()],
        "tickets": [_ticket_view(db, t, names, boards, now) for t in tickets],
        "projects": [to_dict(p) for p in db.execute(select(Project).where(Project.account_tenant_id == tenant_id)).scalars()],
        "devices": db.execute(select(func.count()).where(Device.tenant_id == tenant_id)).scalar() or 0,
    }


def _validate_configuration_links(db: Session, account_tenant_id: str | None, values: dict,
                                  existing_id: str | None = None) -> None:
    """A CMDB record must never link devices, sites or people across customers."""
    if not account_tenant_id:
        raise HTTPException(422, "A customer account is required for an asset")
    for key, linked_model in (("device_id", Device), ("site_id", Site), ("contact_id", Contact)):
        linked_id = values.get(key)
        if not linked_id:
            continue
        linked = db.get(linked_model, linked_id)
        if linked is None:
            raise HTTPException(422, f"{key} does not exist")
        linked_account = linked.tenant_id if linked_model is Device else linked.account_tenant_id
        if linked_account != account_tenant_id:
            raise HTTPException(422, f"{key} belongs to another customer")
        if key == "device_id":
            duplicate = db.execute(select(Configuration).where(
                Configuration.device_id == linked_id,
                Configuration.id != (existing_id or ""))).scalar_one_or_none()
            if duplicate is not None:
                raise HTTPException(409, "The device is already linked to another configuration")


def _crud(model, prefix: str, fields: set[str], required: str, permission: str = "crm"):
    """Register list/create/update/delete routes for a simple tenant-owned PSA collection."""

    @router.get(f"/psa/{prefix}", name=f"list_{prefix}")
    def _list(account_tenant_id: str | None = Query(default=None, alias="accountTenantId"),
              tenant_id: str | None = None,
              principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        query = select(model).where(or_(model.tenant_id.in_(principal.tenant_ids),
                                        *( [model.account_tenant_id.in_(principal.tenant_ids)] if hasattr(model, "account_tenant_id") else [])))
        if tenant_id and model is KbArticle:
            principal.check_tenant(tenant_id)
            query = query.where(model.tenant_id == tenant_id)
        if account_tenant_id and hasattr(model, "account_tenant_id"):
            query = query.where(model.account_tenant_id == account_tenant_id)
        names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
        return [{**to_dict(r), "account": names.get(getattr(r, "account_tenant_id", None), "")}
                for r in db.execute(query.limit(5000)).scalars()]

    @router.post(f"/psa/{prefix}", name=f"create_{prefix}")
    def _create(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        principal.require(permission)
        owner = body.get("tenantId") if model is KbArticle else None
        if owner:
            principal.check_tenant(owner)
        if hasattr(model, "account_tenant_id"):
            account = body.get("accountTenantId")
            principal.check_tenant(account)
        obj = model(tenant_id=owner or (_msp(principal, db) if hasattr(model, "account_tenant_id") else _msp_owned(principal, db)))
        if hasattr(model, "account_tenant_id"):
            obj.account_tenant_id = account
        if model is Configuration:
            _validate_configuration_links(db, obj.account_tenant_id, {
                "device_id": body.get("device_id", body.get("deviceId")),
                "site_id": body.get("site_id", body.get("siteId")),
                "contact_id": body.get("contact_id", body.get("contactId")),
            })
        apply_fields(obj, body, fields)
        if not getattr(obj, required, None):
            raise HTTPException(400, f"{required} is required")
        if hasattr(obj, "author"):
            obj.author = principal.actor
        db.add(obj)
        audit.record(db, principal.actor, f"psa.{prefix}.created", str(getattr(obj, required)), getattr(obj, "account_tenant_id", obj.tenant_id))
        if model is KbArticle:
            from ..documentation import snapshot
            snapshot(db, obj, principal.actor)
        db.commit()
        return to_dict(obj)

    @router.patch(f"/psa/{prefix}/{{obj_id}}", name=f"update_{prefix}")
    def _update(obj_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        principal.require(permission)
        obj = _owned(db, principal, model, obj_id)
        if model is KbArticle:
            from ..documentation import snapshot
            snapshot(db, obj, principal.actor)
        if model is Configuration:
            _validate_configuration_links(db, obj.account_tenant_id, {
                "device_id": body.get("device_id", body.get("deviceId", obj.device_id)),
                "site_id": body.get("site_id", body.get("siteId", obj.site_id)),
                "contact_id": body.get("contact_id", body.get("contactId", obj.contact_id)),
            }, existing_id=obj.id)
        changed = apply_fields(obj, body, fields)
        if hasattr(obj, "updated_at"):
            obj.updated_at = utcnow()
        audit.record(db, principal.actor, f"psa.{prefix}.updated", obj_id, getattr(obj, "account_tenant_id", obj.tenant_id), fields=changed)
        if model is KbArticle:
            snapshot(db, obj, principal.actor)
        db.commit()
        return to_dict(obj)

    @router.delete(f"/psa/{prefix}/{{obj_id}}", name=f"delete_{prefix}")
    def _delete(obj_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        principal.require(permission)
        obj = _owned(db, principal, model, obj_id)
        db.delete(obj)
        audit.record(db, principal.actor, f"psa.{prefix}.deleted", obj_id, getattr(obj, "account_tenant_id", obj.tenant_id))
        db.commit()
        return {"ok": True}


_crud(Site, "sites", {"name", "address", "city", "postcode", "country", "phone", "primary"}, "name")
_crud(Configuration, "configurations", {"name", "type", "status", "device_id", "site_id", "contact_id", "manufacturer", "model",
                                        "serial_number", "ip_address", "mac_address", "os", "purchase_date", "warranty_expires",
                                        "vendor", "notes", "questions"}, "name")
_crud(Product, "products", {"sku", "description", "category", "cost", "price", "recurring", "taxable", "vendor", "active"}, "sku",
      permission="billing")
_crud(KbArticle, "kb", {"title", "body", "category", "tags", "public"}, "title")


@router.post("/psa/configurations/sync")
def sync_configurations(body: dict = Body(default={}), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Create or refresh a configuration for every managed device (the RMM -> CMDB sync)."""
    principal.require("crm")
    scope = scoped_tenant(principal, body.get("tenantId"))
    owner = _msp(principal, db)
    created = updated = 0
    for device in db.execute(select(Device).where(
        Device.tenant_id.in_(scope), Device.approved.is_(True))).scalars():
        try:
            result = psa.sync_managed_device(db, device)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        created += result == "created"
        updated += result == "updated"
    audit.record(db, principal.actor, "psa.configurations.synced", f"{created} new, {updated} updated", owner)
    db.commit()
    return {"created": created, "updated": updated}


# --------------------------------------------------------------------------- quotes


@router.get("/psa/quotes")
def list_quotes(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    rows = db.execute(select(Quote).where(Quote.tenant_id.in_(principal.tenant_ids)).order_by(Quote.created_at.desc())).scalars()
    return [{**to_dict(q), "account": names.get(q.account_tenant_id, ""), **_quote_totals(q)} for q in rows]


def _quote_totals(quote: Quote) -> dict:
    one_off = sum(float(l.get("quantity", 0)) * float(l.get("unitPrice", 0)) for l in quote.lines or [] if not l.get("recurring"))
    monthly = sum(float(l.get("quantity", 0)) * float(l.get("unitPrice", 0)) for l in quote.lines or [] if l.get("recurring"))
    return {"oneOffTotal": round(one_off, 2), "monthlyTotal": round(monthly, 2)}


@router.post("/psa/quotes")
def create_quote(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("crm")
    # A quote for one of the caller's customers is fine; an unattached quote is MSP-level.
    owner = _msp(principal, db) if body.get("accountTenantId") else _msp_owned(principal, db)
    count = db.execute(select(func.count()).select_from(Quote).where(Quote.tenant_id == owner)).scalar() or 0
    lines = []
    for line in body.get("lines") or []:
        product = db.get(Product, line.get("productId")) if line.get("productId") else None
        lines.append({"productId": product.id if product else None,
                      "description": str(line.get("description") or (product.description if product else "Item")),
                      "quantity": float(line.get("quantity") or 1),
                      "unitPrice": float(line.get("unitPrice") if line.get("unitPrice") not in (None, "") else (product.price if product else 0)),
                      "recurring": bool(line.get("recurring", product.recurring if product else False))})
    if body.get("accountTenantId"):
        principal.check_tenant(body["accountTenantId"])
    quote = Quote(number=f"Q-{date.today():%Y%m}-{count + 1:04d}", tenant_id=owner, account_tenant_id=body.get("accountTenantId"),
                  lead_id=body.get("leadId"), title=str(body.get("title") or "Quote"), lines=lines, notes=str(body.get("notes") or ""),
                  valid_until=str(body.get("validUntil") or (date.today() + timedelta(days=30)).isoformat()), created_by=principal.actor)
    db.add(quote)
    audit.record(db, principal.actor, "psa.quote.created", quote.number, quote.account_tenant_id)
    db.commit()
    return {**to_dict(quote), **_quote_totals(quote)}


@router.patch("/psa/quotes/{quote_id}")
def update_quote(quote_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("crm")
    quote = _owned(db, principal, Quote, quote_id)
    if body.get("status") and body["status"] not in {"Draft", "Sent", "Accepted", "Declined"}:
        raise HTTPException(400, "invalid status")
    apply_fields(quote, body, {"title", "lines", "status", "valid_until", "notes"})
    db.commit()
    return {**to_dict(quote), **_quote_totals(quote)}


@router.delete("/psa/quotes/{quote_id}")
def delete_quote(quote_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("crm")
    quote = _owned(db, principal, Quote, quote_id)
    if quote.status == "Accepted":
        raise HTTPException(409, "An accepted quote is a record of what the customer agreed to and cannot be deleted")
    db.delete(quote)
    audit.record(db, principal.actor, "psa.quote.deleted", quote.title, quote.account_tenant_id or quote.tenant_id)
    db.commit()
    return {"ok": True}


@router.get("/psa/quotes/{quote_id}/print", response_class=HTMLResponse)
def print_quote(quote_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    quote = _owned(db, principal, Quote, quote_id)
    account = db.get(Tenant, quote.account_tenant_id) if quote.account_tenant_id else None
    owner = db.get(Tenant, quote.tenant_id)
    esc = html.escape
    rows = "".join(f"<tr><td>{esc(l['description'])}</td><td>{l['quantity']:g}</td><td>£{l['unitPrice']:,.2f}</td>"
                   f"<td>{'Monthly' if l.get('recurring') else 'One-off'}</td><td>£{l['quantity'] * l['unitPrice']:,.2f}</td></tr>"
                   for l in quote.lines or [])
    totals = _quote_totals(quote)
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{esc(quote.number)}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:820px;margin:32px auto;color:#111}}table{{width:100%;border-collapse:collapse}}
td,th{{border-bottom:1px solid #ddd;padding:8px;text-align:left}}.r{{text-align:right}}</style></head><body>
<h1>{esc(owner.name if owner else '')} — Quote {esc(quote.number)}</h1>
<p><b>{esc(quote.title)}</b><br>Prepared for: {esc(account.name if account else 'Prospect')}<br>Valid until: {esc(quote.valid_until)}</p>
<table><tr><th>Item</th><th>Qty</th><th>Unit</th><th>Billing</th><th>Amount</th></tr>{rows}</table>
<p class="r">One-off total: <b>£{totals['oneOffTotal']:,.2f}</b><br>Monthly total: <b>£{totals['monthlyTotal']:,.2f}</b><br>Prices exclude VAT.</p>
<p>{esc(quote.notes)}</p></body></html>"""


# --------------------------------------------------------------------------- workflow rules


WORKFLOW_FIELDS = {"board_id", "name", "enabled", "trigger", "idle_hours", "conditions", "actions"}
TRIGGERS = {"ticket.created", "ticket.updated", "ticket.idle", "sla.warning", "sla.breached"}


@router.get("/psa/workflows")
def list_workflows(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return [to_dict(w) for w in db.execute(select(WorkflowRule).where(WorkflowRule.tenant_id.in_(principal.tenant_ids))).scalars()]


@router.post("/psa/workflows")
def create_workflow(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    if body.get("trigger", "ticket.created") not in TRIGGERS:
        raise HTTPException(400, f"trigger must be one of {sorted(TRIGGERS)}")
    rule = WorkflowRule(tenant_id=_msp_owned(principal, db), name=str(body.get("name") or "Workflow rule"))
    apply_fields(rule, body, WORKFLOW_FIELDS)
    db.add(rule)
    audit.record(db, principal.actor, "psa.workflow.created", rule.name, rule.tenant_id)
    db.commit()
    return to_dict(rule)


@router.patch("/psa/workflows/{rule_id}")
def update_workflow(rule_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    rule = _owned(db, principal, WorkflowRule, rule_id)
    if body.get("trigger") and body["trigger"] not in TRIGGERS:
        raise HTTPException(400, "invalid trigger")
    apply_fields(rule, body, WORKFLOW_FIELDS)
    db.commit()
    return to_dict(rule)


@router.delete("/psa/workflows/{rule_id}")
def delete_workflow(rule_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    db.delete(_owned(db, principal, WorkflowRule, rule_id))
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- projects (phases, tickets, hours)


@router.get("/psa/projects/{project_id}")
def project_detail(project_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    project = _owned(db, principal, Project, project_id)
    tickets = db.execute(select(Ticket).where(Ticket.project_id == project.id)).scalars().all()
    hours = db.execute(select(func.sum(TimeEntry.hours)).where(TimeEntry.project_id == project.id)).scalar() or 0
    phases = []
    for phase in project.phases or []:
        phase_tickets = [t for t in tickets if (t.phase or "") == phase.get("name")]
        phases.append({**phase, "tickets": [{"id": t.id, "number": t.number, "subject": t.subject, "status": t.status,
                                             "assignee": t.assignee} for t in phase_tickets]})
    return {"project": to_dict(project), "phases": phases, "actualHours": round(hours, 2),
            "unphased": [{"id": t.id, "number": t.number, "subject": t.subject, "status": t.status}
                         for t in tickets if not t.phase]}


# --------------------------------------------------------------------------- inbound email


def _inbound_token_ok(db: Session, tenant: Tenant, token: str | None) -> bool:
    expected = (tenant.settings or {}).get("inboundEmailToken") or os.getenv("FENRIR_INBOUND_EMAIL_TOKEN", "")
    return bool(expected) and bool(token) and hmac.compare_digest(str(expected), str(token))


@inbound.post("/email/{tenant_slug}")
async def inbound_email(tenant_slug: str, request: Request, token: str | None = Query(default=None),
                        db: Session = Depends(get_db)):
    """Email-to-ticket webhook. Accepts JSON {from, to, subject, text, messageId, inReplyTo} or a raw RFC 822 message."""
    tenant = db.execute(select(Tenant).where(Tenant.slug == tenant_slug)).scalar_one_or_none()
    if tenant is None or not _inbound_token_ok(db, tenant, token or request.headers.get("x-fenrir-inbound-token")):
        raise HTTPException(401, "Invalid inbound email token")
    raw = await request.body()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(413, "message too large")
    if request.headers.get("content-type", "").startswith("application/json"):
        import json

        message = json.loads(raw or b"{}")
    else:
        message = psa.parse_rfc822(raw)
    result = psa.process_inbound_email(db, services.msp_tenant_id(db, tenant.id), message)
    db.commit()
    return result


@router.post("/psa/inbound-token")
def rotate_inbound_token(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    from ..security import new_secret

    tenant = db.get(Tenant, _msp_owned(principal, db))
    token = new_secret("inb", 24)
    tenant.settings = {**(tenant.settings or {}), "inboundEmailToken": token}
    audit.record(db, principal.actor, "psa.inbound_token.rotated", tenant.name, tenant.id)
    db.commit()
    return {"token": token, "url": f"/api/inbound/email/{tenant.slug}?token={token}"}


# --------------------------------------------------------------------------- AI helpdesk triage (ai_helpdesk.py)


@router.get("/psa/ai-triage")
def get_ai_triage(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    from .. import ai_helpdesk

    principal.require("crm")
    owner = db.get(Tenant, services.msp_tenant_id(db, principal.user.tenant_id))
    return {"mode": "off", "engine": "local", **((owner.settings or {}).get("aiTriage") or {}),
            "claudeConfigured": bool(ai_helpdesk.api_key()), "model": os.getenv("FENRIR_AI_TRIAGE_MODEL", ai_helpdesk.DEFAULT_MODEL)}


@router.put("/psa/ai-triage")
def set_ai_triage(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """MSP-wide. Choosing the Claude engine sends redacted ticket text to Anthropic: an explicit opt-in."""
    principal.require("crm")
    principal.require("configure")
    owner = db.get(Tenant, services.msp_tenant_id(db, principal.user.tenant_id))
    if owner is None or owner.id != principal.user.tenant_id:
        raise HTTPException(403, "Only the MSP's own staff change helpdesk triage")
    mode, engine = str(body.get("mode") or "off"), str(body.get("engine") or "local")
    if mode not in ("off", "suggest", "apply") or engine not in ("local", "claude"):
        raise HTTPException(422, "mode must be off, suggest or apply; engine local or claude")
    owner.settings = {**(owner.settings or {}), "aiTriage": {"mode": mode, "engine": engine}}
    audit.record(db, principal.actor, "psa.ai_triage.updated", owner.name, owner.id, mode=mode, engine=engine)
    db.commit()
    return owner.settings["aiTriage"]


@router.post("/tickets/{ticket_id}/triage")
def triage_ticket(ticket_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Run triage now (suggest mode when triage is otherwise off)."""
    from .. import ai_helpdesk

    principal.require("respond")
    ticket = db.get(Ticket, ticket_id)
    if ticket is None or (ticket.account_tenant_id or ticket.tenant_id) not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    result = ai_helpdesk.triage(db, ticket, force=True)
    db.commit()
    return result
