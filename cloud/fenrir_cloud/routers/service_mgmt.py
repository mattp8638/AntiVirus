"""Service management on top of PSA tickets: problem and change records, and technician workload."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, psa
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import Board, ScheduleEntry, Ticket, TimeEntry, Vulnerability, utcnow
from ..serialize import to_dict

router = APIRouter(prefix="/api/console", tags=["Service management"])

RECORD_TYPES = ("incident", "service_request", "problem", "change")
CHANGE_RISKS = ("Low", "Medium", "High")
# change_state transitions: action -> (allowed from, to)
CHANGE_FLOW = {
    "submit": ({"", "Draft", "Rejected"}, "Submitted"),
    "approve": ({"Submitted"}, "Approved"),
    "reject": ({"Submitted"}, "Rejected"),
    "implement": ({"Approved"}, "Implemented"),
    "fail": ({"Approved"}, "Failed"),
    "close": ({"Implemented", "Failed", "Rejected"}, "Closed"),
}
ITIL_TEXT_FIELDS = ("root_cause", "workaround", "implementation_plan", "backout_plan", "test_plan")
WEEKLY_CAPACITY_HOURS = 37.5


def _ticket(db: Session, principal: Principal, ticket_id: str) -> Ticket:
    ticket = db.get(Ticket, ticket_id)
    if ticket is None or (ticket.tenant_id not in principal.tenant_ids and ticket.account_tenant_id not in principal.tenant_ids):
        raise HTTPException(404, "Not found")
    return ticket


def _when(value) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, "Dates must be ISO 8601") from None
    return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed


def _note(ticket: Ticket, by: str, text: str) -> None:
    ticket.comments = (ticket.comments or []) + [{"at": utcnow().isoformat(), "by": by, "kind": "system", "internal": True, "text": text}]


@router.patch("/tickets/{ticket_id}/itil")
def update_itil(ticket_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Record type, problem link, root cause / workaround, and change details."""
    if not (principal.can("respond") or principal.can("crm")):
        raise HTTPException(403, "Your role cannot edit service records")
    ticket = _ticket(db, principal, ticket_id)
    changed = []
    if "recordType" in body:
        if body["recordType"] not in RECORD_TYPES:
            raise HTTPException(400, f"recordType must be one of {', '.join(RECORD_TYPES)}")
        ticket.record_type = body["recordType"]
        if ticket.record_type == "change" and not ticket.change_state:
            ticket.change_state = "Draft"
        changed.append("record_type")
    if "problemId" in body:
        problem_id = body["problemId"] or None
        if problem_id:
            problem = _ticket(db, principal, problem_id)
            if problem.record_type != "problem" or problem.id == ticket.id:
                raise HTTPException(400, "problemId must be another ticket recorded as a problem")
            if problem.tenant_id != ticket.tenant_id:
                raise HTTPException(400, "The problem belongs to a different service provider")
        ticket.problem_id = problem_id
        changed.append("problem_id")
    for key, attr in (("rootCause", "root_cause"), ("workaround", "workaround"), ("implementationPlan", "implementation_plan"),
                      ("backoutPlan", "backout_plan"), ("testPlan", "test_plan")):
        if key in body:
            setattr(ticket, attr, str(body[key] or "")[:20000])
            changed.append(attr)
    if "knownError" in body:
        ticket.known_error = bool(body["knownError"])
        changed.append("known_error")
    if "changeRisk" in body:
        if body["changeRisk"] not in CHANGE_RISKS:
            raise HTTPException(400, "changeRisk must be Low, Medium or High")
        ticket.change_risk = body["changeRisk"]
        changed.append("change_risk")
    if "plannedStart" in body:
        ticket.planned_start = _when(body["plannedStart"])
        changed.append("planned_start")
    if "plannedEnd" in body:
        ticket.planned_end = _when(body["plannedEnd"])
        changed.append("planned_end")
    if ticket.planned_start and ticket.planned_end and ticket.planned_end <= ticket.planned_start:
        raise HTTPException(400, "The change window must end after it starts")
    if ticket.change_state in {"Submitted", "Approved"} and {"implementation_plan", "backout_plan", "change_risk",
                                                            "planned_start", "planned_end"} & set(changed):
        # Editing an approved plan invalidates the approval.
        ticket.change_state, ticket.change_approvals = "Draft", []
        _note(ticket, principal.actor, "Change plan edited; it must be submitted and approved again.")
    ticket.updated_at = utcnow()
    audit.record(db, principal.actor, "ticket.itil.updated", f"#{ticket.number}", ticket.account_tenant_id, fields=changed)
    db.commit()
    return to_dict(ticket)


@router.post("/tickets/{ticket_id}/change/{action}")
def change_action(ticket_id: str, action: str, body: dict = Body(default={}), principal: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    """Change workflow: submit -> approve/reject -> implement/fail -> close. High risk needs two approvers."""
    if action not in CHANGE_FLOW:
        raise HTTPException(404, "Unknown change action")
    ticket = _ticket(db, principal, ticket_id)
    if ticket.record_type != "change":
        raise HTTPException(400, "This ticket is not a change request")
    allowed_from, target = CHANGE_FLOW[action]
    state = ticket.change_state or ""
    if state not in allowed_from:
        raise HTTPException(409, f"Cannot {action} a change that is {state or 'Draft'}")
    comment = str(body.get("comment") or "").strip()[:2000]
    if action == "submit":
        principal.require("respond")
        missing = [label for label, value in (("risk", ticket.change_risk), ("implementation plan", ticket.implementation_plan),
                                              ("backout plan", ticket.backout_plan), ("planned start", ticket.planned_start),
                                              ("planned end", ticket.planned_end)) if not value]
        if missing:
            raise HTTPException(400, "Before submitting, add: " + ", ".join(missing))
        ticket.change_approvals = []
    elif action in {"approve", "reject"}:
        principal.require("configure")  # change approvers: MSP admins
        submitter = next((n.get("by") for n in reversed(ticket.comments or []) if n.get("text") == "Change submitted for approval"), "")
        if submitter == principal.actor:
            raise HTTPException(403, "The person who submitted a change cannot approve it")
        approvals = list(ticket.change_approvals or [])
        if any(a.get("by") == principal.actor for a in approvals):
            raise HTTPException(409, "You have already recorded a decision on this change")
        if action == "reject" and not comment:
            raise HTTPException(400, "Say why the change is rejected")
        approvals.append({"by": principal.actor, "decision": action, "comment": comment, "at": utcnow().isoformat()})
        ticket.change_approvals = approvals
        needed = 2 if ticket.change_risk == "High" else 1
        approved = sum(1 for a in approvals if a["decision"] == "approve")
        if action == "approve" and approved < needed:
            target = "Submitted"  # waiting for another approver
    elif action in {"implement", "fail"}:
        principal.require("respond")
        if action == "fail" and not comment:
            raise HTTPException(400, "Describe what went wrong and whether the backout plan was used")
    ticket.change_state = target
    text = {"submit": "Change submitted for approval", "approve": f"Change approved by {principal.actor}",
            "reject": f"Change rejected by {principal.actor}", "implement": "Change implemented successfully",
            "fail": "Change implementation failed", "close": "Change closed"}[action]
    if action == "approve" and target == "Submitted":
        text = f"Change approved by {principal.actor}; a second approval is needed for a high-risk change"
    _note(ticket, principal.actor, text)
    if comment:
        psa.add_note(db, ticket, principal.actor, comment, "internal")
    if target == "Closed":
        board = db.get(Board, ticket.board_id) if ticket.board_id else None
        closed = sorted(psa.closed_statuses(board))
        psa.set_status(db, ticket, "Closed" if "Closed" in closed else closed[0], principal.actor)
    ticket.updated_at = utcnow()
    audit.record(db, principal.actor, f"change.{action}", f"#{ticket.number}", ticket.account_tenant_id, state=target)
    db.commit()
    return to_dict(ticket)


@router.get("/psa/problems")
def list_problems(include_closed: bool = False, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    problems = db.execute(select(Ticket).where(Ticket.tenant_id.in_(principal.tenant_ids), Ticket.record_type == "problem")
                          .order_by(Ticket.created_at.desc())).scalars().all()
    if not problems:
        return []
    linked = db.execute(select(Ticket).where(Ticket.problem_id.in_([p.id for p in problems]))).scalars().all()
    out = []
    for p in problems:
        if not include_closed and psa.is_closed(db, p):
            continue
        incidents = [t for t in linked if t.problem_id == p.id]
        out.append({"id": p.id, "number": p.number, "subject": p.subject, "status": p.status, "priority": p.priority,
                    "accountTenantId": p.account_tenant_id, "knownError": bool(p.known_error), "rootCause": p.root_cause or "",
                    "workaround": p.workaround or "", "linkedIncidents": len(incidents),
                    "openIncidents": sum(1 for t in incidents if not psa.is_closed(db, t)), "createdAt": p.created_at})
    return out


@router.post("/tickets/{ticket_id}/problem/resolve-linked")
def resolve_linked_incidents(ticket_id: str, body: dict = Body(default={}), principal: Principal = Depends(current_principal),
                             db: Session = Depends(get_db)):
    """Close every open incident linked to this problem, with a resolution note pointing at the fix."""
    principal.require("respond")
    problem = _ticket(db, principal, ticket_id)
    if problem.record_type != "problem":
        raise HTTPException(400, "This ticket is not a problem record")
    text = str(body.get("resolution") or problem.root_cause or "").strip()
    if not text:
        raise HTTPException(400, "Add a resolution note or record the root cause first")
    resolved = 0
    for incident in db.execute(select(Ticket).where(Ticket.problem_id == problem.id)).scalars():
        if psa.is_closed(db, incident):
            continue
        psa.add_note(db, incident, principal.actor, f"Resolved by problem #{problem.number}: {text}", "resolution",
                     email_contact=bool(body.get("emailContacts")))
        board = db.get(Board, incident.board_id) if incident.board_id else None
        psa.set_status(db, incident, "Resolved" if "Resolved" in psa.closed_statuses(board) else sorted(psa.closed_statuses(board))[0],
                       principal.actor)
        resolved += 1
    audit.record(db, principal.actor, "problem.resolved_linked", f"#{problem.number}", problem.account_tenant_id, count=resolved)
    db.commit()
    return {"resolved": resolved}


@router.get("/tickets/{ticket_id}/links")
def ticket_links(ticket_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Problem/incident links and the vulnerabilities this ticket remediates."""
    ticket = _ticket(db, principal, ticket_id)
    problem = db.get(Ticket, ticket.problem_id) if ticket.problem_id else None
    incidents = db.execute(select(Ticket).where(Ticket.problem_id == ticket.id)).scalars().all() if ticket.record_type == "problem" else []
    vulns = db.execute(select(Vulnerability).where(Vulnerability.ticket_id == ticket.id)).scalars().all()
    return {
        "problem": {"id": problem.id, "number": problem.number, "subject": problem.subject, "status": problem.status,
                    "knownError": bool(problem.known_error), "workaround": problem.workaround or ""} if problem else None,
        "incidents": [{"id": t.id, "number": t.number, "subject": t.subject, "status": t.status, "closed": psa.is_closed(db, t)}
                      for t in incidents],
        "vulnerabilities": [{"id": v.id, "vulnId": v.vuln_id, "package": v.package, "severity": v.severity, "status": v.status,
                             "deviceId": v.device_id, "knownExploited": v.known_exploited, "fixedVersion": v.fixed_version}
                            for v in vulns],
    }


@router.get("/psa/workload")
def workload(days: int = Query(7, ge=1, le=31), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Per technician: open work, SLA risk, booked time ahead and hours logged this week."""
    principal.require("read")
    now = utcnow()
    week_start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    horizon = now + timedelta(days=days)
    tickets = db.execute(select(Ticket).where(Ticket.tenant_id.in_(principal.tenant_ids), Ticket.assignee != "")).scalars().all()
    boards = {b.id: b for b in db.execute(select(Board)).scalars()}
    schedule = db.execute(select(ScheduleEntry).where(ScheduleEntry.tenant_id.in_(principal.tenant_ids),
                                                      ScheduleEntry.end_at >= now, ScheduleEntry.start_at <= horizon,
                                                      ScheduleEntry.status != "Cancelled")).scalars().all()
    time_rows = db.execute(select(TimeEntry).where(TimeEntry.tenant_id.in_(principal.tenant_ids),
                                                   TimeEntry.started_at >= week_start)).scalars().all()
    people: dict[str, dict] = {}

    def person(email: str) -> dict:
        return people.setdefault(email, {"member": email, "openTickets": 0, "p1p2": 0, "overdue": 0, "dueToday": 0,
                                         "scheduledHours": 0.0, "loggedHoursThisWeek": 0.0, "billableHoursThisWeek": 0.0})

    for m in psa.members(db, list(principal.tenant_ids)):
        person(m["email"])["name"] = m["name"]
    for t in tickets:
        if t.status in psa.closed_statuses(boards.get(t.board_id)):
            continue
        row = person(t.assignee)
        row["openTickets"] += 1
        row["p1p2"] += t.priority in ("P1", "P2")
        if t.sla_due_at and t.sla_due_at < now:
            row["overdue"] += 1
        elif t.sla_due_at and t.sla_due_at < now + timedelta(hours=24):
            row["dueToday"] += 1
    for s in schedule:
        start, end = max(s.start_at, now), min(s.end_at, horizon)
        if end > start:
            person(s.member)["scheduledHours"] += (end - start).total_seconds() / 3600
    for e in time_rows:
        row = person(e.member)
        row["loggedHoursThisWeek"] += e.hours or 0
        if e.billable == "Billable":
            row["billableHoursThisWeek"] += e.hours or 0
    capacity = WEEKLY_CAPACITY_HOURS * days / 7
    for row in people.values():
        row.setdefault("name", row["member"])
        row["scheduledHours"] = round(row["scheduledHours"], 1)
        row["loggedHoursThisWeek"] = round(row["loggedHoursThisWeek"], 1)
        row["billableHoursThisWeek"] = round(row["billableHoursThisWeek"], 1)
        row["bookedPercent"] = round(row["scheduledHours"] / capacity * 100) if capacity else 0
        row["utilisationPercent"] = round(row["billableHoursThisWeek"] / WEEKLY_CAPACITY_HOURS * 100)
    unassigned = sum(1 for t in db.execute(select(Ticket).where(Ticket.tenant_id.in_(principal.tenant_ids),
                                                               Ticket.assignee == "")).scalars()
                     if t.status not in psa.closed_statuses(boards.get(t.board_id)))
    return {"days": days, "capacityHours": capacity, "unassignedOpen": unassigned,
            "members": sorted(people.values(), key=lambda r: (-r["overdue"], -r["openTickets"], r["member"]))}


@router.get("/psa/changes")
def list_changes(include_closed: bool = False, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Change calendar: changes by planned start, with their approval state."""
    principal.require("read")
    query = select(Ticket).where(Ticket.tenant_id.in_(principal.tenant_ids), Ticket.record_type == "change")
    if not include_closed:
        query = query.where(Ticket.change_state != "Closed")
    rows = db.execute(query).scalars().all()
    rows.sort(key=lambda t: (t.planned_start is None, t.planned_start or t.created_at))
    return [{"id": t.id, "number": t.number, "subject": t.subject, "accountTenantId": t.account_tenant_id,
             "changeState": t.change_state or "Draft", "changeRisk": t.change_risk or "", "plannedStart": t.planned_start,
             "plannedEnd": t.planned_end, "approvals": len([a for a in t.change_approvals or [] if a.get("decision") == "approve"]),
             "approvalsNeeded": 2 if t.change_risk == "High" else 1, "assignee": t.assignee} for t in rows]
