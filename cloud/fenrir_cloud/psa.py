"""Professional services automation, modelled on how ConnectWise Manage works.

Service boards (statuses, types/subtypes/items, teams), an impact x urgency
priority matrix, respond/resolve SLAs measured in business hours, workflow
rules, email-to-ticket with threaded replies, time entries with agreement
coverage, and the dispatch calendar.
"""

from __future__ import annotations

import email
import email.policy
import email.utils
import imaplib
import logging
import os
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit, mailer
from .models import Board, Contact, Contract, Tenant, Ticket, TimeEntry, User, WorkflowRule, utcnow

log = logging.getLogger("fenrir.psa")

DEFAULT_STATUSES = [
    {"name": "New", "closed": False, "default": True},
    {"name": "Open", "closed": False},
    {"name": "In Progress", "closed": False},
    {"name": "Scheduled", "closed": False},
    {"name": "Waiting Customer", "closed": False, "pausesSla": True},
    {"name": "Customer Responded", "closed": False, "customerResponded": True},
    {"name": "Waiting Vendor", "closed": False, "pausesSla": True},
    {"name": "Escalated", "closed": False},
    {"name": "Resolved", "closed": True},
    {"name": "Closed", "closed": True},
]
CLOSED_DEFAULT = {"Resolved", "Closed", "Completed", "Cancelled"}

DEFAULT_TYPES = [
    {"name": "Incident", "subtypes": [{"name": "Hardware", "items": ["Laptop", "Desktop", "Printer", "Peripheral"]},
                                      {"name": "Software", "items": ["Microsoft 365", "Line of business", "Browser", "Other"]},
                                      {"name": "Network", "items": ["Internet", "Wi-Fi", "VPN", "Firewall"]},
                                      {"name": "Security", "items": ["Malware", "Phishing", "Account compromise"]}]},
    {"name": "Service Request", "subtypes": [{"name": "User", "items": ["New starter", "Leaver", "Password reset", "Access change"]},
                                             {"name": "Device", "items": ["New device", "Move", "Software install"]}]},
    {"name": "Problem", "subtypes": [{"name": "Root cause", "items": []}]},
    {"name": "Change", "subtypes": [{"name": "Standard", "items": []}, {"name": "Emergency", "items": []}]},
    {"name": "Alert", "subtypes": [{"name": "Monitoring", "items": ["CPU", "Disk", "Offline", "Service"]},
                                   {"name": "Security", "items": ["Detection", "Incident"]}]},
]

DEFAULT_BOARDS = [
    ("Service Desk", "P3", "Remote Support"),
    ("Projects", "P3", "Project Work"),
    ("Security Operations", "P2", "Security Response"),
    ("Monitoring Alerts", "P3", "Remote Support"),
]

WORK_TYPES = ["Remote Support", "Onsite Support", "Travel", "After Hours", "Project Work", "Security Response", "Admin", "Training"]
AFTER_HOURS_TYPES = {"After Hours"}

PRIORITY_MATRIX = {
    ("High", "High"): "P1", ("High", "Medium"): "P2", ("Medium", "High"): "P2",
    ("High", "Low"): "P3", ("Medium", "Medium"): "P3", ("Low", "High"): "P3",
    ("Medium", "Low"): "P4", ("Low", "Medium"): "P4", ("Low", "Low"): "P4",
}
DEFAULT_RESPOND_HOURS = {"P1": 0.25, "P2": 1, "P3": 4, "P4": 8}
DEFAULT_RESOLVE_HOURS = {"P1": 4, "P2": 8, "P3": 24, "P4": 72}
DEFAULT_BUSINESS_HOURS = {"days": [0, 1, 2, 3, 4], "start": 9, "end": 17, "tz": "Europe/London", "p1AllHours": True}

TICKET_REF = re.compile(r"\[(?:ticket\s*)?#\s*(\d{3,})\]|ticket\s*#\s*(\d{3,})", re.IGNORECASE)


# --------------------------------------------------------------------------- boards


def ensure_default_boards(db: Session, tenant_id: str) -> list[Board]:
    boards = db.execute(select(Board).where(Board.tenant_id == tenant_id)).scalars().all()
    if boards:
        return list(boards)
    created = []
    for name, priority, work_type in DEFAULT_BOARDS:
        board = Board(tenant_id=tenant_id, name=name, statuses=[dict(s) for s in DEFAULT_STATUSES],
                      types=[dict(t) for t in DEFAULT_TYPES], default_priority=priority, default_work_type=work_type)
        db.add(board)
        created.append(board)
    db.flush()
    return created


def board_by_name(db: Session, tenant_id: str, name: str | None) -> Board | None:
    boards = ensure_default_boards(db, tenant_id)
    if name:
        for board in boards:
            if board.name.lower() == name.lower():
                return board
    return next((b for b in boards if b.name == "Service Desk"), boards[0] if boards else None)


def closed_statuses(board: Board | None) -> set[str]:
    if board is None:
        return set(CLOSED_DEFAULT)
    return {s["name"] for s in board.statuses or [] if s.get("closed")} | CLOSED_DEFAULT


def default_status(board: Board | None) -> str:
    if board is None:
        return "New"
    return next((s["name"] for s in board.statuses or [] if s.get("default")), (board.statuses or [{"name": "New"}])[0]["name"])


def is_closed(db: Session, ticket: Ticket) -> bool:
    board = db.get(Board, ticket.board_id) if ticket.board_id else None
    return ticket.status in closed_statuses(board)


def priority_for(impact: str | None, urgency: str | None) -> str | None:
    if not impact or not urgency:
        return None
    return PRIORITY_MATRIX.get((impact.title(), urgency.title()))


def next_round_robin(db: Session, board: Board) -> str:
    members = [m for m in board.members or [] if m]
    if not members:
        return ""
    member = members[board.rr_index % len(members)]
    board.rr_index = (board.rr_index + 1) % len(members)
    return member


# --------------------------------------------------------------------------- SLA


def _zone(name: str | None):
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name or "UTC")
    except Exception:  # noqa: BLE001
        return timezone.utc


def add_business_hours(start_utc: datetime, hours: float, business: dict | None) -> datetime:
    """Add working hours to a UTC time, skipping nights and non-working days."""
    bh = {**DEFAULT_BUSINESS_HOURS, **(business or {})}
    if bh.get("allHours"):
        return start_utc + timedelta(hours=hours)
    tz = _zone(bh.get("tz"))
    days = {int(d) for d in bh.get("days", [0, 1, 2, 3, 4])} or {0, 1, 2, 3, 4}
    day_start, day_end = float(bh.get("start", 9)), float(bh.get("end", 17))
    remaining = timedelta(hours=hours)
    current = start_utc.replace(tzinfo=timezone.utc).astimezone(tz)
    for _ in range(3660):  # bounded: at most ~10 years of days
        open_at = current.replace(hour=int(day_start), minute=int((day_start % 1) * 60), second=0, microsecond=0)
        close_at = current.replace(hour=int(day_end) % 24, minute=int((day_end % 1) * 60), second=0, microsecond=0)
        if day_end >= 24:
            close_at = (current + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        if current.weekday() in days and current < close_at:
            begin = max(current, open_at)
            available = close_at - begin
            if remaining <= available:
                return (begin + remaining).astimezone(timezone.utc).replace(tzinfo=None)
            remaining -= available
        current = (current + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return start_utc + timedelta(hours=hours)


def active_agreement(db: Session, account_tenant_id: str | None) -> Contract | None:
    if not account_tenant_id:
        return None
    return db.execute(select(Contract).where(Contract.account_tenant_id == account_tenant_id, Contract.active.is_(True))
                      .order_by(Contract.created_at)).scalars().first()


def sla_targets(db: Session, ticket: Ticket) -> tuple[datetime, datetime]:
    """(respond_due, resolve_due) for a ticket from its agreement, priority and business hours."""
    contract = db.get(Contract, ticket.agreement_id) if ticket.agreement_id else active_agreement(db, ticket.account_tenant_id)
    sla = (contract.sla if contract else None) or {}
    resolve = dict(DEFAULT_RESOLVE_HOURS)
    resolve.update({k: v for k, v in sla.items() if k in DEFAULT_RESOLVE_HOURS})
    resolve.update(sla.get("resolve") or {})
    respond = {**DEFAULT_RESPOND_HOURS, **(sla.get("respond") or {})}
    business = dict((contract.business_hours if contract else None) or {})
    if not contract:
        business["allHours"] = True  # no agreement: plain clock hours, as before boards existed
    if ticket.priority == "P1" and business.get("p1AllHours", True):
        business["allHours"] = True
    start = ticket.created_at or utcnow()
    return (add_business_hours(start, float(respond.get(ticket.priority, 4)), business),
            add_business_hours(start, float(resolve.get(ticket.priority, 24)), business))


def apply_sla(db: Session, ticket: Ticket) -> None:
    ticket.respond_due_at, ticket.sla_due_at = sla_targets(db, ticket)


# --------------------------------------------------------------------------- notes, history and email


def add_note(db: Session, ticket: Ticket, by: str, text: str, kind: str = "discussion", email_contact: bool = False,
             staff: bool = True) -> dict:
    """Add a Discussion, Internal or Resolution note (ConnectWise's three note flags)."""
    kind = kind if kind in {"discussion", "internal", "resolution"} else "discussion"
    note = {"at": utcnow().isoformat(), "by": by, "text": text, "kind": kind, "internal": kind == "internal"}
    ticket.comments = (ticket.comments or []) + [note]
    ticket.updated_at = utcnow()
    if staff and kind != "internal" and ticket.responded_at is None:
        ticket.responded_at = utcnow()
    if email_contact and kind != "internal" and ticket.contact_email:
        notify_contact(ticket, f"Update on ticket #{ticket.number}", text)
    return note


def ticket_subject(ticket: Ticket) -> str:
    return f"[Ticket #{ticket.number}] {ticket.subject}"


def notify_contact(ticket: Ticket, heading: str, text: str) -> None:
    if not ticket.contact_email:
        return
    body = (f"{heading}\n\n{text}\n\n"
            f"Status: {ticket.status}\nPriority: {ticket.priority}\n\n"
            f"Reply to this email to update the ticket. Keep [Ticket #{ticket.number}] in the subject.")
    mailer.send(ticket.contact_email, ticket_subject(ticket), body, in_reply_to=ticket.email_thread_id or None)


def set_status(db: Session, ticket: Ticket, status: str, by: str) -> None:
    if status == ticket.status:
        return
    old = ticket.status
    ticket.status = status
    ticket.status_changed_at = utcnow()
    board = db.get(Board, ticket.board_id) if ticket.board_id else None
    closed = closed_statuses(board)
    if status in closed and not ticket.resolved_at:
        ticket.resolved_at = utcnow()
        if ticket.contact_email:
            notify_contact(ticket, f"Ticket #{ticket.number} has been resolved", _resolution_text(ticket))
    elif status not in closed:
        ticket.resolved_at = None
    if old in {"New"} and status not in {"New"} and ticket.responded_at is None:
        ticket.responded_at = utcnow()
    ticket.comments = (ticket.comments or []) + [{"at": utcnow().isoformat(), "by": by, "kind": "system", "internal": True,
                                                  "text": f"Status changed from {old} to {status}"}]


def _resolution_text(ticket: Ticket) -> str:
    resolutions = [c["text"] for c in ticket.comments or [] if c.get("kind") == "resolution"]
    return resolutions[-1] if resolutions else "Your ticket has been resolved. Reply to this email if anything is still wrong."


# --------------------------------------------------------------------------- workflow rules


def _field_value(db: Session, ticket: Ticket, field: str):
    if field == "board":
        board = db.get(Board, ticket.board_id) if ticket.board_id else None
        return board.name if board else ""
    if field == "account":
        tenant = db.get(Tenant, ticket.account_tenant_id) if ticket.account_tenant_id else None
        return tenant.name if tenant else ""
    if field == "assignee_empty":
        return "true" if not ticket.assignee else "false"
    return getattr(ticket, field, "") if hasattr(ticket, field) else ""


def _matches(db: Session, ticket: Ticket, conditions: list[dict]) -> bool:
    for cond in conditions or []:
        actual = str(_field_value(db, ticket, str(cond.get("field", ""))) or "")
        expected = cond.get("value", "")
        op = cond.get("op", "equals")
        if op == "equals" and actual.lower() != str(expected).lower():
            return False
        if op == "not_equals" and actual.lower() == str(expected).lower():
            return False
        if op == "contains" and str(expected).lower() not in actual.lower():
            return False
        if op == "in" and actual.lower() not in [str(v).lower() for v in (expected if isinstance(expected, list) else str(expected).split(","))]:
            return False
    return True


SETTABLE = {"status", "priority", "assignee", "team", "type", "subtype", "item", "board_id", "queue"}


def _run_actions(db: Session, rule: WorkflowRule, ticket: Ticket) -> None:
    actor = f"workflow:{rule.name}"
    for action in rule.actions or []:
        kind = action.get("type")
        if kind == "set" and action.get("field") in SETTABLE:
            if action["field"] == "status":
                set_status(db, ticket, str(action.get("value")), actor)
            else:
                setattr(ticket, action["field"], action.get("value"))
                if action["field"] == "priority":
                    apply_sla(db, ticket)
        elif kind == "note":
            add_note(db, ticket, actor, str(action.get("text") or ""), str(action.get("kind") or "internal"),
                     email_contact=bool(action.get("emailContact")), staff=False)
        elif kind == "email_contact" and ticket.contact_email:
            text = _template(str(action.get("body") or ""), ticket)
            mailer.send(ticket.contact_email, _template(str(action.get("subject") or ticket_subject(ticket)), ticket), text,
                        in_reply_to=ticket.email_thread_id or None)
        elif kind == "notify":
            to = str(action.get("to") or ticket.assignee or "")
            if to:
                mailer.send(to, f"[Fenrir PSA] {ticket_subject(ticket)}",
                            _template(str(action.get("body") or "Ticket #{number} needs attention: {subject}"), ticket))
        elif kind == "assign":
            if action.get("member") == "round_robin":
                board = db.get(Board, ticket.board_id) if ticket.board_id else None
                ticket.assignee = next_round_robin(db, board) if board else ticket.assignee
            else:
                ticket.assignee = str(action.get("member") or "")
    rule.runs = (rule.runs or 0) + 1
    ticket.updated_at = utcnow()
    audit.record(db, actor, "psa.workflow.ran", f"#{ticket.number}", ticket.account_tenant_id)


def _template(text: str, ticket: Ticket) -> str:
    return (text.replace("{number}", str(ticket.number)).replace("{subject}", ticket.subject).replace("{status}", ticket.status)
            .replace("{priority}", ticket.priority).replace("{assignee}", ticket.assignee or "unassigned"))


def run_workflows(db: Session, ticket: Ticket, trigger: str) -> int:
    rules = db.execute(select(WorkflowRule).where(WorkflowRule.tenant_id == ticket.tenant_id, WorkflowRule.enabled.is_(True),
                                                  WorkflowRule.trigger == trigger)).scalars().all()
    ran = 0
    for rule in rules:
        if rule.board_id and rule.board_id != ticket.board_id:
            continue
        if _matches(db, ticket, rule.conditions):
            _run_actions(db, rule, ticket)
            ran += 1
    return ran


def _fire_once(ticket: Ticket, marker: str) -> bool:
    fired = list(ticket.workflow_fired or [])
    if marker in fired:
        return False
    ticket.workflow_fired = (fired + [marker])[-50:]
    return True


def timed_workflows(db: Session, now: datetime | None = None) -> int:
    """Idle-status rules and SLA warning/breach rules. Runs from the maintenance loop."""
    now = now or utcnow()
    count = 0
    rules = db.execute(select(WorkflowRule).where(WorkflowRule.enabled.is_(True),
                                                  WorkflowRule.trigger.in_(("ticket.idle", "sla.warning", "sla.breached")))).scalars().all()
    if not rules:
        return 0
    tenants = {r.tenant_id for r in rules}
    tickets = db.execute(select(Ticket).where(Ticket.tenant_id.in_(tenants), Ticket.status.notin_(tuple(CLOSED_DEFAULT)))).scalars().all()
    for ticket in tickets:
        if is_closed(db, ticket):
            continue
        for rule in rules:
            if rule.tenant_id != ticket.tenant_id or (rule.board_id and rule.board_id != ticket.board_id):
                continue
            if rule.trigger == "ticket.idle":
                since = ticket.status_changed_at or ticket.updated_at or ticket.created_at
                if not rule.idle_hours or now - since < timedelta(hours=rule.idle_hours):
                    continue
                marker = f"{rule.id}:{ticket.status}:{since.isoformat()}"
            elif rule.trigger == "sla.warning":
                if not ticket.sla_due_at:
                    continue
                total = (ticket.sla_due_at - ticket.created_at).total_seconds()
                if total <= 0 or (now - ticket.created_at).total_seconds() < 0.75 * total or now >= ticket.sla_due_at:
                    continue
                marker = f"{rule.id}:warn"
            else:
                if not ticket.sla_due_at or now < ticket.sla_due_at:
                    continue
                marker = f"{rule.id}:breach"
            if _matches(db, ticket, rule.conditions) and _fire_once(ticket, marker):
                _run_actions(db, rule, ticket)
                count += 1
    return count


# --------------------------------------------------------------------------- email to ticket


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def match_account(db: Session, msp_tenant_id: str, from_address: str) -> tuple[str, Contact | None]:
    """Find the customer for a sender: exact contact, then a contact with the same domain, then the tenant's domains."""
    address = from_address.lower()
    contact = db.execute(select(Contact).where(Contact.tenant_id == msp_tenant_id, func.lower(Contact.email) == address)).scalars().first()
    if contact and contact.account_tenant_id:
        return contact.account_tenant_id, contact
    domain = _domain(address)
    if domain and domain not in {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "live.com"}:
        for other in db.execute(select(Contact).where(Contact.tenant_id == msp_tenant_id, Contact.email.ilike(f"%@{domain}"))).scalars():
            if other.account_tenant_id:
                return other.account_tenant_id, None
        for tenant in db.execute(select(Tenant).where(Tenant.parent_id == msp_tenant_id)).scalars():
            domains = [d.lower() for d in (tenant.settings or {}).get("emailDomains", [])]
            if domain in domains:
                return tenant.id, None
    return msp_tenant_id, None


def process_inbound_email(db: Session, msp_tenant_id: str, message: dict) -> dict:
    """Create or update a ticket from an inbound email.

    ``message``: {"from", "fromName", "to", "subject", "text", "messageId", "inReplyTo", "autoSubmitted"}
    """
    from . import services

    sender = str(message.get("from") or "").strip().lower()
    subject = str(message.get("subject") or "(no subject)").strip()[:300]
    text = str(message.get("text") or "").strip()
    if not sender or sender == mailer.sender().lower():
        return {"action": "ignored", "reason": "own address"}
    if message.get("autoSubmitted") and str(message.get("autoSubmitted")).lower() not in {"no", ""}:
        return {"action": "ignored", "reason": "auto-submitted"}
    body = _strip_quoted(text)

    ticket = None
    ref = TICKET_REF.search(subject)
    if ref:
        number = int(ref.group(1) or ref.group(2))
        ticket = db.execute(select(Ticket).where(Ticket.tenant_id == msp_tenant_id, Ticket.number == number)).scalar_one_or_none()
    if ticket is None and message.get("inReplyTo"):
        ticket = db.execute(select(Ticket).where(Ticket.tenant_id == msp_tenant_id,
                                                 Ticket.email_thread_id == str(message["inReplyTo"]))).scalars().first()
    if ticket is not None:
        add_note(db, ticket, sender, body or "(empty reply)", "discussion", staff=False)
        board = db.get(Board, ticket.board_id) if ticket.board_id else None
        responded = next((s["name"] for s in (board.statuses if board else []) or [] if s.get("customerResponded")), None)
        if is_closed(db, ticket):
            set_status(db, ticket, responded or "Open", "email")  # a reply re-opens the ticket
        elif responded:
            set_status(db, ticket, responded, "email")
        run_workflows(db, ticket, "ticket.updated")
        audit.record(db, sender, "psa.email.reply", f"#{ticket.number}", ticket.account_tenant_id)
        return {"action": "updated", "ticketId": ticket.id, "number": ticket.number}

    account_id, contact = match_account(db, msp_tenant_id, sender)
    to = str(message.get("to") or "").lower()
    boards = ensure_default_boards(db, msp_tenant_id)
    board = next((b for b in boards if b.mailbox and b.mailbox.lower() in to), None) or board_by_name(db, msp_tenant_id, "Service Desk")
    ticket = services.open_ticket(db, account_id, subject, body, board.default_priority if board else "P3", "email",
                                  str(message.get("fromName") or sender), queue=board.name if board else "Service Desk")
    ticket.contact_email = sender
    ticket.contact_id = contact.id if contact else None
    ticket.email_thread_id = str(message.get("messageId") or "")[:300]
    db.flush()
    notify_contact(ticket, f"We have received your request and logged it as ticket #{ticket.number}.",
                   "A member of the team will be in touch shortly.")
    audit.record(db, sender, "psa.email.ticket", f"#{ticket.number}", account_id)
    return {"action": "created", "ticketId": ticket.id, "number": ticket.number}


def _strip_quoted(text: str) -> str:
    """Drop the quoted history below a reply."""
    lines = []
    for line in text.splitlines():
        if line.startswith(">") or re.match(r"^On .+ wrote:$", line.strip()) or line.strip() in {"-----Original Message-----"}:
            break
        if re.match(r"^From: .+", line.strip()) and lines:
            break
        lines.append(line)
    return "\n".join(lines).strip()


def parse_rfc822(raw: bytes) -> dict:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    name, address = email.utils.parseaddr(str(msg.get("From", "")))
    text = ""
    part = msg.get_body(preferencelist=("plain", "html"))
    if part is not None:
        text = part.get_content()
        if part.get_content_type() == "text/html":
            text = re.sub(r"<[^>]+>", " ", text)
    return {"from": address, "fromName": name, "to": str(msg.get("To", "")), "subject": str(msg.get("Subject", "")),
            "text": text, "messageId": str(msg.get("Message-ID", "")), "inReplyTo": str(msg.get("In-Reply-To", "") or ""),
            "autoSubmitted": str(msg.get("Auto-Submitted", "") or "")}


def poll_imap(db: Session, msp_tenant_id: str) -> int:
    """Fetch unseen mail from FENRIR_IMAP_* and turn it into tickets. Returns messages processed."""
    host = os.getenv("FENRIR_IMAP_HOST")
    if not host:
        return 0
    processed = 0
    try:
        with imaplib.IMAP4_SSL(host, int(os.getenv("FENRIR_IMAP_PORT", "993"))) as imap:
            imap.login(os.getenv("FENRIR_IMAP_USER", ""), os.getenv("FENRIR_IMAP_PASSWORD", ""))
            imap.select(os.getenv("FENRIR_IMAP_FOLDER", "INBOX"))
            _, data = imap.search(None, "UNSEEN")
            for num in (data[0] or b"").split()[:50]:
                _, parts = imap.fetch(num, "(RFC822)")
                raw = next((p[1] for p in parts if isinstance(p, tuple)), None)
                if raw:
                    process_inbound_email(db, msp_tenant_id, parse_rfc822(raw))
                    processed += 1
                imap.store(num, "+FLAGS", "\\Seen")
    except (OSError, imaplib.IMAP4.error) as exc:  # pragma: no cover - network dependent
        log.warning("IMAP poll failed: %s", exc)
    return processed


# --------------------------------------------------------------------------- time


def round_hours(hours: float, increment: float = 0.25) -> float:
    if hours <= 0:
        return 0.0
    steps = -(-hours // increment)  # ceiling
    return round(steps * increment, 2)


def coverage(contract: Contract | None, work_type: str) -> bool:
    """Is this work type included in the agreement (subject to its hours allowance)?"""
    if contract is None:
        return False
    if (contract.agreement_type or "Managed Services") == "Time & Materials":
        return False
    if work_type in AFTER_HOURS_TYPES and not contract.covers_after_hours:
        return False
    covered = contract.covered_work_types or []
    return not covered or work_type in covered


def create_time_entry(db: Session, *, member: str, owner_tenant_id: str, account_tenant_id: str | None, hours: float | None = None,
                      started_at: datetime | None = None, ended_at: datetime | None = None, ticket: Ticket | None = None,
                      project_id: str | None = None, work_type: str = "Remote Support", notes: str = "", internal_notes: str = "",
                      billable: str = "Billable", remote_session_id: str | None = None, work_role: str = "Engineer") -> TimeEntry:
    if hours is None:
        if not (started_at and ended_at) or ended_at <= started_at:
            raise ValueError("give hours, or a start and an end time")
        hours = (ended_at - started_at).total_seconds() / 3600
    hours = round(float(hours), 2)
    if hours <= 0 or hours > 24:
        raise ValueError("hours must be between 0 and 24")
    started_at = started_at or (utcnow() - timedelta(hours=hours))
    contract = None
    if ticket is not None and ticket.agreement_id:
        contract = db.get(Contract, ticket.agreement_id)
    if contract is None:
        contract = active_agreement(db, account_tenant_id)
    entry = TimeEntry(tenant_id=owner_tenant_id, account_tenant_id=account_tenant_id, member=member,
                      charge_to="ticket" if ticket else ("project" if project_id else "activity"),
                      ticket_id=ticket.id if ticket else None, project_id=project_id or (ticket.project_id if ticket else None),
                      remote_session_id=remote_session_id, work_type=work_type, work_role=work_role, started_at=started_at,
                      ended_at=ended_at or started_at + timedelta(hours=hours), hours=hours, hours_billed=round_hours(hours),
                      billable=billable if billable in {"Billable", "Do Not Bill", "No Charge"} else "Billable", notes=notes,
                      internal_notes=internal_notes, agreement_id=contract.id if contract else None,
                      covered=coverage(contract, work_type), rate=float(contract.hourly_rate) if contract else 0.0)
    db.add(entry)
    if ticket is not None:
        ticket.time_minutes = int((ticket.time_minutes or 0) + round(hours * 60))
        if notes:
            add_note(db, ticket, member, notes, "discussion" if billable != "No Charge" else "internal")
        ticket.updated_at = utcnow()
    return entry


def members(db: Session, tenant_ids: list[str]) -> list[dict]:
    rows = db.execute(select(User).where(User.tenant_id.in_(tenant_ids), User.active.is_(True), User.role != "client")).scalars().all()
    return [{"email": u.email, "name": u.name or u.email, "role": u.role} for u in rows]
