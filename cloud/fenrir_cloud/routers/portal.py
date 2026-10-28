"""Client portal: customers raise and follow tickets, read public KB articles and see invoices."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import audit, psa, services
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import Board, Contact, Device, Invoice, KbArticle, Tenant, Ticket, utcnow
from ..serialize import to_dict

router = APIRouter(prefix="/api/portal", tags=["Client portal"])


def _portal(principal: Principal = Depends(current_principal)) -> Principal:
    # Staff can open the portal too (to see what customers see); everyone else needs the portal permission.
    if not (principal.can("portal") or principal.can("read")):
        raise HTTPException(403, "No portal access")
    return principal


def _public_ticket(db: Session, ticket: Ticket) -> dict:
    board = db.get(Board, ticket.board_id) if ticket.board_id else None
    return {"id": ticket.id, "number": ticket.number, "subject": ticket.subject, "description": ticket.description,
            "status": ticket.status, "priority": ticket.priority, "closed": ticket.status in psa.closed_statuses(board),
            "createdAt": to_dict(ticket)["createdAt"], "updatedAt": to_dict(ticket)["updatedAt"], "assignee": ticket.assignee or "",
            "notes": [{"at": c.get("at"), "by": c.get("by"), "text": c.get("text"), "kind": c.get("kind", "discussion")}
                      for c in ticket.comments or [] if not c.get("internal") and c.get("kind") != "system"]}


def _account(principal: Principal) -> str:
    return principal.user.tenant_id


@router.get("/me")
def portal_me(principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    tenant = db.get(Tenant, _account(principal))
    owner = db.get(Tenant, services.msp_tenant_id(db, tenant.id)) if tenant else None
    return {"user": {"email": principal.user.email, "name": principal.user.name}, "company": tenant.name if tenant else "",
            "provider": owner.name if owner else "", "supportPhone": (owner.settings or {}).get("phone", "") if owner else ""}


@router.get("/tickets")
def portal_tickets(principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    rows = db.execute(select(Ticket).where(Ticket.account_tenant_id == _account(principal))
                      .order_by(Ticket.created_at.desc()).limit(500)).scalars()
    return [_public_ticket(db, t) for t in rows]


@router.post("/tickets")
def portal_create(body: dict = Body(...), principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    subject = str(body.get("subject") or "").strip()
    if not subject:
        raise HTTPException(400, "Please give your request a subject")
    urgency = str(body.get("urgency") or "Medium").title()
    impact = str(body.get("impact") or "Low").title()
    priority = psa.priority_for(impact, urgency) or "P3"
    contact = db.execute(select(Contact).where(Contact.email == principal.user.email,
                                               Contact.account_tenant_id == _account(principal))).scalars().first()
    ticket = services.open_ticket(db, _account(principal), subject, str(body.get("description") or ""), priority, "portal",
                                  principal.user.name or principal.user.email, impact=impact, urgency=urgency,
                                  contact_email=principal.user.email, contact_id=contact.id if contact else None)
    psa.notify_contact(ticket, f"We have received your request and logged it as ticket #{ticket.number}.",
                       "You can follow progress in the portal or reply to this email.")
    audit.record(db, principal.actor, "portal.ticket.created", f"#{ticket.number}", ticket.account_tenant_id)
    db.commit()
    return _public_ticket(db, ticket)


@router.get("/tickets/{ticket_id}")
def portal_ticket(ticket_id: str, principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    ticket = db.get(Ticket, ticket_id)
    if ticket is None or ticket.account_tenant_id != _account(principal):
        raise HTTPException(404, "Not found")
    return _public_ticket(db, ticket)


@router.post("/tickets/{ticket_id}/reply")
def portal_reply(ticket_id: str, body: dict = Body(...), principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    ticket = db.get(Ticket, ticket_id)
    if ticket is None or ticket.account_tenant_id != _account(principal):
        raise HTTPException(404, "Not found")
    text = str(body.get("text") or "").strip()
    if not text:
        raise HTTPException(400, "Write a reply first")
    psa.add_note(db, ticket, principal.user.email, text, "discussion", staff=False)
    board = db.get(Board, ticket.board_id) if ticket.board_id else None
    responded = next((s["name"] for s in (board.statuses if board else []) or [] if s.get("customerResponded")), None)
    if body.get("close"):
        psa.set_status(db, ticket, "Closed", principal.user.email)
    elif psa.is_closed(db, ticket):
        psa.set_status(db, ticket, responded or "Open", principal.user.email)
    elif responded:
        psa.set_status(db, ticket, responded, principal.user.email)
    psa.run_workflows(db, ticket, "ticket.updated")
    ticket.updated_at = utcnow()
    db.commit()
    return _public_ticket(db, ticket)


@router.get("/kb")
def portal_kb(q: str | None = None, principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    owner = services.msp_tenant_id(db, _account(principal))
    query = select(KbArticle).where(KbArticle.tenant_id == owner, KbArticle.public.is_(True))
    if q:
        query = query.where(or_(KbArticle.title.ilike(f"%{q}%"), KbArticle.body.ilike(f"%{q}%")))
    return [to_dict(a) for a in db.execute(query.order_by(KbArticle.category, KbArticle.title)).scalars()]


@router.get("/invoices")
def portal_invoices(principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    rows = db.execute(select(Invoice).where(Invoice.account_tenant_id == _account(principal), Invoice.status != "Draft")
                      .order_by(Invoice.created_at.desc())).scalars()
    return [to_dict(i) for i in rows]


@router.get("/devices")
def portal_devices(principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    rows = db.execute(select(Device).where(Device.tenant_id == _account(principal), Device.approved.is_(True))).scalars()
    now = utcnow()
    return [{"id": d.id, "hostname": d.hostname, "osVersion": d.os_version, "healthState": d.health_state,
             "online": bool(d.last_seen_at and (now - d.last_seen_at).total_seconds() < 300),
             "loggedOnUser": (d.metrics or {}).get("loggedOnUser", "")} for d in rows]
