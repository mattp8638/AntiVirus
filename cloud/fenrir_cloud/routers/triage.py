"""Triage inbox API (triage.py): list, owner, snooze, dismiss, raise a ticket, log time. Actions take several keys."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, psa, services, triage
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import Alert, Device, Incident, Ticket, utcnow
from ..serialize import to_dict

router = APIRouter(prefix="/api/console/triage", tags=["Triage inbox"])

MAX_SNOOZE_MINUTES = 7 * 24 * 60
MAX_KEYS = 200


@router.get("/items")
def list_items(view: str = "all", kind: str | None = None, severity: str | None = None, tenant_id: str | None = None,
               snoozed: str = "hide", q: str = "", principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """``view``: all | mine | unassigned. ``snoozed``: hide | only | all (dismissed items show with "only"/"all")."""
    principal.require("read")
    now = utcnow()
    kinds = tuple(k for k in (kind or "").split(",") if k in triage.KINDS) or triage.KINDS
    items = triage.collect(db, scoped_tenant(principal, tenant_id), principal.actor, kinds, now)
    me = principal.actor.lower()

    def mine(i: triage.Item) -> bool:
        return me in {o.strip().lower() for o in (i.owner or "").split(",")}

    hidden = lambda i: bool(i.snoozed_until or i.dismissed)  # noqa: E731
    open_items = [i for i in items if not hidden(i)]
    counts = {"open": len(open_items), "mine": sum(1 for i in open_items if mine(i)),
              "unassigned": sum(1 for i in open_items if not i.owner),
              "breached": sum(1 for i in open_items if i.sla_due and i.sla_due < now),
              "snoozed": sum(1 for i in items if hidden(i)),
              "byKind": {k: sum(1 for i in open_items if i.kind == k) for k in triage.KINDS}}
    if snoozed == "hide":
        items = open_items
    elif snoozed == "only":
        items = [i for i in items if hidden(i)]
    if view == "mine":
        items = [i for i in items if mine(i)]
    elif view == "unassigned":
        items = [i for i in items if not i.owner]
    if severity in triage.RANK:
        items = [i for i in items if triage.RANK[i.severity] <= triage.RANK[severity]]
    if q:
        needle = q.lower()
        items = [i for i in items if needle in f"{i.title} {i.summary} {i.owner or ''}".lower()]
    items = triage.order(items, now)[:500]
    customers, hosts = triage.names(db, items)
    return {"items": [triage.view(i, now, customers, hosts) for i in items], "counts": counts, "slaHours": triage.sla_hours(db)}


@router.get("/item")
def item_detail(key: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    now = utcnow()
    item = triage.find(db, principal, key)
    customers, hosts = triage.names(db, [item])
    devices = db.execute(select(Device).where(Device.id.in_(item.device_ids[:200]))).scalars().all() if item.device_ids else []
    return {**triage.view(item, now, customers, hosts),
            "devices": sorted(({"id": d.id, "hostname": d.hostname, "platform": d.platform, "approved": bool(d.approved),
                                "retired": d.api_key_hash == f"retired-{d.id}", "lastSeenAt": to_dict(d).get("lastSeenAt")} for d in devices),
                              key=lambda d: d["hostname"].lower())}


def _items(db: Session, principal: Principal, keys) -> list[triage.Item]:
    if not isinstance(keys, list) or not keys:
        raise HTTPException(400, "Choose at least one item")
    return triage.find_many(db, principal, [str(k) for k in dict.fromkeys(keys[:MAX_KEYS])])


def _member(db: Session, principal: Principal, who: str) -> str:
    who = who.strip()
    if who.lower() == "me":
        return principal.actor
    if not who:
        return ""
    members = {m["email"].lower(): m["email"] for m in psa.members(db, list(principal.tenant_ids))}
    if who.lower() not in members:
        raise HTTPException(400, "Items can only be given to a technician in your organisation")
    return members[who.lower()]


@router.post("/assign")
def assign(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Owner for each item ("me", an email, or "" for nobody). Alerts, incidents and tickets take it themselves."""
    principal.require("respond")
    who = _member(db, principal, str(body.get("owner") or ""))
    items = _items(db, principal, body.get("keys"))
    for item in items:
        if item.kind == "alert":
            for alert in db.execute(select(Alert).where(Alert.id.in_(item.refs))).scalars():
                alert.assignee, alert.updated_at = who or None, utcnow()
        elif item.kind == "incident":
            db.get(Incident, item.refs[0]).assignee = who
        elif item.kind == "ticket":
            ticket = db.get(Ticket, item.refs[0])
            ticket.assignee, ticket.updated_at = who, utcnow()
        else:
            triage.state_for(db, item).owner = who or None
        audit.record(db, principal.actor, "triage.assigned", item.key, item.tenant_id, owner=who)
    db.commit()
    return {"updated": len(items), "owner": who}


@router.post("/snooze")
def snooze(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Hide items for ``minutes`` (5 minutes to 7 days); 0 brings them back now, including ones marked done."""
    principal.require("respond")
    try:
        minutes = int(body.get("minutes"))
    except (TypeError, ValueError):
        raise HTTPException(400, "minutes must be a number") from None
    if minutes and not 5 <= minutes <= MAX_SNOOZE_MINUTES:
        raise HTTPException(400, "Snooze for between 5 minutes and 7 days")
    until = utcnow() + timedelta(minutes=minutes) if minutes else None
    items = _items(db, principal, body.get("keys"))
    for item in items:
        if item.kind == "alert":
            for alert in db.execute(select(Alert).where(Alert.id.in_(item.refs))).scalars():
                alert.snoozed_until, alert.snoozed_by = until, principal.actor if until else None
        else:
            state = triage.state_for(db, item)
            state.snoozed_until, state.snoozed_by = until, principal.actor if until else None
            if not minutes:  # back in the inbox, whether it was snoozed or marked done
                state.dismissed_marker = state.dismissed_by = state.dismissed_at = None
        audit.record(db, principal.actor, "triage.snoozed", item.key, item.tenant_id, minutes=minutes)
    db.commit()
    return {"updated": len(items), "snoozedUntil": until.isoformat() + "Z" if until else None}


@router.post("/dismiss")
def dismiss(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Done with these. Alerts are resolved; anything else stays hidden until it changes (a new device failing the
    same update, another requirement falling overdue). Decisions, incidents and tickets are closed on their own page."""
    principal.require("respond")
    items = _items(db, principal, body.get("keys"))
    refused = [i.title for i in items if i.kind not in triage.DISMISSIBLE]
    if refused:
        raise HTTPException(400, f"Decide or close these on their own page: {', '.join(refused[:5])}")
    for item in items:
        if item.kind == "alert":
            for alert in db.execute(select(Alert).where(Alert.id.in_(item.refs))).scalars():
                alert.status, alert.updated_at = "resolved", utcnow()
                audit.record(db, principal.actor, "alert.updated", alert.id, alert.tenant_id, status="resolved", via="triage")
        else:
            state = triage.state_for(db, item)
            state.dismissed_marker, state.dismissed_by, state.dismissed_at = item.marker, principal.actor, utcnow()
        audit.record(db, principal.actor, "triage.dismissed", item.key, item.tenant_id, kind=item.kind, count=item.count)
    db.commit()
    return {"updated": len(items)}


def _ticket_for(db: Session, principal: Principal, item: triage.Item) -> tuple[Ticket, bool]:
    """The item's open ticket, or a new one on the service desk. Returns (ticket, created)."""
    if item.ticket_id:
        ticket = db.get(Ticket, item.ticket_id)
        if ticket is not None and not psa.is_closed(db, ticket):
            return ticket, False
    hosts = dict(db.execute(select(Device.id, Device.hostname).where(Device.id.in_(item.device_ids[:50]))).all()) if item.device_ids else {}
    lines = [item.summary, "", f"Raised from the triage inbox by {principal.actor}."]
    if hosts:
        lines += ["", f"Devices ({len(item.device_ids)}):"] + [f"- {hosts.get(d, d)}" for d in item.device_ids[:50]]
    ticket = services.open_ticket(db, item.tenant_id, item.title, "\n".join(lines).strip(),
                                  priority=triage.SEVERITY_PRIORITY[item.severity], source="triage",
                                  device_id=item.device_ids[0] if len(item.device_ids) == 1 else None)
    if not ticket.assignee and item.owner and "," not in item.owner:
        ticket.assignee = item.owner
    if item.kind == "incident":
        incident = db.get(Incident, item.refs[0])
        incident.ticket_id = incident.ticket_id or ticket.id
    triage.state_for(db, item).ticket_id = ticket.id
    audit.record(db, principal.actor, "triage.ticket_created", item.key, item.tenant_id, ticket=ticket.number)
    return ticket, True


@router.post("/ticket")
def raise_ticket(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    if not (principal.can("respond") or principal.can("crm")):
        raise HTTPException(403, "Forbidden")
    items = _items(db, principal, body.get("keys") or ([body["key"]] if body.get("key") else []))
    tickets = [_ticket_for(db, principal, item) for item in items]
    db.commit()
    return {"tickets": [{"id": t.id, "number": t.number, "created": created} for t, created in tickets]}


@router.post("/time")
def log_time(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Bill time against the item: on its ticket, raising one first if it has none."""
    if not (principal.can("respond") or principal.can("crm")):
        raise HTTPException(403, "Forbidden")
    try:
        minutes = int(body.get("minutes"))
    except (TypeError, ValueError):
        raise HTTPException(400, "minutes must be a number") from None
    if not 1 <= minutes <= 24 * 60:
        raise HTTPException(400, "Log between 1 minute and 24 hours")
    item = triage.find(db, principal, str(body.get("key") or ""))
    ticket, _ = _ticket_for(db, principal, item)
    try:
        entry = psa.create_time_entry(db, member=principal.actor, owner_tenant_id=ticket.tenant_id, account_tenant_id=ticket.account_tenant_id,
                                      hours=minutes / 60, ticket=ticket, notes=str(body.get("notes") or "")[:2000],
                                      work_type=str(body.get("workType") or "Remote Support"),
                                      billable=str(body.get("billable") or "Billable"))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    db.flush()
    audit.record(db, principal.actor, "triage.time_logged", item.key, item.tenant_id, ticket=ticket.number, minutes=minutes)
    db.commit()
    return {"ticket": {"id": ticket.id, "number": ticket.number}, "entryId": entry.id, "hours": entry.hours}


@router.get("/settings")
def get_settings(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    return {"slaHours": triage.sla_hours(db), "defaults": triage.DEFAULT_SLA_HOURS}


@router.put("/settings")
def put_settings(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """How long each severity may wait before it is past SLA (tickets keep their board's SLA, approvals their expiry).
    One setting for the whole MSP, so a customer's own administrator cannot change it."""
    principal.require("configure")
    principal.require("manage_tenants")
    from ..platform_security import _msp

    hours = body.get("slaHours") or {}
    if not isinstance(hours, dict):
        raise HTTPException(400, "slaHours must be an object")
    clean = {}
    for severity, value in hours.items():
        if severity not in triage.DEFAULT_SLA_HOURS:
            raise HTTPException(400, f"Unknown severity {severity!r}")
        try:
            value = float(value)
        except (TypeError, ValueError):
            raise HTTPException(400, f"{severity} must be a number of hours") from None
        if not 0.25 <= value <= 24 * 90:
            raise HTTPException(400, f"{severity}: between 15 minutes and 90 days")
        clean[severity] = value
    msp = _msp(db)
    msp.settings = {**(msp.settings or {}), "triage": {**((msp.settings or {}).get("triage") or {}), "slaHours": clean}}
    audit.record(db, principal.actor, "triage.sla_updated", "triage", msp.id, slaHours=clean)
    db.commit()
    return {"slaHours": triage.sla_hours(db), "defaults": triage.DEFAULT_SLA_HOURS}
