"""CRM accounts: account owner, 360° view, timeline, profitability, M365 licences, opportunity pipeline.

Registered before the generic /crm/{kind} CRUD in business.py so these paths win.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import (Activity, Contact, Contract, Device, Invoice, M365Connection, Opportunity, Project, Tenant, Ticket,
                      TimeEntry, utcnow)
from ..serialize import to_dict

router = APIRouter(prefix="/api/console", tags=["CRM"])

OPEN_TICKET = ("Open", "In Progress", "Waiting", "New", "Scheduled")
DEFAULT_LABOUR_COST = 40.0  # per hour, when the MSP has not set crm.labourCostPerHour


def _account(db: Session, principal: Principal, tenant_id: str) -> Tenant:
    tenant = db.get(Tenant, tenant_id)
    if tenant is None or tenant.id not in principal.tenant_ids or tenant.kind == "msp":
        raise HTTPException(404, "Account not found")
    return tenant


def _labour_cost_rate(db: Session, principal: Principal) -> float:
    msp = db.get(Tenant, principal.user.tenant_id)
    try:
        return float(((msp.settings or {}).get("crm") or {}).get("labourCostPerHour") or DEFAULT_LABOUR_COST) if msp else DEFAULT_LABOUR_COST
    except (TypeError, ValueError):
        return DEFAULT_LABOUR_COST


def contracted_mrr(db: Session, account_id: str) -> float:
    devices = db.scalar(select(func.count()).select_from(Device).where(Device.tenant_id == account_id)) or 0
    total = 0.0
    for contract in db.execute(select(Contract).where(Contract.account_tenant_id == account_id, Contract.active.is_(True))).scalars():
        monthly = (contract.monthly_fee or 0) + (contract.price_per_device or 0) * devices
        cycle = (contract.billing_cycle or "Monthly").lower()
        # monthly_fee is per billing cycle; normalise to a month.
        if cycle == "quarterly":
            monthly = (contract.monthly_fee or 0) / 3 + (contract.price_per_device or 0) * devices
        elif cycle == "annually":
            monthly = (contract.monthly_fee or 0) / 12 + (contract.price_per_device or 0) * devices
        total += monthly
    return round(total, 2)


def profitability(db: Session, account_id: str, days: int, cost_rate: float) -> dict:
    since = utcnow() - timedelta(days=days)
    invoices = db.execute(select(Invoice).where(Invoice.account_tenant_id == account_id, Invoice.created_at >= since,
                                                Invoice.status.in_(("Sent", "Paid", "Overdue")))).scalars().all()
    revenue = round(sum(i.subtotal or 0 for i in invoices), 2)
    entries = db.execute(select(TimeEntry).where(TimeEntry.account_tenant_id == account_id, TimeEntry.started_at >= since)).scalars().all()
    hours = round(sum(e.hours or 0 for e in entries), 2)
    covered_hours = round(sum(e.hours or 0 for e in entries if e.covered), 2)
    unbilled = round(sum((e.hours_billed or e.hours or 0) * (e.rate or 0) for e in entries
                         if e.billable == "Billable" and not e.covered and e.status != "Billed"), 2)
    cost = round(hours * cost_rate, 2)
    margin = round(revenue - cost, 2)
    return {"days": days, "revenue": revenue, "labourHours": hours, "coveredHours": covered_hours, "labourCostRate": cost_rate,
            "labourCost": cost, "margin": margin, "marginPercent": round(margin / revenue * 100, 1) if revenue else None,
            "unbilledTime": unbilled, "invoiceCount": len(invoices),
            "outstanding": round(sum(i.total or 0 for i in invoices if i.status in ("Sent", "Overdue")), 2)}


def m365_licences(db: Session, account_id: str) -> dict | None:
    connection = db.execute(select(M365Connection).where(M365Connection.tenant_id == account_id)).scalars().first()
    if connection is None:
        return None
    skus = []
    for sku in (connection.snapshot or {}).get("licenses") or []:
        if not isinstance(sku, dict):
            continue
        purchased = int(((sku.get("prepaidUnits") or {}).get("enabled")) or 0)
        assigned = int(sku.get("consumedUnits") or 0)
        skus.append({"sku": sku.get("skuPartNumber") or sku.get("skuId") or "", "purchased": purchased, "assigned": assigned,
                     "unused": max(purchased - assigned, 0), "overAssigned": max(assigned - purchased, 0)})
    skus.sort(key=lambda s: -s["purchased"])
    return {"connectionId": connection.id, "status": connection.status, "syncedAt": connection.synced_at, "skus": skus,
            "purchased": sum(s["purchased"] for s in skus), "assigned": sum(s["assigned"] for s in skus),
            "unused": sum(s["unused"] for s in skus)}


def timeline(db: Session, account_id: str, limit: int = 100) -> list[dict]:
    items: list[dict] = []
    for a in db.execute(select(Activity).where(Activity.account_tenant_id == account_id)
                        .order_by(Activity.created_at.desc()).limit(limit)).scalars():
        items.append({"at": a.completed_at or a.created_at, "type": a.kind, "title": a.subject, "detail": a.body[:500],
                      "by": a.owner or a.created_by, "ref": a.id, "open": a.kind == "task" and a.completed_at is None,
                      "dueAt": a.due_at})
    for t in db.execute(select(Ticket).where(Ticket.account_tenant_id == account_id)
                        .order_by(Ticket.created_at.desc()).limit(limit)).scalars():
        items.append({"at": t.created_at, "type": "ticket", "title": f"#{t.number} {t.subject}", "detail": f"{t.priority} · {t.status}",
                      "by": t.requester, "ref": t.id, "open": t.status in OPEN_TICKET})
    for i in db.execute(select(Invoice).where(Invoice.account_tenant_id == account_id)
                        .order_by(Invoice.created_at.desc()).limit(limit)).scalars():
        items.append({"at": i.created_at, "type": "invoice", "title": f"Invoice {i.number}", "detail": f"{i.currency} {i.total:.2f} · {i.status}",
                      "by": "", "ref": i.id, "open": i.status in ("Sent", "Overdue")})
    for o in db.execute(select(Opportunity).where(Opportunity.account_tenant_id == account_id, Opportunity.closed_at.is_not(None))
                        .order_by(Opportunity.closed_at.desc()).limit(limit)).scalars():
        items.append({"at": o.closed_at, "type": "opportunity", "title": f"{o.stage}: {o.name}",
                      "detail": o.lost_reason if o.stage == "Lost" else f"{o.value:.2f} + {o.monthly_value:.2f}/month",
                      "by": o.owner, "ref": o.id, "open": False})
    items.sort(key=lambda item: item["at"] or datetime.min, reverse=True)
    return items[:limit]


@router.get("/crm/accounts")
def list_accounts(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    accounts = db.execute(select(Tenant).where(Tenant.id.in_(principal.tenant_ids), Tenant.kind == "customer")
                          .order_by(Tenant.name)).scalars().all()
    ids = [a.id for a in accounts]
    if not ids:
        return []
    devices = dict(db.execute(select(Device.tenant_id, func.count()).where(Device.tenant_id.in_(ids)).group_by(Device.tenant_id)).all())
    tickets = dict(db.execute(select(Ticket.account_tenant_id, func.count()).where(Ticket.account_tenant_id.in_(ids),
                              Ticket.status.in_(OPEN_TICKET)).group_by(Ticket.account_tenant_id)).all())
    pipeline = dict(db.execute(select(Opportunity.account_tenant_id, func.sum(Opportunity.value + Opportunity.monthly_value * 12))
                               .where(Opportunity.account_tenant_id.in_(ids), Opportunity.closed_at.is_(None))
                               .group_by(Opportunity.account_tenant_id)).all())
    last_touch = dict(db.execute(select(Activity.account_tenant_id, func.max(Activity.created_at))
                                 .where(Activity.account_tenant_id.in_(ids)).group_by(Activity.account_tenant_id)).all())
    open_tasks = dict(db.execute(select(Activity.account_tenant_id, func.count()).where(
        Activity.account_tenant_id.in_(ids), Activity.kind == "task", Activity.completed_at.is_(None))
        .group_by(Activity.account_tenant_id)).all())
    return [{"id": a.id, "name": a.name, "plan": a.plan, "accountOwner": a.account_owner or "", "devices": devices.get(a.id, 0),
             "openTickets": tickets.get(a.id, 0), "openPipeline": round(pipeline.get(a.id) or 0, 2),
             "mrr": contracted_mrr(db, a.id), "lastActivityAt": last_touch.get(a.id), "openTasks": open_tasks.get(a.id, 0)}
            for a in accounts]


@router.get("/crm/accounts/{tenant_id}")
def account_detail(tenant_id: str, days: int = Query(90, ge=7, le=730), principal: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)):
    principal.require("read")
    account = _account(db, principal, tenant_id)
    scope = principal.tenant_ids
    finance = principal.can("billing") or principal.can("crm")
    return {
        "account": {"id": account.id, "name": account.name, "plan": account.plan, "accountOwner": account.account_owner or "",
                    "createdAt": account.created_at},
        "devices": db.scalar(select(func.count()).select_from(Device).where(Device.tenant_id == account.id)) or 0,
        "contacts": [to_dict(c) for c in db.execute(select(Contact).where(Contact.account_tenant_id == account.id,
                                                                          Contact.tenant_id.in_(scope))).scalars()],
        "opportunities": [to_dict(o) for o in db.execute(select(Opportunity).where(Opportunity.account_tenant_id == account.id,
                                                                                   Opportunity.tenant_id.in_(scope))
                                                         .order_by(Opportunity.created_at.desc())).scalars()],
        "contracts": [to_dict(c) for c in db.execute(select(Contract).where(Contract.account_tenant_id == account.id)).scalars()],
        "projects": [to_dict(p) for p in db.execute(select(Project).where(Project.account_tenant_id == account.id)).scalars()],
        "openTickets": db.scalar(select(func.count()).select_from(Ticket).where(Ticket.account_tenant_id == account.id,
                                                                                Ticket.status.in_(OPEN_TICKET))) or 0,
        "mrr": contracted_mrr(db, account.id),
        "profitability": profitability(db, account.id, days, _labour_cost_rate(db, principal)) if finance else None,
        "m365": m365_licences(db, account.id),
        "timeline": timeline(db, account.id),
    }


@router.patch("/crm/accounts/{tenant_id}")
def update_account(tenant_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)):
    principal.require("crm")
    account = _account(db, principal, tenant_id)
    if "accountOwner" in body:
        account.account_owner = str(body.get("accountOwner") or "").strip()[:200] or None
    audit.record(db, principal.actor, "crm.account.updated", account.id, account.id, accountOwner=account.account_owner)
    db.commit()
    return {"id": account.id, "accountOwner": account.account_owner or ""}


@router.get("/crm/opportunity-pipeline")
def opportunity_pipeline(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Open deals by stage with weighted value (one-off + 12 months of recurring, times probability)."""
    principal.require("read")
    rows = db.execute(select(Opportunity).where(Opportunity.tenant_id.in_(principal.tenant_ids))).scalars().all()
    stages: dict[str, dict] = {}
    for opp in rows:
        total = (opp.value or 0) + (opp.monthly_value or 0) * 12
        bucket = stages.setdefault(opp.stage, {"stage": opp.stage, "count": 0, "value": 0.0, "weighted": 0.0})
        bucket["count"] += 1
        bucket["value"] = round(bucket["value"] + total, 2)
        bucket["weighted"] = round(bucket["weighted"] + total * (opp.probability or 0) / 100, 2)
    open_rows = [o for o in rows if o.closed_at is None]
    won_90 = [o for o in rows if o.stage == "Won" and o.closed_at and o.closed_at >= utcnow() - timedelta(days=90)]
    lost_90 = [o for o in rows if o.stage == "Lost" and o.closed_at and o.closed_at >= utcnow() - timedelta(days=90)]
    return {"stages": list(stages.values()),
            "openValue": round(sum((o.value or 0) + (o.monthly_value or 0) * 12 for o in open_rows), 2),
            "weightedValue": round(sum(((o.value or 0) + (o.monthly_value or 0) * 12) * (o.probability or 0) / 100 for o in open_rows), 2),
            "wonLast90Days": len(won_90), "lostLast90Days": len(lost_90),
            "winRate": round(len(won_90) / (len(won_90) + len(lost_90)) * 100, 1) if won_90 or lost_90 else None}
