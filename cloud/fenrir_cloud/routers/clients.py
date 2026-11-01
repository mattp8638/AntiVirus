"""Client 360 API (client360.py): a customer's health score and trend, and its monthly and quarterly reports."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, client360
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import ClientHealthSnapshot, ClientReport, Tenant

router = APIRouter(prefix="/api/console/clients", tags=["Client 360"])


def _customer(db: Session, principal: Principal, tenant_id: str) -> Tenant:
    principal.require("read")
    tenant = db.get(Tenant, tenant_id)
    if tenant is None or tenant.id not in principal.tenant_ids or tenant.kind != "customer":
        raise HTTPException(404, "Not found")
    return tenant


def _finance(principal: Principal) -> bool:
    return principal.can("billing") or principal.can("crm")


@router.get("/health")
def all_health(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The latest daily score of every customer in scope, for lists."""
    principal.require("read")
    latest: dict[str, ClientHealthSnapshot] = {}
    for row in db.execute(select(ClientHealthSnapshot).where(ClientHealthSnapshot.tenant_id.in_(principal.tenant_ids))
                          .order_by(ClientHealthSnapshot.at)).scalars():
        latest[row.tenant_id] = row
    return {tid: {"score": row.score, "at": row.at.isoformat() + "Z"} for tid, row in latest.items()}


@router.get("/{tenant_id}/health")
def client_health(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    tenant = _customer(db, principal, tenant_id)
    report = client360.health(db, tenant, client360.cost_rate_for(db, tenant), finance=_finance(principal))
    return {**report, "trend": client360.trend(db, tenant.id)}


@router.get("/{tenant_id}/reports")
def list_reports(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    tenant = _customer(db, principal, tenant_id)
    rows = db.execute(select(ClientReport).where(ClientReport.tenant_id == tenant.id).order_by(ClientReport.created_at.desc())
                      .limit(48)).scalars().all()
    return [{"id": r.id, "kind": r.kind, "period": r.period, "createdBy": r.created_by, "createdAt": r.created_at.isoformat() + "Z"}
            for r in rows]


@router.get("/{tenant_id}/reports/monthly.html", response_class=HTMLResponse)
def monthly(tenant_id: str, month: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    tenant = _customer(db, principal, tenant_id)
    try:
        _, body = client360.monthly_report(db, tenant, client360._msp_name(db, tenant), client360.cost_rate_for(db, tenant), month)
    except ValueError:
        raise HTTPException(400, "month must look like 2026-09") from None
    return HTMLResponse(body)


@router.get("/{tenant_id}/reports/quarterly.html", response_class=HTMLResponse)
def quarterly(tenant_id: str, quarter: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    tenant = _customer(db, principal, tenant_id)
    try:
        _, body = client360.quarterly_review(db, tenant, client360._msp_name(db, tenant), client360.cost_rate_for(db, tenant), quarter)
    except ValueError:
        raise HTTPException(400, "quarter must look like 2026-Q3") from None
    return HTMLResponse(body)


@router.post("/{tenant_id}/reports")
def save_report(tenant_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Keep a copy of a report as it was sent to the customer (monthly reports are also kept automatically)."""
    tenant = _customer(db, principal, tenant_id)
    if not (principal.can("crm") or principal.can("respond")):
        raise HTTPException(403, "Forbidden")
    kind, period = str(body.get("kind") or ""), body.get("period") or None
    rate, msp = client360.cost_rate_for(db, tenant), client360._msp_name(db, tenant)
    try:
        if kind == "monthly":
            key, html = client360.monthly_report(db, tenant, msp, rate, period)
        elif kind == "quarterly":
            key, html = client360.quarterly_review(db, tenant, msp, rate, period)
        else:
            raise HTTPException(400, "kind must be monthly or quarterly")
    except ValueError:
        raise HTTPException(400, "period must look like 2026-09 or 2026-Q3") from None
    row = ClientReport(tenant_id=tenant.id, kind=kind, period=key, html=html, created_by=principal.actor)
    db.add(row)
    db.flush()
    audit.record(db, principal.actor, "client.report_saved", tenant.name, tenant.id, kind=kind, period=key)
    db.commit()
    return {"id": row.id, "kind": kind, "period": key}


@router.get("/{tenant_id}/reports/{report_id}.html", response_class=HTMLResponse)
def saved_report(tenant_id: str, report_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    tenant = _customer(db, principal, tenant_id)
    row = db.get(ClientReport, report_id)
    if row is None or row.tenant_id != tenant.id:
        raise HTTPException(404, "Not found")
    return HTMLResponse(row.html)
