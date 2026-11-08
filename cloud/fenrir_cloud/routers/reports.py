"""Customer reports (reports.py): every kind as branded HTML or PDF, and report schedules emailed as PDFs."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from .. import audit, ratelimit, reports
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import Tenant

router = APIRouter(prefix="/api/console/reports", tags=["Reports"])


def _customer(db: Session, principal: Principal, tenant_id: str | None) -> Tenant:
    tid = tenant_id or principal.user.tenant_id
    principal.require("read")
    principal.check_tenant(tid)
    tenant = db.get(Tenant, tid)
    if tenant is None:
        raise HTTPException(404, "Not found")
    return tenant


def _build(db: Session, tenant: Tenant, kind: str, days: int, period: str | None) -> tuple[str, dict]:
    if kind not in reports.KINDS:
        raise HTTPException(404, "No such report")
    if kind in ("monthly", "quarterly") and tenant.kind != "customer":
        raise HTTPException(400, "Monthly and quarterly reports are made for customers")
    try:
        return reports.build(db, tenant, kind, days=days, period=period)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


@router.get("/kinds")
def kinds(principal: Principal = Depends(current_principal)):
    principal.require("read")
    return [{"kind": key, "description": text} for key, text in reports.KINDS.items()]


@router.get("/{kind}.html", response_class=HTMLResponse)
def report_html(kind: str, tenant_id: str | None = None, days: int = 30, period: str | None = None,
                principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    tenant = _customer(db, principal, tenant_id)
    _, doc = _build(db, tenant, kind, days, period)
    return HTMLResponse(reports.html(db, tenant, doc))


@router.get("/{kind}.pdf")
def report_pdf(kind: str, tenant_id: str | None = None, days: int = 30, period: str | None = None,
               principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    tenant = _customer(db, principal, tenant_id)
    ratelimit.check(f"report-pdf:{principal.user.id}", 30, 60)  # PDFs take real work to draw
    key, doc = _build(db, tenant, kind, days, period)
    return Response(reports.pdf(db, tenant, doc), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{reports.filename(tenant, kind, key)}"'})


@router.get("/schedules")
def get_schedules(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    tenant = _customer(db, principal, tenant_id)
    return {"tenantId": tenant.id, "schedules": (tenant.settings or {}).get("reportSchedules") or [],
            "kinds": reports.KINDS, "every": sorted(reports.EVERY)}


@router.put("/schedules")
def put_schedules(tenant_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    """Replace a customer's report schedules. Each sends once per week, month or quarter, as a PDF attachment."""
    tenant = _customer(db, principal, tenant_id)
    principal.require("configure")
    if tenant.kind != "customer":
        raise HTTPException(400, "Report schedules are set per customer")
    previous = {s.get("id"): s for s in (tenant.settings or {}).get("reportSchedules") or [] if isinstance(s, dict)}
    try:
        schedules = reports.validate_schedules(body.get("schedules"))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    for schedule in schedules:  # delivery state is the server's, not the client's
        old = previous.get(schedule["id"]) or {}
        unchanged = old and (old.get("kind"), old.get("every")) == (schedule["kind"], schedule["every"])
        for key in ("lastPeriod", "lastSentAt", "lastError"):
            schedule[key] = old.get(key) if unchanged else None
    tenant.settings = {**(tenant.settings or {}), "reportSchedules": schedules}
    audit.record(db, principal.actor, "report.schedules_updated", tenant.name, tenant.id,
                 schedules=[{"kind": s["kind"], "every": s["every"], "recipients": len(s["to"])} for s in schedules])
    db.commit()
    return {"tenantId": tenant.id, "schedules": schedules}


@router.post("/schedules/{schedule_id}/send")
def send_now(schedule_id: str, tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Send a scheduled report now (to check it), without changing when it next goes out."""
    tenant = _customer(db, principal, tenant_id)
    principal.require("configure")
    ratelimit.check(f"report-send:{tenant.id}", 10, 3600)
    schedule = next((s for s in (tenant.settings or {}).get("reportSchedules") or [] if s.get("id") == schedule_id), None)
    if schedule is None:
        raise HTTPException(404, "Not found")
    period = reports.deliver(db, tenant, schedule)
    audit.record(db, principal.actor, "report.sent_now", tenant.name, tenant.id, kind=schedule["kind"], recipients=len(schedule["to"]))
    db.commit()
    return {"sent": len(schedule["to"]), "period": period}
