"""Microsoft 365 reports and their email schedules (m365_reports.py)."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from .. import audit, crypto, m365_reports as reports
from ..m365_admin import unexpected
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import M365Connection, Tenant
from .documentation import owned

router = APIRouter(prefix="/api/console/m365", tags=["Microsoft 365 reports"])


class Schedule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reports: list[str] = Field(min_length=1, max_length=len(reports.REPORTS))
    every: Literal["weekly", "monthly"] = "monthly"
    to: list[str] = Field(min_length=1, max_length=20)


class Schedules(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    schedules: list[Schedule] = Field(default_factory=list, max_length=10)


def _connection(db: Session, ident: str, principal: Principal) -> M365Connection:
    principal.require("m365_admin")
    return owned(db, M365Connection, ident, principal)


def _build(row, key):
    try:
        return reports.build(row, key)
    except reports.ReportError as exc:
        raise HTTPException(400, str(exc)) from None
    except (ValueError, crypto.VaultError) as exc:
        raise HTTPException(400, f"The connection cannot sign in: {exc}") from None
    except Exception as exc:
        raise unexpected(exc, "Microsoft 365 reports") from None


@router.get("/reports")
def catalogue(principal: Principal = Depends(current_principal)):
    principal.require("read")
    return [{"key": k, "title": t} for k, t in reports.REPORTS.items()]


@router.get("/connections/{connection_id}/reports/{key}")
def report(connection_id: str, key: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return _build(_connection(db, connection_id, principal), key)


@router.get("/connections/{connection_id}/reports/{key}/csv")
def report_csv(connection_id: str, key: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = _connection(db, connection_id, principal)
    data = _build(row, key)
    audit.record(db, principal.actor, "m365.report.exported", key, row.tenant_id, connection=row.id, rows=len(data["rows"]))
    db.commit()
    return Response(reports.to_csv(data), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{key}.csv"', "Cache-Control": "no-store"})


@router.get("/report-schedules")
def get_schedules(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "Not found")
    return {"schedules": (tenant.settings or {}).get("m365Reports") or []}


@router.put("/report-schedules")
def put_schedules(body: Schedules, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("m365_admin")
    principal.check_tenant(body.tenantId)
    tenant = db.get(Tenant, body.tenantId)
    if tenant is None:
        raise HTTPException(404, "Not found")
    for schedule in body.schedules:
        if any(k not in reports.REPORTS for k in schedule.reports):
            raise HTTPException(422, "Unknown report")
        if any("@" not in t or len(t) > 254 for t in schedule.to):
            raise HTTPException(422, "Recipients are email addresses")
    old = {tuple(s.get("reports") or []): s.get("lastSentAt") for s in (tenant.settings or {}).get("m365Reports") or []}
    value = [{**s.model_dump(), "lastSentAt": old.get(tuple(s.reports))} for s in body.schedules]
    tenant.settings = {**(tenant.settings or {}), "m365Reports": value}
    audit.record(db, principal.actor, "m365.report_schedules.updated", tenant.name, tenant.id, schedules=len(value))
    db.commit()
    return {"schedules": value}
