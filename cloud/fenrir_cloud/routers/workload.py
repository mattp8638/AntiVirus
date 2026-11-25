"""Server and workload protection: file integrity monitoring and container posture (AV-21)."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, workload
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import Device, FimBaseline, Tenant, WorkloadReport
from ..serialize import to_dict

router = APIRouter(prefix="/api/console/workload", tags=["Workload protection"])


def _device(db, ident, p) -> Device:
    d = db.get(Device, ident)
    if d is None or d.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Device not found")
    return d


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fim: bool = False
    containers: bool = False
    paths: list[str] = Field(default_factory=list, max_length=200)


@router.put("/settings/{tenant_id}")
def save_settings(tenant_id: str, body: Settings, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    p.check_tenant(tenant_id)
    if any(not x.startswith("/") or ".." in x for x in body.paths):
        raise HTTPException(400, "Watched paths must be absolute")
    tenant = db.get(Tenant, tenant_id)
    tenant.settings = {**(tenant.settings or {}), "workloadMonitoring": body.model_dump()}
    audit.record(db, p.actor, "workload.settings_saved", tenant_id, tenant_id, **body.model_dump())
    db.commit()
    return body.model_dump()


@router.get("/settings/{tenant_id}")
def get_settings(tenant_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    p.check_tenant(tenant_id)
    return workload.settings(db, tenant_id)


class Scan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["fim", "containers"]


@router.post("/devices/{device_id}/scan")
def scan(device_id: str, body: Scan, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("respond")
    d = _device(db, device_id, p)
    try:
        cmd = workload.request(db, d, body.kind, p.actor)
    except workload.WorkloadError as exc:
        raise HTTPException(400, str(exc)) from None
    db.commit()
    return {"commandId": cmd.id}


@router.get("/devices/{device_id}")
def device_state(device_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    d = _device(db, device_id, p)
    reports = db.scalars(select(WorkloadReport).where(WorkloadReport.device_id == d.id).order_by(WorkloadReport.created_at.desc()).limit(20)).all()
    baseline = db.scalars(select(FimBaseline).where(FimBaseline.device_id == d.id)).first()
    out = []
    for r in reports:
        row = to_dict(r)
        row["data"] = {k: v for k, v in (r.data or {}).items() if k != "manifest"}
        out.append(row)
    return {"reports": out, "baseline": {"files": len(baseline.manifest), "setBy": baseline.set_by, "setAt": baseline.set_at} if baseline else None}


@router.post("/devices/{device_id}/accept-baseline")
def accept(device_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("respond")
    d = _device(db, device_id, p)
    try:
        b = workload.accept_baseline(db, d, p.actor)
    except workload.WorkloadError as exc:
        raise HTTPException(409, str(exc)) from None
    db.commit()
    return {"files": len(b.manifest), "setBy": b.set_by}
