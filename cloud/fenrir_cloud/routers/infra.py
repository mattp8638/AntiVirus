"""Hypervisor and virtual infrastructure monitoring (RMM-14)."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, infra
from ..db import get_db
from ..deps import Principal, current_device, current_principal, require_reauth, scoped_tenant
from ..models import Command, Device, InfraAsset, InfraSource
from ..serialize import to_dict

router = APIRouter(prefix="/api/console/infrastructure", tags=["Infrastructure monitoring"])
agent_router = APIRouter(prefix="/api/v1", tags=["Agent API"])


def _out(s: InfraSource) -> dict:
    d = to_dict(s)
    d.pop("credentialsEnvelope", None)
    return d


def _source(db, ident, p) -> InfraSource:
    s = db.get(InfraSource, ident)
    if s is None or s.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Source not found")
    return s


class NewSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    name: str = Field(min_length=1, max_length=200)
    provider: Literal["proxmox", "vsphere"]
    baseUrl: str = Field(max_length=300)
    route: Literal["direct", "agent"] = "agent"
    probeDeviceId: str | None = None
    credentials: dict
    tlsInsecure: bool = False
    pollMinutes: int = Field(default=5, ge=1, le=1440)


@router.post("/sources")
def create(body: NewSource, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    p.check_tenant(body.tenantId)
    require_reauth(request, p)
    try:
        url = infra.validate_url(body.baseUrl)
    except infra.InfraError as exc:
        raise HTTPException(400, str(exc)) from None
    if body.route == "agent":
        probe = db.get(Device, body.probeDeviceId or "")
        if probe is None or probe.tenant_id != body.tenantId:
            raise HTTPException(400, "Choose a probe device of this customer on the same network")
    s = InfraSource(tenant_id=body.tenantId, name=body.name, provider=body.provider, base_url=url, route=body.route,
                    probe_device_id=body.probeDeviceId if body.route == "agent" else None, tls_insecure=body.tlsInsecure,
                    poll_minutes=body.pollMinutes, created_by=p.actor)
    db.add(s)
    db.flush()
    try:
        infra.store_credentials(s, body.credentials)
    except infra.InfraError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from None
    audit.record(db, p.actor, "infra.source_added", s.id, body.tenantId, provider=body.provider, route=body.route, baseUrl=url)
    db.commit()
    return _out(s)


@router.get("/sources")
def list_sources(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    rows = db.scalars(select(InfraSource).where(InfraSource.tenant_id.in_(scoped_tenant(p, tenantId))))
    return [_out(s) for s in rows]


@router.get("/sources/{ident}/assets")
def assets(ident: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    s = _source(db, ident, p)
    rows = db.scalars(select(InfraAsset).where(InfraAsset.source_id == s.id).order_by(InfraAsset.kind, InfraAsset.name))
    return [to_dict(a) for a in rows]


@router.post("/sources/{ident}/poll")
def poll_now(ident: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    s = _source(db, ident, p)
    out = infra.poll(db, s, p.actor)
    db.commit()
    return {**out, "source": _out(s)}


class Expected(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expectedState: Literal["running", "stopped", ""]


@router.put("/assets/{asset_id}/expected")
def set_expected(asset_id: str, body: Expected, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    a = db.get(InfraAsset, asset_id)
    if a is None or a.tenant_id not in p.tenant_ids or a.kind != "vm":
        raise HTTPException(404, "Virtual machine not found")
    a.expected_state = body.expectedState
    audit.record(db, p.actor, "infra.expected_state", a.id, a.tenant_id, name=a.name, expected=body.expectedState or "not watched")
    db.commit()
    return to_dict(a)


@agent_router.post("/devices/{device_id}/commands/{command_id}/infra-credential")
def infra_credential(command_id: str, device: Device = Depends(current_device), db: Session = Depends(get_db)):
    """Base address and credential for one infra.poll command, released once, only to the device it was sent to."""
    command = db.get(Command, command_id)
    if command is None:
        raise HTTPException(404, "Not found")
    try:
        details = infra.credential_for_command(db, device, command)
    except infra.InfraError as exc:
        db.commit()
        raise HTTPException(404, str(exc)) from exc
    db.commit()
    return details
