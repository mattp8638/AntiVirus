from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session
from .. import audit, network, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import Configuration, Device, NetworkMonitor
from ..serialize import to_dict
from .documentation import owned

router = APIRouter(prefix="/api/console/network", tags=["Network monitoring"])

class MonitorInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    name: str = Field(min_length=1, max_length=200)
    address: str
    port: int = Field(ge=1, le=65535)
    intervalSeconds: int = Field(default=300, ge=60, le=86400)
    configurationId: str | None = None
    probeDeviceId: str | None = None

    @field_validator("address")
    @classmethod
    def address_valid(cls, value):
        return network.validate_address(value)

class MonitorState(BaseModel):
    enabled: bool | None = None
    probeDeviceId: str | None = None


def _probe_device(db, tenant_id, device_id):
    if not device_id:
        return None
    device = db.get(Device, device_id)
    if device is None or device.tenant_id != tenant_id:
        raise HTTPException(404, "Probe device not found in this tenant")
    return device.id

@router.get("/monitors")
def monitors(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    return [to_dict(row) for row in db.scalars(select(NetworkMonitor).where(NetworkMonitor.tenant_id.in_(scoped_tenant(principal, tenant_id))).limit(2000))]

@router.post("/monitors")
def create(body: MonitorInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    principal.check_tenant(body.tenantId)
    if body.configurationId:
        config = db.get(Configuration, body.configurationId)
        if config is None or config.account_tenant_id != body.tenantId:
            raise HTTPException(404, "Configuration not found in this tenant")
    row = NetworkMonitor(tenant_id=body.tenantId, name=body.name, address=body.address, port=body.port,
                         interval_seconds=body.intervalSeconds, configuration_id=body.configurationId,
                         probe_device_id=_probe_device(db, body.tenantId, body.probeDeviceId))
    db.add(row)
    db.flush()
    audit.record(db, principal.actor, "network.created", row.id, row.tenant_id)
    db.commit()
    return to_dict(row)

@router.patch("/monitors/{monitor_id}")
def enable(monitor_id: str, body: MonitorState, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = owned(db, NetworkMonitor, monitor_id, principal)
    if body.enabled is not None:
        row.enabled = body.enabled
        audit.record(db, principal.actor, "network.enabled" if row.enabled else "network.disabled", row.id, row.tenant_id)
    if "probeDeviceId" in body.model_fields_set:
        row.probe_device_id = _probe_device(db, row.tenant_id, body.probeDeviceId)
        row.state, row.failures = "unknown", 0
        audit.record(db, principal.actor, "network.probe_changed", row.id, row.tenant_id, probeDeviceId=row.probe_device_id)
    db.commit()
    return to_dict(row)

@router.post("/monitors/{monitor_id}/check")
def check(monitor_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = owned(db, NetworkMonitor, monitor_id, principal)
    ratelimit.check(f"network-check:{principal.user.id}", 20, 300)
    network.check(db, row)
    audit.record(db, principal.actor, "network.checked", row.id, row.tenant_id, state=row.state)
    db.commit()
    return to_dict(row)
