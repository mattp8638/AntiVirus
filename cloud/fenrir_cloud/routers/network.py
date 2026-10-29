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


# --------------------------------------------------------------------------- topology discovery (topology.py)
from fastapi import Body  # noqa: E402

from .. import services, topology  # noqa: E402
from ..models import NetworkNode, Tenant  # noqa: E402


@router.post("/discover")
def discover(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Run discovery from one device, or from every approved device of a customer."""
    principal.require("respond")
    if body.get("deviceId"):
        device = db.get(Device, str(body["deviceId"]))
        if device is None or device.tenant_id not in principal.tenant_ids:
            raise HTTPException(404, "Not found")
        devices = [device]
    else:
        devices = db.scalars(select(Device).where(Device.tenant_id.in_(scoped_tenant(principal, body.get("tenantId"))),
                                                  Device.approved.is_(True))).all()
    queued, skipped = [], []
    for device in devices[:500]:
        try:
            queued.append(topology.request_discovery(db, device, principal.actor, sweep=bool(body.get("sweep", True))).id)
        except services.CommandError as exc:
            skipped.append({"deviceId": device.id, "reason": str(exc)})
    audit.record(db, principal.actor, "topology.discovery_requested", f"{len(queued)} devices", devices[0].tenant_id if devices else None)
    db.commit()
    return {"queued": len(queued), "skipped": skipped}


@router.get("/topology")
def topology_graph(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    return {**topology.graph(db, tenant_id), "settings": ((tenant.settings or {}).get("topology") or {}) if tenant else {}}


@router.put("/topology/settings")
def topology_settings(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Which devices re-run discovery on a schedule for this customer."""
    principal.require("configure")
    tenant_id = str(body.get("tenantId") or "")
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "Not found")
    probes = [str(d) for d in body.get("probeDeviceIds") or []][:20]
    for device_id in probes:
        _probe_device(db, tenant_id, device_id)
    config = {"probeDeviceIds": probes, "intervalHours": max(1, min(int(body.get("intervalHours") or 24), 168)),
              "sweep": bool(body.get("sweep", True))}
    tenant.settings = {**(tenant.settings or {}), "topology": config}
    audit.record(db, principal.actor, "topology.settings", tenant.name, tenant.id, probes=len(probes))
    db.commit()
    return config


@router.patch("/nodes/{node_id}")
def update_node(node_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = owned(db, NetworkNode, node_id, principal)
    if "ignored" in body:
        row.ignored = bool(body["ignored"])
    if body.get("kind") in ("gateway", "server", "workstation", "printer", "network", "virtual", "iot", "camera", "unknown"):
        row.kind = body["kind"]
    audit.record(db, principal.actor, "topology.node_updated", row.ip, row.tenant_id, ignored=row.ignored, kind=row.kind)
    db.commit()
    return to_dict(row)


@router.post("/nodes/{node_id}/monitor")
def monitor_node(node_id: str, body: dict = Body(default={}), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Watch an unmanaged node (printer, switch, NAS) from a device on its network."""
    principal.require("configure")
    row = owned(db, NetworkNode, node_id, principal)
    port = int(body.get("port") or (row.open_ports or [0])[0] or 0)
    if not 0 < port < 65536:
        raise HTTPException(422, "Choose a port to check; none was found open on this node")
    probe = next((d for d in row.seen_by or [] if db.get(Device, d) is not None), None)
    monitor = NetworkMonitor(tenant_id=row.tenant_id, name=str(body.get("name") or row.hostname or row.ip)[:200], address=row.ip,
                             port=port, interval_seconds=300, probe_device_id=probe)
    db.add(monitor)
    db.flush()
    audit.record(db, principal.actor, "network.created", monitor.id, monitor.tenant_id, fromTopology=row.id)
    db.commit()
    return to_dict(monitor)
