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

@router.delete("/monitors/{monitor_id}")
def delete_monitor(monitor_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Stop checking a service and forget the monitor; alerts it raised stay in the alert history, resolved."""
    from ..models import Alert, utcnow

    principal.require("configure")
    row = owned(db, NetworkMonitor, monitor_id, principal)
    for alert in db.execute(select(Alert).where(Alert.tenant_id == row.tenant_id, Alert.rule_id == "network:" + row.id,
                                                Alert.status.in_(("new", "triaged")))).scalars():
        alert.status, alert.updated_at = "resolved", utcnow()
        alert.details = {**(alert.details or {}), "autoResolved": "The monitor was deleted."}
    db.delete(row)
    audit.record(db, principal.actor, "network.deleted", row.id, row.tenant_id, name=row.name)
    db.commit()
    return {"ok": True}

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


# --------------------------------------------------------------------------- switch-port topology: SNMP credentials
import ipaddress as _ipaddress  # noqa: E402
import json as _json  # noqa: E402
from typing import Literal  # noqa: E402

from fastapi import Request  # noqa: E402

from .. import crypto  # noqa: E402
from ..deps import current_device, require_reauth  # noqa: E402
from ..models import Command, NetworkSnmpCredential, utcnow  # noqa: E402

agent = APIRouter(prefix="/api/v1", tags=["Network topology (agent)"])


def _snmp_view(row: NetworkSnmpCredential) -> dict:
    return {"id": row.id, "tenantId": row.tenant_id, "name": row.name, "version": row.version, "username": row.username,
            "authProtocol": row.auth_protocol, "privProtocol": row.priv_protocol, "hosts": row.hosts or [],
            "hasSecret": bool(row.secret_envelope), "lastResult": row.last_result or {},
            "updatedAt": row.updated_at.isoformat() + "Z"}


class SnmpCredentialInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    name: str = Field(default="", max_length=200)
    version: Literal["2c", "3"] = "2c"
    hosts: list[str] = Field(min_length=1, max_length=64)
    community: str | None = Field(default=None, max_length=200)
    username: str = Field(default="", max_length=200)
    authProtocol: Literal["", "SHA", "SHA256", "SHA512", "MD5"] = ""
    authPassword: str | None = Field(default=None, max_length=200)
    privProtocol: Literal["", "AES", "AES256", "DES"] = ""
    privPassword: str | None = Field(default=None, max_length=200)

    @field_validator("hosts")
    @classmethod
    def private_ipv4(cls, hosts: list[str]) -> list[str]:
        out = []
        for host in hosts:
            try:
                ip = _ipaddress.ip_address(host.strip())
            except ValueError:
                raise ValueError(f"{host} is not an IP address")
            if ip.version != 4 or not ip.is_private:
                raise ValueError(f"{host} is not a private IPv4 address: Fenrir only reads switches on the customer's own network")
            out.append(str(ip))
        return sorted(set(out))


def _apply_snmp(row: NetworkSnmpCredential, body: SnmpCredentialInput, existing: dict) -> None:
    secret = dict(existing)
    for field in ("community", "authPassword", "privPassword"):
        value = getattr(body, field)
        if value is not None:
            secret[field] = value
    if body.version == "2c" and not secret.get("community"):
        raise HTTPException(400, "SNMP v2c needs a community string")
    if body.version == "3":
        if not body.username:
            raise HTTPException(400, "SNMP v3 needs a username")
        if body.privProtocol and not body.authProtocol:
            raise HTTPException(400, "SNMP v3 privacy needs authentication too")
        for proto, key in ((body.authProtocol, "authPassword"), (body.privProtocol, "privPassword")):
            if proto and len(secret.get(key) or "") < 8:
                raise HTTPException(400, "SNMP v3 passphrases must be at least 8 characters")
    row.name, row.version, row.hosts = body.name.strip() or f"SNMP v{body.version}", body.version, body.hosts
    row.username, row.auth_protocol, row.priv_protocol = body.username.strip(), body.authProtocol, body.privProtocol
    if body.version == "2c":
        secret = {"community": secret.get("community", "")}
    row.secret_envelope = crypto.encrypt(_json.dumps(secret), f"snmp:{row.tenant_id}:{row.id}")
    row.updated_at = utcnow()


@router.get("/snmp-credentials")
def list_snmp(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    principal.check_tenant(tenant_id)
    rows = db.execute(select(NetworkSnmpCredential).where(NetworkSnmpCredential.tenant_id == tenant_id).order_by(NetworkSnmpCredential.name)).scalars()
    return [_snmp_view(r) for r in rows]


@router.post("/snmp-credentials")
def create_snmp(body: SnmpCredentialInput, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    principal.check_tenant(body.tenantId)
    require_reauth(request, principal)
    row = NetworkSnmpCredential(tenant_id=body.tenantId, created_by=principal.actor)
    db.add(row)
    db.flush()
    _apply_snmp(row, body, {})
    audit.record(db, principal.actor, "topology.snmp_credential_created", row.name, row.tenant_id, version=row.version, hosts=len(row.hosts))
    db.commit()
    return _snmp_view(row)


@router.put("/snmp-credentials/{credential_id}")
def update_snmp(credential_id: str, body: SnmpCredentialInput, request: Request, principal: Principal = Depends(current_principal),
                db: Session = Depends(get_db)):
    """Secrets left out are kept; send a new one to replace it."""
    principal.require("configure")
    row = owned(db, NetworkSnmpCredential, credential_id, principal)
    if body.tenantId != row.tenant_id:
        raise HTTPException(400, "A credential cannot move to another customer")
    require_reauth(request, principal)
    from .. import topology

    _apply_snmp(row, body, topology.snmp_secret(row))
    audit.record(db, principal.actor, "topology.snmp_credential_updated", row.name, row.tenant_id, version=row.version, hosts=len(row.hosts))
    db.commit()
    return _snmp_view(row)


@router.delete("/snmp-credentials/{credential_id}")
def delete_snmp(credential_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = owned(db, NetworkSnmpCredential, credential_id, principal)
    audit.record(db, principal.actor, "topology.snmp_credential_deleted", row.name, row.tenant_id)
    db.delete(row)
    db.commit()
    return {"ok": True}


@agent.post("/devices/{device_id}/commands/{command_id}/snmp-credentials")
def release_snmp(command_id: str, device: Device = Depends(current_device), db: Session = Depends(get_db)):
    """Switch credentials for one discovery command, released once, only to the probe device it was sent to."""
    from .. import topology

    command = db.get(Command, command_id)
    if command is None:
        raise HTTPException(404, "Not found")
    try:
        credentials = topology.snmp_credentials_for_command(db, device, command)
    except LookupError as exc:
        db.commit()
        raise HTTPException(404, str(exc)) from exc
    db.commit()
    return {"credentials": credentials}
