"""Out-of-band management (Intel AMT / vPro) and cross-platform session routing."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import amt, audit, presence, remote, services
from ..db import get_db
from ..deps import Principal, current_device, current_principal, require_reauth, scoped_tenant
from ..models import AmtEndpoint, Command, Device, NetworkNode

router = APIRouter(prefix="/api/console", tags=["Out-of-band management"])
agent_router = APIRouter(prefix="/api/v1", tags=["Agent API"])

DESKTOP_PLATFORMS = {"windows", "macos", "linux"}
PORT_PROTOCOLS = {22: "SSH", 23: "Telnet", 80: "Web (HTTP)", 443: "Web (HTTPS)", 3389: "Remote Desktop (RDP)", 5900: "VNC",
                  8080: "Web (HTTP)", 8443: "Web (HTTPS)", 16992: "Intel AMT web UI", 16993: "Intel AMT web UI (TLS)",
                  16994: "Intel AMT redirection", 16995: "Intel AMT redirection (TLS)"}


def _owned(db: Session, principal: Principal, endpoint_id: str) -> AmtEndpoint:
    row = db.get(AmtEndpoint, endpoint_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    return row


def _probe(db: Session, tenant_id: str, device_id: str | None) -> str | None:
    if not device_id:
        return None
    device = db.get(Device, device_id)
    if device is None or device.tenant_id != tenant_id or not device.approved:
        raise HTTPException(422, "The relay device must be an approved device of the same customer")
    return device.id


def _hostnames(db: Session, rows: list[AmtEndpoint]) -> dict[str, str]:
    ids = {i for r in rows for i in (r.device_id, r.probe_device_id) if i}
    return dict(db.execute(select(Device.id, Device.hostname).where(Device.id.in_(ids))).all()) if ids else {}


@router.get("/oob/amt")
def list_amt(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    rows = db.execute(select(AmtEndpoint).where(AmtEndpoint.tenant_id.in_(scoped_tenant(principal, tenant_id)))
                      .order_by(AmtEndpoint.name, AmtEndpoint.host)).scalars().all()
    names = _hostnames(db, rows)
    return [amt.view(r, names) for r in rows]


@router.post("/oob/amt")
def create_amt(request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Register an AMT endpoint. Storing its admin password needs a fresh sign-in check."""
    principal.require("configure")
    require_reauth(request, principal)
    tenant_id = str(body.get("tenantId") or "")
    principal.check_tenant(tenant_id)
    row = AmtEndpoint(tenant_id=tenant_id, host="", created_by=principal.actor)
    _apply(db, row, body)
    if not body.get("password"):
        raise HTTPException(422, "The AMT admin password is required")
    db.add(row)
    db.flush()
    amt.set_password(row, str(body["password"]))
    audit.record(db, principal.actor, "amt.endpoint.created", row.name or row.host, tenant_id, endpoint=row.id, route=row.route)
    db.commit()
    return amt.view(row, _hostnames(db, [row]))


def _apply(db: Session, row: AmtEndpoint, body: dict) -> None:
    if "host" in body:
        host = str(body["host"] or "").strip()
        if not host or len(host) > 255 or any(c in host for c in "/?#@ "):
            raise HTTPException(422, "Enter the AMT host name or IP address")
        row.host = host
    if "port" in body:
        if int(body["port"] or 0) not in amt.PORTS:
            raise HTTPException(422, "AMT listens on 16992 (HTTP) or 16993 (TLS)")
        row.port = int(body["port"])
    for field, attr in (("name", "name"), ("username", "username")):
        if field in body:
            setattr(row, attr, str(body[field] or "")[:200] or ("admin" if field == "username" else ""))
    if "tlsInsecure" in body:
        row.tls_insecure = bool(body["tlsInsecure"])
    if "route" in body:
        if body["route"] not in ("agent", "direct"):
            raise HTTPException(422, "route must be agent or direct")
        row.route = body["route"]
    if "probeDeviceId" in body:
        row.probe_device_id = _probe(db, row.tenant_id, body.get("probeDeviceId"))
    if "deviceId" in body:
        device = db.get(Device, str(body.get("deviceId") or "")) if body.get("deviceId") else None
        if body.get("deviceId") and (device is None or device.tenant_id != row.tenant_id):
            raise HTTPException(422, "The managed device must belong to the same customer")
        row.device_id = device.id if device else None
    if "nodeId" in body:
        node = db.get(NetworkNode, str(body.get("nodeId") or "")) if body.get("nodeId") else None
        if body.get("nodeId") and (node is None or node.tenant_id != row.tenant_id):
            raise HTTPException(422, "The network node must belong to the same customer")
        row.node_id = node.id if node else None
    if not row.host:
        raise HTTPException(422, "Enter the AMT host name or IP address")
    if row.route == "agent" and not row.probe_device_id:
        raise HTTPException(422, "Choose a device on the same network to reach AMT through, or use the direct route")


@router.patch("/oob/amt/{endpoint_id}")
def update_amt(endpoint_id: str, request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal),
               db: Session = Depends(get_db)):
    principal.require("configure")
    row = _owned(db, principal, endpoint_id)
    if "password" in body or "host" in body or "port" in body:
        require_reauth(request, principal)  # where the password goes, and the password itself
    _apply(db, row, body)
    if body.get("password"):
        amt.set_password(row, str(body["password"]))
    row.status = "unknown" if {"host", "port", "password", "route", "probeDeviceId"} & set(body) else row.status
    audit.record(db, principal.actor, "amt.endpoint.updated", row.name or row.host, row.tenant_id, endpoint=row.id,
                 fields=sorted(k for k in body if k != "password") + (["password"] if body.get("password") else []))
    db.commit()
    return amt.view(row, _hostnames(db, [row]))


@router.delete("/oob/amt/{endpoint_id}")
def delete_amt(endpoint_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = _owned(db, principal, endpoint_id)
    audit.record(db, principal.actor, "amt.endpoint.deleted", row.name or row.host, row.tenant_id, endpoint=row.id)
    db.delete(row)
    db.commit()
    return {"deleted": endpoint_id}


@router.post("/oob/amt/{endpoint_id}/check")
def check_amt(endpoint_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Read the AMT version, power state and AMT's network settings."""
    principal.require("read")
    principal.require("respond")
    row = _owned(db, principal, endpoint_id)
    try:
        result = amt.run(db, row, amt.check_requests(), principal.actor)
    except (amt.AmtError, services.CommandError) as exc:
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    return {**result, "endpoint": amt.view(row, _hostnames(db, [row]))}


@router.post("/oob/amt/{endpoint_id}/power")
def power_amt(endpoint_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Power on, off, cycle or reset through the management engine, whatever state the operating system is in."""
    principal.require("respond")
    action = str(body.get("action") or "")
    if action not in amt.POWER_ACTIONS:
        raise HTTPException(422, f"action must be one of {', '.join(amt.POWER_ACTIONS)}")
    if action != "on":
        principal.require("destructive")
    row = _owned(db, principal, endpoint_id)
    requests = [{"name": f"power:{action}", "body": amt.power_change(action)},
                {"name": "power", "body": amt.enumerate_items(amt.CIM + "CIM_AssociatedPowerManagementService")}]
    try:
        result = amt.run(db, row, requests, principal.actor)
    except (amt.AmtError, services.CommandError) as exc:
        raise HTTPException(422, str(exc)) from exc
    audit.record(db, principal.actor, "amt.power", row.name or row.host, row.tenant_id, endpoint=row.id, powerAction=action,
                 route=row.route, reason=str(body.get("reason") or "")[:300])
    db.commit()
    return {**result, "endpoint": amt.view(row, _hostnames(db, [row]))}


@agent_router.post("/devices/{device_id}/commands/{command_id}/amt-credential")
def amt_credential(command_id: str, device: Device = Depends(current_device), db: Session = Depends(get_db)):
    """Connection details for one amt.wsman command, released once, only to the device the command was sent to."""
    command = db.get(Command, command_id)
    if command is None:
        raise HTTPException(404, "Not found")
    try:
        details = amt.credential_for_command(db, device, command)
    except amt.AmtError as exc:
        db.commit()
        raise HTTPException(404, str(exc)) from exc
    db.commit()
    return details


# --------------------------------------------------------------------------- session routing


@router.get("/remote/routes")
def remote_routes(device_id: str | None = None, node_id: str | None = None, principal: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    """Every way to reach a managed device or an agentless network node, best first.

    - agent: the device's own agent (desktop on Windows, macOS and Linux with X11; backstage on every platform).
    - tunnel: TCP through another agent on the same LAN to RDP, SSH, VNC or a web UI (agentless devices, or a managed
      device whose agent is offline).
    - amt: Intel AMT out-of-band power control, whatever state the operating system is in.
    """
    principal.require("read")
    if bool(device_id) == bool(node_id):
        raise HTTPException(422, "Give a deviceId or a nodeId")
    routes: list[dict] = []
    device = node = None
    if device_id:
        device = db.get(Device, device_id)
        if device is None or device.tenant_id not in principal.tenant_ids:
            raise HTTPException(404, "Not found")
        tenant_id = device.tenant_id
        policy = remote.remote_policy(db, device)
        online = remote.hub.device_online(device.id) or presence.state(device) == "online"
        if policy.get("enabled", True):
            modes = (["desktop"] if device.platform in DESKTOP_PLATFORMS else []) + \
                    [m for m, key in (("terminal", "allowTerminal"), ("files", "allowFileTransfer")) if policy.get(key, True)] + \
                    (["backstage"] if policy.get("backstage", "off") == "on" else [])
            routes.append({"kind": "agent", "available": online and bool(modes), "deviceId": device.id, "modes": modes,
                           "detail": "Agent online" if online else "Agent offline: try a tunnel or AMT"})
        nodes = db.execute(select(NetworkNode).where(NetworkNode.tenant_id == tenant_id, NetworkNode.device_id == device.id)).scalars().all()
    else:
        node = db.get(NetworkNode, node_id)
        if node is None or node.tenant_id not in principal.tenant_ids:
            raise HTTPException(404, "Not found")
        tenant_id, nodes = node.tenant_id, [node]
    # Tunnels through peer agents that saw the target on their network.
    for target in nodes:
        peers = [db.get(Device, d) for d in (target.seen_by or [])]
        for peer in [p for p in peers if p is not None and p.approved and p.id != (device.id if device else None)][:3]:
            policy = remote.remote_policy(db, peer)
            allowed = remote.tunnel_ports(policy) if policy.get("allowTunnels", False) else set()
            ports = [p for p in (target.open_ports or []) if p in PORT_PROTOCOLS]
            routes.append({"kind": "tunnel", "available": bool(allowed & set(ports)), "deviceId": peer.id, "via": peer.hostname,
                           "targetHost": target.ip, "targetNodeId": target.id,
                           "ports": [{"port": p, "protocol": PORT_PROTOCOLS[p], "allowed": p in allowed} for p in ports],
                           "detail": "Tunnels are turned off in this device's policy" if not policy.get("allowTunnels", False)
                           else f"Through {peer.hostname}"})
    endpoints = db.execute(select(AmtEndpoint).where(AmtEndpoint.tenant_id == tenant_id)).scalars().all()
    for endpoint in endpoints:
        if (device and endpoint.device_id == device.id) or (node and (endpoint.node_id == node.id or endpoint.host == node.ip)):
            routes.append({"kind": "amt", "available": bool(endpoint.secret_envelope), "amtEndpointId": endpoint.id,
                           "powerState": endpoint.power_state, "status": endpoint.status,
                           "detail": f"Intel AMT {endpoint.amt_version or ''} via {endpoint.route}".replace("  ", " ")})
    if node is not None and not any(r["kind"] == "amt" for r in routes) and {16992, 16993} & set(node.open_ports or []):
        routes.append({"kind": "amt", "available": False, "detail": "AMT answers on this address: add it under Out-of-band management",
                       "suggestHost": node.ip, "suggestPort": 16993 if 16993 in (node.open_ports or []) else 16992})
    order = {"agent": 0, "tunnel": 1, "amt": 2}
    return sorted(routes, key=lambda r: (not r["available"], order[r["kind"]]))
