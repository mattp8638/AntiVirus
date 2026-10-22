"""Devices, remote actions, policies, and agent releases."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import audit, policy_schema, services
from ..commands import BY_TYPE, catalog_document
from ..config import get_settings
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import (AgentRelease, Alert, Command, Device, DeviceGroup, Event, Policy, SoftwareItem, Tenant, Vulnerability,
                      utcnow)
from ..serialize import apply_fields, to_dict

router = APIRouter(prefix="/api/console", tags=["Fleet"])

ONLINE_WINDOW = timedelta(minutes=10)


def _device_view(device: Device, summary: bool = False) -> dict:
    data = to_dict(device, exclude={"dns_token", "inventory"} if summary else {"dns_token"})
    data["online"] = bool(device.last_seen_at and device.last_seen_at >= utcnow() - ONLINE_WINDOW)
    if summary:
        metrics = device.metrics or {}
        disks = metrics.get("disks") or []
        data["metrics"] = {k: metrics[k] for k in ("cpuPercent", "memoryPercent", "loggedOnUser", "rebootPending", "uptimeSeconds",
                                                   "reportedAt", "patchScanAt") if k in metrics}
        if disks:
            data["metrics"]["diskFreePercent"] = min(d.get("freePercent", 100) for d in disks)
    return data


def _get_device(db: Session, principal: Principal, device_id: str) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(device.tenant_id)
    return device


# --------------------------------------------------------------------------- devices


@router.get("/devices")
def list_devices(
    tenant_id: str | None = None,
    q: str | None = None,
    platform: str | None = None,
    group_id: str | None = None,
    status: str | None = Query(default=None, description="online | offline | isolated | pending | at-risk"),
    principal: Principal = Depends(current_principal),
    db: Session = Depends(get_db),
):
    query = select(Device).where(Device.tenant_id.in_(scoped_tenant(principal, tenant_id)))
    if q:
        like = f"%{q}%"
        query = query.where(or_(Device.hostname.ilike(like), Device.os_version.ilike(like), Device.ip_address.ilike(like)))
    if platform:
        query = query.where(Device.platform == platform)
    if group_id:
        query = query.where(Device.group_id == group_id)
    cutoff = utcnow() - ONLINE_WINDOW
    if status == "online":
        query = query.where(Device.last_seen_at >= cutoff)
    elif status == "offline":
        query = query.where(or_(Device.last_seen_at.is_(None), Device.last_seen_at < cutoff))
    elif status == "isolated":
        query = query.where(Device.isolated.is_(True))
    elif status == "pending":
        query = query.where(Device.approved.is_(False))
    elif status == "at-risk":
        query = query.where(Device.risk_score >= 40)
    rows = db.execute(query.order_by(Device.risk_score.desc(), Device.hostname).limit(2000)).scalars().all()
    return [_device_view(d, summary=True) for d in rows]


@router.get("/devices/{device_id}")
def device_detail(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    device = _get_device(db, principal, device_id)
    resolution, agent_doc = services.effective_policy(db, device)
    alerts = db.execute(select(Alert).where(Alert.device_id == device.id).order_by(Alert.created_at.desc()).limit(25)).scalars().all()
    commands = db.execute(select(Command).where(Command.device_id == device.id).order_by(Command.created_at.desc()).limit(25)).scalars().all()
    software = db.execute(select(SoftwareItem).where(SoftwareItem.device_id == device.id).order_by(SoftwareItem.name).limit(1000)).scalars().all()
    vulns = db.execute(select(Vulnerability).where(Vulnerability.device_id == device.id, Vulnerability.status != "fixed")
                       .order_by(Vulnerability.known_exploited.desc(), Vulnerability.severity)).scalars().all()
    events = db.execute(select(func.count()).where(Event.device_id == device.id)).scalar() or 0
    base = get_settings().public_base_url.rstrip("/")
    return {
        "device": _device_view(device),
        "policy": {"revision": agent_doc["revision"], "applied": device.applied_policy_revision == agent_doc["revision"],
                   "settings": resolution["settings"], "origin": resolution["origin"], "locked": resolution["locked"],
                   "overridesBlocked": resolution["overridesBlocked"]},
        "dnsOverHttpsUrl": f"{base}/dns/{device.dns_token}/dns-query",
        "alerts": [to_dict(a) for a in alerts],
        "commands": [to_dict(c) for c in commands],
        "software": [to_dict(s) for s in software],
        "vulnerabilities": [to_dict(v) for v in vulns],
        "eventCount": events,
    }


@router.patch("/devices/{device_id}")
def update_device(device_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    principal.require("configure")
    device = _get_device(db, principal, device_id)
    if "tenantId" in body:
        principal.require("manage_tenants")
        principal.check_tenant(body["tenantId"])
        device.tenant_id = body["tenantId"]
        device.approved = True
    if body.get("groupId"):
        group = db.get(DeviceGroup, body["groupId"])
        if group is None or group.tenant_id != device.tenant_id:
            raise HTTPException(400, "Group belongs to another tenant")
    if body.get("policyId"):
        policy = db.get(Policy, body["policyId"])
        if policy is None or policy.tenant_id not in (None, device.tenant_id):
            raise HTTPException(400, "Policy belongs to another tenant")
    changed = apply_fields(device, body, {"group_id", "policy_id", "tags", "approved"})
    audit.record(db, principal.actor, "device.updated", device.hostname, device.tenant_id, fields=changed)
    db.commit()
    return _device_view(device)


@router.delete("/devices/{device_id}")
def retire_device(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    device = _get_device(db, principal, device_id)
    device.approved = False
    device.api_key_hash = f"retired-{device.id}"
    audit.record(db, principal.actor, "device.retired", device.hostname, device.tenant_id)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- commands


@router.get("/commands/catalog")
def command_catalog(principal: Principal = Depends(current_principal)):
    return catalog_document()


@router.get("/commands")
def list_commands(tenant_id: str | None = None, device_id: str | None = None, status: str | None = None,
                  principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    query = select(Command).where(Command.tenant_id.in_(scoped_tenant(principal, tenant_id)))
    if device_id:
        query = query.where(Command.device_id == device_id)
    if status:
        query = query.where(Command.status == status)
    return [to_dict(c) for c in db.execute(query.order_by(Command.created_at.desc()).limit(500)).scalars()]


@router.post("/devices/{device_id}/commands")
def issue_command(device_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    device = _get_device(db, principal, device_id)
    command_type = str(body.get("type") or "")
    spec = BY_TYPE.get(command_type)
    if spec is None:
        raise HTTPException(400, "Unknown command type")
    principal.require(spec.permission)
    try:
        command = services.enqueue_command(db, device, command_type, principal.actor, target_path=str(body.get("targetPath") or ""),
                                           record_id=str(body.get("recordId") or ""), payload=body.get("payload") or {},
                                           reason=str(body.get("reason") or ""), incident_id=body.get("incidentId"))
    except services.CommandError as exc:
        raise HTTPException(400, str(exc)) from exc
    db.commit()
    return to_dict(command)


@router.post("/commands/bulk")
def bulk_command(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Run one action on many devices (e.g. scan a whole tenant after an outbreak)."""
    command_type = str(body.get("type") or "")
    spec = BY_TYPE.get(command_type)
    if spec is None:
        raise HTTPException(400, "Unknown command type")
    principal.require(spec.permission)
    ids = body.get("deviceIds") or []
    queued, skipped = [], []
    for device_id in ids[:5000]:
        device = db.get(Device, device_id)
        if device is None or device.tenant_id not in principal.tenant_ids:
            skipped.append({"deviceId": device_id, "reason": "not found"})
            continue
        try:
            queued.append(services.enqueue_command(db, device, command_type, principal.actor, target_path=str(body.get("targetPath") or ""),
                                                   record_id=str(body.get("recordId") or ""), reason=str(body.get("reason") or "")).id)
        except services.CommandError as exc:
            skipped.append({"deviceId": device_id, "reason": str(exc)})
    db.commit()
    return {"queued": queued, "skipped": skipped}


@router.post("/commands/{command_id}/cancel")
def cancel_command(command_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    command = db.get(Command, command_id)
    if command is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(command.tenant_id)
    if command.status != "pending":
        raise HTTPException(409, f"Command is already {command.status}")
    command.status, command.updated_at = "cancelled", utcnow()
    audit.record(db, principal.actor, "command.cancelled", command.id, command.tenant_id)
    db.commit()
    return to_dict(command)


# --------------------------------------------------------------------------- policies


@router.get("/policy-schema")
def get_policy_schema(principal: Principal = Depends(current_principal)):
    return policy_schema.schema_document()


@router.get("/policy-templates/{name}")
def get_template(name: str, principal: Principal = Depends(current_principal)):
    if name not in policy_schema.TEMPLATES:
        raise HTTPException(404, "Unknown template")
    return policy_schema.resolve([policy_schema.Layer("template", policy_schema.template_settings(name))])["settings"]


@router.get("/policies")
def list_policies(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    scope = scoped_tenant(principal, tenant_id)
    rows = db.execute(select(Policy).where(or_(Policy.tenant_id.in_(scope), Policy.tenant_id.is_(None))).order_by(Policy.name)).scalars().all()
    usage = dict(db.execute(select(Device.policy_id, func.count()).group_by(Device.policy_id)).all())
    group_usage = dict(db.execute(select(DeviceGroup.policy_id, func.count()).group_by(DeviceGroup.policy_id)).all())
    tenant_usage = dict(db.execute(select(Tenant.default_policy_id, func.count()).group_by(Tenant.default_policy_id)).all())
    return [{**to_dict(p), "devices": usage.get(p.id, 0), "groups": group_usage.get(p.id, 0), "tenants": tenant_usage.get(p.id, 0)}
            for p in rows]


@router.get("/policies/{policy_id}")
def get_policy(policy_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    policy = db.get(Policy, policy_id)
    if policy is None or (policy.tenant_id is not None and policy.tenant_id not in principal.tenant_ids):
        raise HTTPException(404, "Not found")
    tenant = db.get(Tenant, policy.tenant_id) if policy.tenant_id else None
    # Show the layers *above* this policy so the editor can display inherited values and locks.
    inherited = [layer for layer in services.policy_layers(db, tenant) if not layer.name.endswith(f"/ {policy.name}")]
    above = policy_schema.resolve(inherited)
    effective = policy_schema.resolve(inherited + [policy_schema.Layer(policy.name, policy.settings or {}, policy.locks or [])])
    return {"policy": to_dict(policy), "inherited": above, "effective": effective}


def _validated(body: dict) -> tuple[dict, list[str]]:
    try:
        return policy_schema.validate_partial(body.get("settings") or {}), policy_schema.validate_locks(body.get("locks") or [])
    except policy_schema.PolicyError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/policies")
def create_policy(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.get("tenantId")
    principal.check_tenant(tenant_id)
    template = str(body.get("template") or "")
    if template and template not in policy_schema.TEMPLATES:
        raise HTTPException(400, "Unknown template")
    settings, locks = _validated(body)
    if template:
        merged = policy_schema.template_settings(template)
        for section, values in settings.items():
            merged.setdefault(section, {}).update(values)
        settings = policy_schema.validate_partial(merged)
    policy = Policy(tenant_id=tenant_id, name=str(body.get("name") or "New policy"), description=str(body.get("description") or ""),
                    template=template or "custom", parent_id=body.get("parentId"), settings=settings, locks=locks,
                    updated_by=principal.actor)
    db.add(policy)
    audit.record(db, principal.actor, "policy.created", policy.name, tenant_id, template=template)
    db.commit()
    return to_dict(policy)


@router.put("/policies/{policy_id}")
def update_policy(policy_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    principal.require("configure")
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(policy.tenant_id)
    settings, locks = _validated(body)
    before = policy.settings
    policy.settings, policy.locks = settings, locks
    for key in ("name", "description"):
        if key in body:
            setattr(policy, key, str(body[key]))
    policy.version += 1
    policy.updated_at, policy.updated_by = utcnow(), principal.actor
    changed = sorted({f"{s}.{k}" for s, v in settings.items() for k in v if (before.get(s) or {}).get(k) != v[k]} |
                     {f"{s}.{k}" for s, v in before.items() for k in v if k not in settings.get(s, {})})
    audit.record(db, principal.actor, "policy.updated", policy.name, policy.tenant_id, version=policy.version, changed=changed[:100])
    db.commit()
    return to_dict(policy)


@router.post("/policies/preview")
def preview_policy(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Resolve what a device would get, before saving: the 'what if' button."""
    device_id = body.get("deviceId")
    if not device_id:
        raise HTTPException(400, "deviceId is required")
    device = _get_device(db, principal, device_id)
    settings, locks = _validated(body)
    tenant = db.get(Tenant, device.tenant_id)
    layers = services.policy_layers(db, tenant, device=device) + [policy_schema.Layer("preview", settings, locks)]
    resolution = policy_schema.resolve(layers)
    return {"resolution": resolution, "agentPolicy": policy_schema.to_agent_policy("preview", "preview", resolution["settings"])}


# --------------------------------------------------------------------------- releases


@router.get("/releases")
def list_releases(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return [to_dict(r) for r in db.execute(select(AgentRelease).order_by(AgentRelease.published_at.desc())).scalars()]


@router.post("/releases")
def publish_release(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("platform")
    required = ("platform", "version", "url", "sha256")
    if any(not body.get(key) for key in required):
        raise HTTPException(400, f"{', '.join(required)} are required")
    release = AgentRelease(platform=body["platform"], version=body["version"], url=body["url"], sha256=str(body["sha256"]).lower(),
                           channel=str(body.get("channel") or "stable"), component=str(body.get("component") or "agent"),
                           signature=str(body.get("signature") or ""), notes=str(body.get("notes") or ""),
                           rollout_percent=int(body.get("rolloutPercent") or 100))
    db.add(release)
    audit.record(db, principal.actor, "release.published", f"{release.platform} {release.version}", None, channel=release.channel)
    db.commit()
    return to_dict(release)
