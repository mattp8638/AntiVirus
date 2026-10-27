"""Devices, remote actions, policies, and agent releases."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.orm import Session

from .. import audit, detection, policy_schema, rmm, services
from ..commands import BY_TYPE, catalog_document
from ..config import get_settings
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth, scoped_tenant
from ..models import (AgentRelease, Alert, Command, Configuration, Device, DeviceGroup, Event, Policy, RemoteSession, SoftwareItem, Tenant, Vulnerability,
                      utcnow)
from ..serialize import apply_fields, to_dict

router = APIRouter(prefix="/api/console", tags=["Fleet"])
# Irreversible actions that need the technician's password again.
REAUTH_COMMANDS = {"device.wipe"}

ONLINE_WINDOW = timedelta(minutes=10)


def _device_view(device: Device, summary: bool = False) -> dict:
    data = to_dict(device, exclude={"dns_token", "inventory"} if summary else {"dns_token"})
    data["retired"] = device.api_key_hash == f"retired-{device.id}"
    data["online"] = not data["retired"] and bool(device.last_seen_at and device.last_seen_at >= utcnow() - ONLINE_WINDOW)
    if summary:
        metrics = device.metrics or {}
        disks = metrics.get("disks") or []
        data["metrics"] = {k: metrics[k] for k in ("cpuPercent", "memoryPercent", "loggedOnUser", "rebootPending", "uptimeSeconds",
                                                   "reportedAt", "patchScanAt") if k in metrics}
        if disks:
            data["metrics"]["diskFreePercent"] = min(d.get("freePercent", 100) for d in disks)
    return data


def _vuln_views(db: Session, device: Device, vulns: list[Vulnerability]) -> list[dict]:
    """Device vulnerabilities, worst first, each with its risk on this device and the CVE's NVD/EPSS/KEV record."""
    from .. import cveintel, vulnmgmt
    from ..models import CveRecord

    records = {r.cve_id: r for r in db.execute(select(CveRecord).where(CveRecord.cve_id.in_({v.vuln_id for v in vulns}))).scalars()}
    out = []
    for v in vulns:
        view = to_dict(v)
        view["riskScore"] = vulnmgmt.risk_score(v, device.criticality)
        view["reasons"] = vulnmgmt.risk_reasons(v)
        view["priority"] = vulnmgmt.priority(v)
        view["recommendation"] = vulnmgmt.recommendation(v)
        view["intel"] = cveintel.record_view(records.get(v.vuln_id))
        out.append(view)
    order = {"open": 0, "patching": 1, "mitigated": 2, "accepted": 3}
    return sorted(out, key=lambda x: (order.get(x["status"], 4), -x["riskScore"]))


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
    status: str | None = Query(default=None, description="online | offline | isolated | pending | at-risk | retired"),
    principal: Principal = Depends(current_principal),
    db: Session = Depends(get_db),
):
    query = select(Device).where(Device.tenant_id.in_(scoped_tenant(principal, tenant_id)))
    retired = Device.api_key_hash == ("retired-" + Device.id)
    query = query.where(retired if status == "retired" else ~retired)
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
        "vulnerabilities": _vuln_views(db, device, vulns),
        "risk": detection.risk_breakdown(db, device),
        "eventCount": events,
    }


@router.patch("/devices/{device_id}")
def update_device(device_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    principal.require("configure")
    device = _get_device(db, principal, device_id)
    if "tenantId" in body and body["tenantId"] != device.tenant_id:
        raise HTTPException(409, "An enrolled device cannot move customers without retirement and fresh enrollment.")
    if body.get("approved") is False:
        raise HTTPException(409, "Use the device retirement action to revoke credentials and preserve asset history.")
    if body.get("approved") is True and device.api_key_hash == f"retired-{device.id}":
        raise HTTPException(409, "Retired devices require fresh enrollment credentials.")
    if body.get("approved") is True:
        device.approved = True
    if body.get("groupId"):
        group = db.get(DeviceGroup, body["groupId"])
        if group is None or group.tenant_id != device.tenant_id:
            raise HTTPException(400, "Group belongs to another tenant")
    if body.get("policyId"):
        policy = db.get(Policy, body["policyId"])
        if policy is None or policy.tenant_id not in (None, device.tenant_id):
            raise HTTPException(400, "Policy belongs to another tenant")
    if "criticality" in body and body["criticality"] not in {"low", "medium", "high", "critical"}:
        raise HTTPException(400, "criticality must be low, medium, high or critical")
    changed = apply_fields(device, body, {"group_id", "policy_id", "tags", "approved", "criticality"})
    audit.record(db, principal.actor, "device.updated", device.hostname, device.tenant_id, fields=changed)
    db.commit()
    return _device_view(device)


@router.delete("/devices/{device_id}")
def retire_device(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    device = _get_device(db, principal, device_id)
    if device.api_key_hash == f"retired-{device.id}":
        return {"ok": True}
    in_flight = db.execute(select(Command).where(
        Command.device_id == device.id, Command.status == "dispatched")).first()
    if in_flight:
        raise HTTPException(409, "This device has in-flight work. Reconcile command outcomes before retirement.")
    active_support = db.execute(select(RemoteSession).where(
        RemoteSession.device_id == device.id,
        RemoteSession.status.in_(("waiting", "connected")))).first()
    if active_support:
        raise HTTPException(409, "End active remote support sessions before retiring this device.")
    affected_jobs: set[str] = set()
    for command in db.execute(select(Command).where(
            Command.device_id == device.id, Command.status == "pending")).scalars():
        command.status, command.updated_at = "cancelled", utcnow()
        job_id = (command.payload or {}).get("jobId")
        if job_id:
            affected_jobs.add(job_id)
    for job_id in affected_jobs:
        rmm.refresh_job(db, job_id)
    # Preserve historical ownership; never leave retired endpoints active in CMDB.
    for asset in db.execute(select(Configuration).where(
            Configuration.device_id == device.id)).scalars():
        asset.status = "Retired"
        asset.updated_at = utcnow()
    device.approved = False
    device.api_key_hash = f"retired-{device.id}"
    audit.record(db, principal.actor, "device.retired", device.hostname, device.tenant_id)
    db.commit()
    return {"ok": True}


@router.post("/devices/{device_id}/purge")
def purge_device(device_id: str, request: Request, body: dict = Body(default={}), principal: Principal = Depends(current_principal),
                 db: Session = Depends(get_db)):
    """Permanently delete a decommissioned device and everything recorded about it.

    Tickets and CMDB configurations are service and billing history: they stay, unlinked from the device.
    The audit log keeps a record of the deletion.
    """
    from ..models import (Alert, ConditionState, DeviceArtifact, DeviceMetric, DevicePatch, DeviceProfile, DnsQueryLog,
                          EnrollmentToken, Incident, IncidentEvidence, NetworkMonitor, RecoveryKey, DeviceLocation, RuleMatch, Ticket)

    principal.require("configure")
    require_reauth(request, principal)
    device = _get_device(db, principal, device_id)
    if device.api_key_hash != f"retired-{device.id}":
        raise HTTPException(409, "Decommission the device first; only decommissioned devices can be deleted.")
    if str(body.get("confirmHostname") or "") != device.hostname:
        raise HTTPException(422, "Type the device's hostname to confirm permanent deletion.")
    removed: dict[str, int] = {}
    artifact_dir = get_settings().artifact_dir
    for artifact in db.scalars(select(DeviceArtifact).where(DeviceArtifact.device_id == device.id)):
        (artifact_dir / artifact.storage_name).unlink(missing_ok=True)
    incident_ids = list(db.scalars(select(Incident.id).where(Incident.device_id == device.id)))
    if incident_ids:
        removed["incident_evidence"] = db.execute(delete(IncidentEvidence).where(
            IncidentEvidence.incident_id.in_(incident_ids))).rowcount or 0
    for model in (Event, RuleMatch, Alert, Incident, Command, ConditionState, DeviceMetric, DevicePatch, SoftwareItem,
                  Vulnerability, DnsQueryLog, RemoteSession, DeviceArtifact, DeviceProfile, RecoveryKey, DeviceLocation):
        removed[model.__tablename__] = db.execute(delete(model).where(model.device_id == device.id)).rowcount or 0
    db.execute(update(Ticket).where(Ticket.device_id == device.id).values(device_id=None))
    db.execute(update(Configuration).where(Configuration.device_id == device.id).values(device_id=None))
    db.execute(update(NetworkMonitor).where(NetworkMonitor.probe_device_id == device.id).values(probe_device_id=None))
    db.execute(update(EnrollmentToken).where(EnrollmentToken.label == f"Reinstate {device.id}").values(revoked=True))
    hostname, tenant_id = device.hostname, device.tenant_id
    db.delete(device)
    audit.record(db, principal.actor, "device.purged", hostname, tenant_id, deviceId=device_id,
                 removed={k: v for k, v in removed.items() if v})
    db.commit()
    return {"ok": True, "removed": removed}


# --------------------------------------------------------------------------- commands


@router.get("/protection/health")
def protection_health(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Is every endpoint protected, current, scanning and reporting?"""
    from .. import endpoint_health

    return endpoint_health.summary(db, scoped_tenant(principal, tenant_id))


QUARANTINE_EVENTS = ("scan.finding", "realtime.protection.action", "scan.threat.quarantined", "threat.process.blocked",
                     "quarantine.added")


@router.get("/protection/quarantine")
def quarantine_items(tenant_id: str | None = None, device_id: str | None = None, include_released: bool = False,
                     principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Files agents hold in quarantine, with the state of any restore/delete action taken on them."""
    tenants = scoped_tenant(principal, tenant_id)
    query = (select(Event, Device.hostname).join(Device, Device.id == Event.device_id)
             .where(Event.tenant_id.in_(tenants), Event.event_type.in_(QUARANTINE_EVENTS),
                    Event.occurred_at >= utcnow() - timedelta(days=180)))
    if device_id:
        query = query.where(Event.device_id == device_id)
    items: dict[tuple[str, str], dict] = {}
    for event, hostname in db.execute(query.order_by(Event.occurred_at.desc()).limit(5000)):
        fields = event.fields or {}
        record = str(fields.get("quarantineRecordId") or fields.get("recordId") or "")
        if not record or (event.device_id, record) in items:
            continue
        items[(event.device_id, record)] = {
            "deviceId": event.device_id, "hostname": hostname, "tenantId": event.tenant_id, "recordId": record,
            "path": fields.get("TargetFilename") or fields.get("path") or fields.get("Image") or "",
            "threat": fields.get("ThreatName") or fields.get("alertTitle") or event.summary or "",
            "sha256": fields.get("sha256") or "", "source": event.event_type, "quarantinedAt": event.occurred_at,
            "status": "quarantined", "commandId": None, "lastError": "",
        }
    if items:
        actions = db.execute(select(Command).where(
            Command.tenant_id.in_(tenants), Command.type.in_(("quarantine.restore", "quarantine.delete")),
            Command.device_id.in_({key[0] for key in items}), Command.record_id.in_({key[1] for key in items}))
            .order_by(Command.created_at)).scalars()
        for command in actions:  # oldest first, so the newest action decides the state
            item = items.get((command.device_id, command.record_id))
            if item is None or command.status == "cancelled":
                continue
            verb = "restore" if command.type == "quarantine.restore" else "delete"
            item["commandId"] = command.id
            if command.status == "completed":
                item["status"], item["lastError"] = ("restored" if verb == "restore" else "deleted"), ""
            elif command.status == "failed":
                item["status"] = "quarantined"
                item["lastError"] = str((command.result or {}).get("error") or command.result or "")[:500]
            else:
                item["status"] = "restoring" if verb == "restore" else "deleting"
    rows = list(items.values())
    if not include_released:
        rows = [r for r in rows if r["status"] not in ("restored", "deleted")]
    return rows


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


def _command_arguments(body: dict) -> dict:
    payload = body.get("payload")
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise HTTPException(422, "Command payload must be a JSON object")
    arguments = {"payload": payload}
    for field, name in (("targetPath", "target_path"), ("recordId", "record_id"), ("reason", "reason")):
        value = body.get(field)
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise HTTPException(422, f"{field} must be a string")
        arguments[name] = value.strip()
    return arguments


@router.post("/devices/{device_id}/commands")
def issue_command(device_id: str, request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    device = _get_device(db, principal, device_id)
    command_type = str(body.get("type") or "")
    spec = BY_TYPE.get(command_type)
    if spec is None:
        raise HTTPException(400, "Unknown command type")
    principal.require(spec.permission)
    if command_type in REAUTH_COMMANDS:
        require_reauth(request, principal)
    if command_type == "device.lostmode":
        raise HTTPException(400, "Turn lost mode on or off from the device's Location tab")
    arguments = _command_arguments(body)
    try:
        command = services.enqueue_command(db, device, command_type, principal.actor,
                                           **arguments, incident_id=body.get("incidentId"))
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
    if command_type in REAUTH_COMMANDS or command_type == "device.lostmode":
        raise HTTPException(400, f"{spec.label} is sent to one device at a time")
    ids = body.get("deviceIds")
    if not isinstance(ids, list) or not ids or any(not isinstance(i, str) or not i.strip() for i in ids):
        raise HTTPException(422, "deviceIds must be a non-empty list of device IDs")
    if len(ids) > 5000:
        raise HTTPException(422, "A bulk action supports at most 5000 device IDs")
    ids = list(dict.fromkeys(i.strip() for i in ids))
    arguments = _command_arguments(body)
    queued, skipped = [], []
    for device_id in ids:
        device = db.get(Device, device_id)
        if device is None or device.tenant_id not in principal.tenant_ids:
            skipped.append({"deviceId": device_id, "reason": "not found"})
            continue
        try:
            queued.append(services.enqueue_command(db, device, command_type, principal.actor, **arguments).id)
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
