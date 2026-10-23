"""Agent-facing API.

Paths and JSON shapes match what the shipped agents already call:
``agent/windows/service/src/ControlPlaneClient.cpp`` (enroll, heartbeat,
policy-check-in, telemetry, commands, update-check, signature bundle) and the
Linux agent's reputation lookup. Device calls authenticate with the
``X-Device-Api-Key`` header issued at enrollment.
"""

from __future__ import annotations

import json
import re
import secrets

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, endpoint_health, intel, rmm, services
from ..config import get_settings
from ..db import get_db
from ..deps import current_device
from ..detection import ingest
from ..models import AgentRelease, Command, Device, EnrollmentToken, Event, Tenant, utcnow
from ..security import digest, new_secret

router = APIRouter(prefix="/api/v1", tags=["Agent API"])


def _iso(value) -> str:
    return value.isoformat(timespec="seconds") + "Z" if value else ""


def _platform(os_version: str, hint: str | None) -> str:
    if hint in {"windows", "linux", "macos"}:
        return hint
    lowered = os_version.lower()
    if "mac" in lowered or "darwin" in lowered:
        return "macos"
    if any(word in lowered for word in ("linux", "ubuntu", "debian", "centos", "rhel", "fedora", "suse", "alpine", "rocky")):
        return "linux"
    return "windows"


def _unassigned_tenant(db: Session) -> Tenant:
    tenant = db.execute(select(Tenant).where(Tenant.slug == "unassigned")).scalar_one_or_none()
    if tenant is None:
        root = db.execute(select(Tenant).where(Tenant.kind == "msp")).scalars().first()
        tenant = Tenant(name="Unassigned devices", slug="unassigned", kind="unassigned", parent_id=root.id if root else None)
        db.add(tenant)
        db.flush()
    return tenant


def _resolve_enrollment_token(db: Session, raw: str | None) -> EnrollmentToken | None:
    if not raw:
        return None
    token = db.execute(select(EnrollmentToken).where(EnrollmentToken.token_hash == digest(raw))).scalar_one_or_none()
    if token is None or token.revoked:
        raise HTTPException(403, "Enrollment token is invalid or revoked")
    if token.expires_at and token.expires_at < utcnow():
        raise HTTPException(403, "Enrollment token has expired")
    if token.max_uses is not None and token.uses >= token.max_uses:
        raise HTTPException(403, "Enrollment token has no uses left")
    return token


@router.post("/enroll")
def enroll(
    request: Request,
    body: dict = Body(...),
    x_fenrir_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    settings = get_settings()
    hostname = str(body.get("hostname") or "").strip()[:255]
    if not hostname:
        raise HTTPException(400, "hostname is required")
    os_version = str(body.get("osVersion") or "")[:255]
    serial = str(body.get("serialNumber") or "")[:255]
    token = _resolve_enrollment_token(db, body.get("enrollmentToken") or x_fenrir_token)
    if token is None and not settings.open_enrollment:
        raise HTTPException(403, "An enrollment token is required")

    tenant = db.get(Tenant, token.tenant_id) if token else _unassigned_tenant(db)
    api_key = new_secret("fdk", 32)
    device = None
    if token and serial:
        # Re-imaged or reinstalled machine: keep its history, rotate its key.
        device = db.execute(select(Device).where(Device.tenant_id == tenant.id, Device.serial_number == serial)).scalars().first()
    if device is None:
        device = Device(tenant_id=tenant.id, hostname=hostname, serial_number=serial, dns_token=secrets.token_urlsafe(24),
                        api_key_hash=digest(api_key))
        db.add(device)
    device.api_key_hash = digest(api_key)
    device.hostname, device.os_version = hostname, os_version
    device.platform = _platform(os_version, body.get("platform"))
    device.agent_version = str(body.get("agentVersion") or device.agent_version or "")[:64]
    device.group_id = token.group_id if token and token.group_id else device.group_id
    device.approved = token is not None
    device.ip_address = request.client.host if request.client else ""
    device.last_seen_at = utcnow()
    if token:
        token.uses += 1
    db.flush()
    _, policy_doc = services.effective_policy(db, device)
    device.applied_policy_revision = policy_doc["revision"]
    audit.record(db, f"device:{hostname}", "device.enrolled", device.id, tenant.id, platform=device.platform,
                 token=token.label if token else "open-enrollment")
    db.commit()

    base = settings.public_base_url.rstrip("/")
    return {
        "deviceId": device.id,
        "tenantId": tenant.id,
        "issuedAt": _iso(utcnow()),
        "approved": device.approved,
        "deviceApiKey": api_key,
        "commandChannelUrl": f"{base}/api/v1/devices/{device.id}/commands/pending?deviceApiKey={api_key}",
        "dnsOverHttpsUrl": f"{base}/dns/{device.dns_token}/dns-query",
        "realtimeUrl": ("wss://" + base[8:] if base.startswith("https://") else "ws://" + base.removeprefix("http://"))
        + f"/api/v1/devices/{device.id}/realtime",
        "policy": policy_doc,
    }


@router.post("/devices/{device_id}/heartbeat")
def heartbeat(body: dict = Body(default={}), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    device.agent_version = str(body.get("agentVersion") or device.agent_version)[:64]
    device.platform_version = str(body.get("platformVersion") or device.platform_version)[:64]
    previous_health = device.health_state
    device.health_state = str(body.get("healthState") or device.health_state)[:40]
    endpoint_health.on_heartbeat(db, device, previous_health)
    if "isolated" in body:
        device.isolated = bool(body["isolated"])
    if isinstance(body.get("metrics"), dict):
        rmm.record_heartbeat_metrics(db, device, body["metrics"])
        rmm.evaluate_device(db, device)
    _, policy_doc = services.effective_policy(db, device)
    pending = db.execute(select(func.count()).where(Command.device_id == device.id, Command.status == "pending")).scalar() or 0
    db.commit()
    return {"receivedAt": _iso(utcnow()), "effectivePolicyRevision": policy_doc["revision"], "commandsPending": pending,
            "approved": device.approved, "realtimePath": f"/api/v1/devices/{device.id}/realtime"}


@router.post("/devices/{device_id}/policy-check-in")
def policy_check_in(body: dict = Body(default={}), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    _, policy_doc = services.effective_policy(db, device)
    changed = body.get("currentPolicyRevision") != policy_doc["revision"]
    device.applied_policy_revision = policy_doc["revision"]
    db.commit()
    return {"retrievedAt": _iso(utcnow()), "changed": changed, "policy": policy_doc}


@router.post("/devices/{device_id}/telemetry")
def telemetry(body: dict = Body(...), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    events = body.get("events")
    if not isinstance(events, list):
        raise HTTPException(400, "events must be a list")
    limit = get_settings().max_telemetry_batch
    if len(events) > limit:
        raise HTTPException(413, f"at most {limit} events per batch")
    result = ingest(db, device, events)
    total = db.execute(select(func.count()).where(Event.device_id == device.id)).scalar() or 0
    db.commit()
    return {"receivedAt": _iso(utcnow()), "accepted": result.accepted, "duplicates": result.duplicates,
            "totalStored": total, "alerts": result.alerts}


@router.get("/devices/{device_id}/commands/pending")
def pending_commands(limit: int = Query(default=20, ge=1, le=100), device: Device = Depends(current_device),
                     db: Session = Depends(get_db)):
    commands = db.execute(
        select(Command).where(Command.device_id == device.id, Command.status.in_(("pending", "dispatched")))
        .order_by(Command.created_at).limit(limit)
    ).scalars().all()
    now = utcnow()
    for command in commands:
        if command.status == "pending":
            command.status, command.dispatched_at, command.updated_at = "dispatched", now, now
    db.commit()
    return {
        "polledAt": _iso(now),
        "items": [
            {"id": c.id, "type": c.type, "issuedBy": c.issued_by, "createdAt": _iso(c.created_at), "updatedAt": _iso(c.updated_at),
             "targetPath": c.target_path, "recordId": c.record_id, "payloadJson": json.dumps(c.payload) if c.payload else ""}
            for c in commands
        ],
    }


@router.post("/devices/{device_id}/commands/{command_id}/complete")
def complete_command(command_id: str, body: dict = Body(...), device: Device = Depends(current_device),
                     db: Session = Depends(get_db)):
    command = db.get(Command, command_id)
    if command is None or command.device_id != device.id:
        raise HTTPException(404, "Unknown command")
    status = str(body.get("status") or "completed").lower()
    command.status = "completed" if status in {"completed", "succeeded", "success", "ok"} else "failed"
    raw = body.get("resultJson")
    try:
        command.result = json.loads(raw) if isinstance(raw, str) and raw else (raw or {})
    except json.JSONDecodeError:
        command.result = {"raw": raw}
    command.completed_at = command.updated_at = utcnow()
    if command.type == "device.isolate" and command.status == "completed":
        device.isolated = True
    elif command.type == "device.release" and command.status == "completed":
        device.isolated = False
    audit.record(db, f"device:{device.hostname}", "command.completed", command.id, device.tenant_id,
                 type=command.type, status=command.status)
    rmm.on_command_complete(db, device, command)
    db.commit()
    return {"id": command.id, "status": command.status}


def _version_tuple(version: str) -> tuple:
    return tuple(int(part) if part.isdigit() else 0 for part in re.split(r"[.\-+]", version or "0"))


@router.post("/update-check")
def update_check(body: dict = Body(default={}), x_device_api_key: str | None = Header(default=None), db: Session = Depends(get_db)):
    channel = str(body.get("channel") or "stable")
    platform = str(body.get("platform") or "")
    if x_device_api_key:
        device = db.execute(select(Device).where(Device.api_key_hash == digest(x_device_api_key))).scalar_one_or_none()
        if device is not None:
            platform = platform or device.platform
            resolution, _ = services.effective_policy(db, device)
            channel = body.get("channel") or resolution["settings"]["updates"]["channel"]
    platform = platform or "windows"
    current = _version_tuple(str(body.get("agentVersion") or "0"))
    releases = db.execute(select(AgentRelease).where(AgentRelease.platform == platform, AgentRelease.channel == channel)).scalars().all()
    newest: dict[str, AgentRelease] = {}
    for release in releases:
        if release.component == "agent":
            if _version_tuple(release.version) <= current:
                continue
        elif str(body.get(f"{release.component}Version") or "") == release.version:
            continue
        best = newest.get(release.component)
        if best is None or _version_tuple(release.version) > _version_tuple(best.version):
            newest[release.component] = release
    return {
        "checkedAt": _iso(utcnow()),
        "updates": [
            {"packageId": r.id, "packageType": r.component, "targetVersion": r.version, "manifestPath": r.url,
             "sha256": r.sha256, "signature": r.signature, "mandatory": False, "notes": r.notes}
            for r in newest.values()
        ],
    }


def _bundle_tenant(db: Session, x_device_api_key: str | None, x_fenrir_token: str | None) -> str | None:
    if x_device_api_key:
        device = db.execute(select(Device).where(Device.api_key_hash == digest(x_device_api_key))).scalar_one_or_none()
        if device is not None:
            return device.tenant_id
    feed_token = get_settings().feed_token
    if feed_token and x_fenrir_token != feed_token and not x_device_api_key:
        raise HTTPException(401, "A device key or feed token is required")
    return None


@router.api_route("/agent/bundle", methods=["GET", "POST"])
@router.api_route("/signatures/delta", methods=["GET", "POST"])
def agent_bundle(
    hashes_limit: int = Query(default=50000, alias="hashesLimit", ge=0, le=200000),
    urls_limit: int = Query(default=50000, alias="urlsLimit", ge=0, le=200000),
    rules_limit: int = Query(default=5000, alias="rulesLimit", ge=0, le=20000),
    x_device_api_key: str | None = Header(default=None),
    x_fenrir_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    tenant_id = _bundle_tenant(db, x_device_api_key, x_fenrir_token)
    return intel.agent_bundle(db, tenant_id, hashes_limit, urls_limit, rules_limit)


@router.get("/agent/model/manifest")
def model_manifest():
    from .. import mlmodel

    bundle = mlmodel.current()
    if bundle is None:
        raise HTTPException(404, "No model published")
    return {"version": bundle.version, "sha256": bundle.sha256, "size": bundle.size, "format": "fgbt",
            "features": "ember-v2", "metrics": bundle.metrics.get("test", {})}


@router.get("/agent/model")
def model_download(format: str = Query(default="fgbt", pattern="^(fgbt|json)$")):
    from fastapi.responses import FileResponse

    from .. import mlmodel

    bundle = mlmodel.current()
    if bundle is None:
        raise HTTPException(404, "No model published")
    if format == "json":
        return FileResponse(bundle.json_path, media_type="application/gzip", filename=bundle.json_path.name)
    return FileResponse(bundle.fgbt_path, media_type="application/octet-stream", filename=bundle.fgbt_path.name)


@router.get("/reputation/{value:path}")
def reputation(value: str, x_device_api_key: str | None = Header(default=None), db: Session = Depends(get_db)):
    tenant_id = None
    if x_device_api_key:
        device = db.execute(select(Device).where(Device.api_key_hash == digest(x_device_api_key))).scalar_one_or_none()
        tenant_id = device.tenant_id if device else None
    try:
        return intel.lookup(db, value, tenant_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/telemetry")
def legacy_telemetry(body: dict = Body(...), x_device_api_key: str | None = Header(default=None), db: Session = Depends(get_db)):
    """The original single-event schema (schema/telemetry.json), kept for older Linux/macOS builds."""
    if not x_device_api_key:
        raise HTTPException(401, "Enroll the agent and send X-Device-Api-Key")
    device = db.execute(select(Device).where(Device.api_key_hash == digest(x_device_api_key))).scalar_one_or_none()
    if device is None:
        raise HTTPException(401, "Unknown device credentials")
    device.last_seen_at = utcnow()
    result = ingest(db, device, [body])
    db.commit()
    return {"status": "success", "eventId": body.get("eventId"), "alertsGenerated": result.alerts}
