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

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Path, Query, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import devicekeys
from .. import rollouts, audit, endpoint_health, group_rules, intel, psa, rmm, services
from ..config import get_settings
from ..db import get_db
from ..deps import current_command_device, current_device, current_device_by_key
from ..detection import ingest
from ..models import AgentRelease, Command, Device, EnrollmentToken, Tenant, Ticket, utcnow
from ..security import digest, new_secret

router = APIRouter(prefix="/api/v1", tags=["Agent API"])


def _iso(value) -> str:
    return value.isoformat(timespec="seconds") + "Z" if value else ""


def reinstatement_target(raw_token: str | None) -> str | None:
    """Device id named by a reinstatement token (fet_rs-<device id>-<secret>; older frs.<id>.<secret> too)."""
    raw = str(raw_token or "")
    if raw.startswith("fet_rs-"):
        device_id, _, secret = raw[len("fet_rs-"):].rpartition("-")
        return device_id if device_id and secret else None
    if raw.startswith("frs."):
        parts = raw.split(".", 2)
        return parts[1] if len(parts) == 3 else None
    return None


def _platform(os_version: str, hint: str | None) -> str:
    if hint in {"windows", "linux", "macos", "android"}:
        return hint
    lowered = os_version.lower()
    if "android" in lowered:
        return "android"
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
    token = db.execute(select(EnrollmentToken).where(EnrollmentToken.token_hash == digest(raw)).with_for_update()).scalar_one_or_none()
    if token is None or token.revoked:
        raise HTTPException(403, "Enrollment token is invalid or revoked")
    if token.expires_at and token.expires_at < utcnow():
        raise HTTPException(403, "Enrollment token has expired")
    if token.max_uses is not None and token.uses >= token.max_uses:
        raise HTTPException(403, "Enrollment token has no uses left")
    return token


def _sync_cmdb_from_agent(db: Session, device: Device) -> None:
    try:
        psa.sync_managed_device(db, device)
    except ValueError as exc:
        # CMDB corruption must be visible, but must not take down the agent's
        # security heartbeat or repeatedly rotate a valid enrollment key.
        audit.record(db, "system", "cmdb.sync.conflict", device.id, device.tenant_id,
                     reason=str(exc))


def _reinstall_hash(body: dict, tenant_id: str, platform: str) -> str | None:
    proof = body.get("reinstallProof")
    if platform == "windows" and isinstance(proof, str) and re.fullmatch(r"[0-9a-fA-F]{64}", proof):
        return digest(f"{tenant_id}|windows|{proof.lower()}")
    return None


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
    raw_token = body.get("enrollmentToken") or x_fenrir_token
    token = _resolve_enrollment_token(db, raw_token)
    if token is None and not settings.open_enrollment:
        raise HTTPException(403, "An enrollment token is required")

    tenant = db.get(Tenant, token.tenant_id) if token else _unassigned_tenant(db)
    if tenant is None or (tenant.settings or {}).get("archived"):
        raise HTTPException(403, "This customer is archived or deleted; it cannot enrol devices")
    api_key = new_secret("fdk", 32)
    device = None
    target_id = reinstatement_target(raw_token) if token else None
    # Only a token issued for reinstating exactly this device counts (an ordinary token cannot pose as one).
    reinstating = target_id is not None and token.label == f"Reinstate {target_id}"
    platform = _platform(os_version, body.get("platform"))
    proof = _reinstall_hash(body, tenant.id, platform)
    resumed = False
    if reinstating:
        device = db.scalar(select(Device).where(Device.id == target_id).with_for_update())
        if device is None or device.tenant_id != tenant.id:
            raise HTTPException(403, "Reinstatement target is invalid")
        if device.api_key_hash != f"retired-{device.id}":
            raise HTTPException(409, "Device is no longer decommissioned")
        if device.platform != _platform(os_version, body.get("platform")):
            raise HTTPException(409, "Device platform does not match the reinstatement target")
        # Old Windows releases generated a brace-wrapped v4 GUID per installation.
        # A device-specific, single-use installer can bridge the first reinstall.
        legacy_guid = r"(?i)\{[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\}"
        legacy_windows = (platform == "windows" and proof and not device.reinstall_hash
                          and device.hostname.casefold() == hostname.casefold()
                          and re.fullmatch(legacy_guid, device.serial_number or "") and re.fullmatch(legacy_guid, serial))
        if device.reinstall_hash and device.reinstall_hash != proof:
            raise HTTPException(409, "Reinstallation identity does not match the reinstatement target")
        if device.serial_number and device.serial_number != serial and not (proof and device.reinstall_hash == proof or legacy_windows):
            raise HTTPException(409, "Device serial number does not match the reinstatement target")
        if proof:
            owner = db.scalar(select(Device).where(Device.tenant_id == tenant.id, Device.reinstall_hash == proof)
                              .with_for_update())
            if owner and owner.id != device.id:
                if owner.api_key_hash != f"retired-{owner.id}":
                    raise HTTPException(409, "Decommission the duplicate device before reinstating this record")
                owner.reinstall_hash = None
                db.flush()
                audit.record(db, f"device:{hostname}", "device.duplicate_identity_transferred", device.id,
                             tenant.id, previousDeviceId=owner.id)
    elif token and proof:
        device = db.scalar(select(Device).where(Device.tenant_id == tenant.id, Device.platform == platform,
                                                Device.reinstall_hash == proof).with_for_update())
        resumed = device is not None
    if not reinstating and device is None and token and serial and serial != "SERIAL-UNAVAILABLE":
        # Re-imaged or reinstalled machine: keep its history, rotate its key.
        matches = db.scalars(select(Device).where(Device.tenant_id == tenant.id, Device.platform == platform,
                                                  Device.serial_number == serial).limit(2).with_for_update()).all()
        if len(matches) > 1 or (matches and matches[0].reinstall_hash and matches[0].reinstall_hash != proof):
            raise HTTPException(409, "Device identity conflict")
        device = matches[0] if matches else None
    if not reinstating and device is not None and device.api_key_hash == f"retired-{device.id}":
        raise HTTPException(409, "Use a reinstatement installer for this decommissioned device")
    if device is None:
        device = Device(tenant_id=tenant.id, hostname=hostname, serial_number=serial, dns_token=secrets.token_urlsafe(24),
                        api_key_hash=digest(api_key))
        db.add(device)
    if token and proof:
        device.reinstall_hash = proof
    device.api_key_hash = digest(api_key)
    device.pending_api_key_hash, device.api_key_rotated_at, device.key_rotation_requested = None, utcnow(), False
    if reinstating:
        device.dns_token = secrets.token_urlsafe(24)
    device.hostname, device.os_version = hostname, os_version
    device.platform = _platform(os_version, body.get("platform"))
    device.agent_version = str(body.get("agentVersion") or device.agent_version or "")[:64]
    if token and token.group_id and not resumed:
        group_rules.place_by_hand(device, token.group_id)  # the code's group is a person's choice: rules leave it alone
    device.approved = token is not None
    device.ip_address = request.client.host if request.client else ""
    device.last_seen_at = utcnow()
    if token:
        token.uses += 1
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Concurrent enrolment or conflicting device identity")
    group_rules.evaluate(db, device)  # no-op when the code (or a person earlier) chose the group
    if resumed:
        audit.record(db, f"device:{hostname}", "device.reinstalled", device.id, tenant.id)
    _, policy_doc = services.effective_policy(db, device)
    device.applied_policy_revision = policy_doc["revision"]
    _sync_cmdb_from_agent(db, device)
    if reinstating:
        audit.record(db, f"device:{hostname}", "device.reinstated", device.id, tenant.id)
    audit.record(db, f"device:{hostname}", "device.enrolled", device.id, tenant.id, platform=device.platform,
                 token=token.label if token else "open-enrollment")
    db.commit()

    return {"deviceId": device.id, "tenantId": tenant.id, "issuedAt": _iso(utcnow()), "approved": device.approved,
            **_key_urls(settings, device, api_key), "policy": policy_doc}


def _key_urls(settings, device: Device, api_key: str) -> dict:
    """The device key and the URLs that carry it, in the shape enrolment always returned them."""
    base = settings.public_base_url.rstrip("/")
    return {
        "deviceApiKey": api_key,
        "commandChannelUrl": f"{base}/api/v1/devices/{device.id}/commands/pending?deviceApiKey={api_key}",
        "dnsOverHttpsUrl": f"{base}/dns/{device.dns_token}/dns-query",
        "realtimeUrl": ("wss://" + base[8:] if base.startswith("https://") else "ws://" + base.removeprefix("http://"))
        + f"/api/v1/devices/{device.id}/realtime",
    }


@router.post("/devices/{device_id}/rotate-key")
def rotate_key(device: Device = Depends(current_device), db: Session = Depends(get_db)):
    """Step 1 of key rotation (devicekeys.py): a new key, pending until the agent first uses it. The current key keeps
    working until then, so an agent that fails to save the new key just asks again."""
    try:
        key = devicekeys.start(db, device)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return _key_urls(get_settings(), device, key)


@router.post("/devices/{device_id}/presence")
def presence_check_in(device: Device = Depends(current_device), db: Session = Depends(get_db)):
    """A bare check-in from an agent whose live connection is down and whose main loop is busy (a scan, a long script):
    it only keeps the device online. Authenticating it records the check-in."""
    db.commit()
    return {"ok": True}


@router.post("/devices/{device_id}/heartbeat")
def heartbeat(body: dict = Body(default={}), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    device.agent_version = str(body.get("agentVersion") or device.agent_version)[:64]
    device.platform_version = str(body.get("platformVersion") or device.platform_version)[:64]
    if re.fullmatch(r"[a-z0-9]{1,64}", str(body.get("buildId") or "")):
        device.agent_build = str(body["buildId"])
    proof = _reinstall_hash(body, device.tenant_id, device.platform)
    if device.approved and proof and not device.reinstall_hash:
        try:
            with db.begin_nested():
                device.reinstall_hash = proof
                db.flush()
        except IntegrityError:
            pass  # Another device owns this proof. Keep both records and continue the heartbeat.
    if body.get("healthState"):
        device.health_reported_at = utcnow()
    previous_health = device.health_state
    device.health_state = str(body.get("healthState") or device.health_state)[:40]
    endpoint_health.on_heartbeat(db, device, previous_health)
    if "isolated" in body:
        device.isolated = bool(body["isolated"])
    if isinstance(body.get("metrics"), dict):
        rmm.record_heartbeat_metrics(db, device, body["metrics"])
        rmm.evaluate_device(db, device)
    device.metrics = {**(device.metrics or {}), "commandCancellation": body.get("commandCancellation") is True}
    _sync_cmdb_from_agent(db, device)
    resolution, policy_doc = services.effective_policy(db, device)
    if device.platform == "android" and isinstance(body.get("metrics"), dict):
        from .. import android_compliance

        android_compliance.record(db, device, body["metrics"], resolution["settings"])
    if device.platform == "android":
        from .. import care

        care.on_heartbeat(db, device, body.get("metrics"))
    pending = db.execute(select(func.count()).where(Command.device_id == device.id, Command.status == "pending")).scalar() or 0
    db.commit()
    reply = {"receivedAt": _iso(utcnow()), "effectivePolicyRevision": policy_doc["revision"], "commandsPending": pending,
             "approved": device.approved, "realtimePath": f"/api/v1/devices/{device.id}/realtime",
             "rotateKey": devicekeys.due(device, get_settings())}
    if device.platform == "android":
        # Phones re-sync lost mode from every heartbeat, so a missed command cannot leave it stuck on or off.
        lost = device.lost_mode or {}
        reply["lostMode"] = {"enabled": bool(lost.get("enabled")), "message": lost.get("message", ""), "phone": lost.get("phone", "")}
        from .. import geofence

        reply["geofences"] = geofence.for_phone(db, device)  # safe zones: proximity alerts and faster location checks
        from .. import care

        reply["tracking"] = care.tracking_reply(device)  # how often to report location (care level, SOS)
    return reply


SUPPORT_REQUESTS_PER_HOUR = 5


@router.post("/devices/{device_id}/support-requests")
def support_request(body: dict = Body(default={}), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    """'Request support' from the agent window: the person at the device asks their IT provider for help."""
    from datetime import timedelta

    summary = " ".join(str(body.get("summary") or "").split())[:200]
    details = str(body.get("details") or "").strip()[:4000]
    if not summary:
        raise HTTPException(422, "Describe the problem in a few words")
    recent = db.execute(select(func.count()).where(Ticket.device_id == device.id, Ticket.source == "agent",
                                                   Ticket.created_at > utcnow() - timedelta(hours=1))).scalar() or 0
    if recent >= SUPPORT_REQUESTS_PER_HOUR:
        raise HTTPException(429, "Several requests were already sent from this device in the last hour; your IT provider has them")
    user = str(body.get("user") or "")[:120]
    contact = str(body.get("contact") or "")[:200]
    description = "\n\n".join(part for part in (
        details,
        f"Sent from the agent on {device.hostname} by {user or 'the signed-in user'}." + (f" Contact: {contact}" if contact else ""),
    ) if part)
    ticket = services.open_ticket(db, device.tenant_id, summary, description=description, priority="P3", source="agent",
                                  requester=user or device.hostname, device_id=device.id)
    audit.record(db, f"device:{device.hostname}", "ticket.requested_from_agent", str(ticket.number), device.tenant_id,
                 ticket=ticket.id)
    db.commit()
    return {"ticketId": ticket.id, "number": ticket.number}


@router.post("/devices/{device_id}/policy-check-in")
def policy_check_in(body: dict = Body(default={}), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    _, policy_doc = services.effective_policy(db, device)
    changed = body.get("currentPolicyRevision") != policy_doc["revision"]
    device.applied_policy_revision = policy_doc["revision"]
    db.commit()
    return {"retrievedAt": _iso(utcnow()), "changed": changed, "policy": policy_doc}


async def _lenient_json(request: Request) -> dict:
    """The body as a JSON object, tolerating raw control characters inside strings. Windows agents before this fix
    sent them unescaped (from a service description or file name), and refusing the batch left the agent retrying it
    forever, so nothing it queued afterwards, malware findings included, ever arrived."""
    try:
        body = json.loads((await request.body()).decode("utf-8", errors="replace"), strict=False)
    except json.JSONDecodeError:
        raise HTTPException(422, "The body must be JSON") from None
    if not isinstance(body, dict):
        raise HTTPException(422, "The body must be a JSON object")
    return body


# The agent reporting a problem with itself that needs a person: Microsoft Defender flagging or quarantining it (the
# device goes offline until the program is restored), or a policy that makes Defender ignore its exclusions.
AGENT_SELF_ALERTS = {
    "agent.defender.flagged": ("agent:defender-flagged", "high", "Microsoft Defender flagged the Fenrir agent on {host}",
                               "Defender treated a Fenrir program as a threat (details below). If it quarantined the agent, the "
                               "device stays offline until the program is restored: the backup watchdog tries this every 5 "
                               "minutes. Report the file to Microsoft as a false positive, and make sure Fenrir's folder is "
                               "excluded in any Defender policy (Group Policy or Intune)."),
    "agent.defender.exclusions_refused": ("agent:defender-exclusions-refused", "medium",
                                          "Defender ignores Fenrir's exclusions on {host}",
                                          "A Group Policy or Intune setting (DisableLocalAdminMerge) makes Microsoft Defender "
                                          "ignore exclusions set on the PC, so it can quarantine the Fenrir agent. Add Fenrir's "
                                          "install folder and fenrir-agent-service.exe to the exclusions in that policy."),
}


def _agent_self_alerts(db: Session, device: Device, events: list) -> None:
    from ..models import Alert

    for event in events:
        if not isinstance(event, dict):
            continue
        rule = AGENT_SELF_ALERTS.get(str(event.get("eventType") or ""))
        if rule is None:
            continue
        rule_id, severity, title, description = rule
        open_alert = db.execute(select(Alert).where(Alert.device_id == device.id, Alert.rule_id == rule_id,
                                                    Alert.status.in_(("new", "triaged")))).scalars().first()
        if open_alert is not None:
            continue
        db.add(Alert(tenant_id=device.tenant_id, device_id=device.id, rule_id=rule_id, severity=severity, mitre=[], event_ids=[],
                     title=title.format(host=device.hostname)[:300],
                     details={"category": "agent-health", "source": "Fenrir agent", "description": description,
                              "report": str(event.get("payloadJson") or "")[:4000]}))


@router.post("/devices/{device_id}/telemetry")
def telemetry(body: dict = Depends(_lenient_json), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    events = body.get("events")
    if not isinstance(events, list):
        raise HTTPException(400, "events must be a list")
    limit = get_settings().max_telemetry_batch
    if len(events) > limit:
        raise HTTPException(413, f"at most {limit} events per batch")
    result = ingest(db, device, events)
    if events:
        device.telemetry_at = utcnow()
    _agent_self_alerts(db, device, events)
    db.commit()
    # No running total: counting a device's whole history on every batch got slower as the table grew.
    return {"receivedAt": _iso(utcnow()), "accepted": result.accepted, "duplicates": result.duplicates,
            "notStored": result.not_stored, "alerts": result.alerts}


@router.get("/devices/{device_id}/commands/pending")
def pending_commands(limit: int = Query(default=20, ge=1, le=100), types: str | None = Query(default=None, max_length=500),
                     include_cancelling: bool = False,
                     device: Device = Depends(current_device), db: Session = Depends(get_db)):
    # Serialise dispatch with decommissioning. A credential check before this lock may have raced retirement.
    device = db.execute(select(Device).where(Device.id == device.id).with_for_update()
                        .execution_options(populate_existing=True)).scalar_one()
    if device.api_key_hash == f"retired-{device.id}":
        raise HTTPException(401, "Device has been decommissioned")
    # `types` lets an agent fetch only some commands (the Windows agent polls remote sessions on their own thread).
    states = ("pending", "dispatched", "cancelling") if include_cancelling else ("pending", "dispatched")
    query = select(Command).where(Command.device_id == device.id, Command.status.in_(states))
    wanted = [t.strip() for t in (types or "").split(",") if t.strip()]
    if wanted:
        query = query.where(Command.type.in_(wanted))
    from .. import platform_security

    if platform_security.stopped(db):  # emergency stop: hand out containment only, whatever was queued
        query = query.where(Command.type.in_(platform_security.STOP_EXEMPT_COMMANDS))
    commands = db.execute(query.order_by(Command.created_at).limit(limit).with_for_update()
                          .execution_options(populate_existing=True)).scalars().all()
    now = utcnow()
    if not wanted:
        device.command_poll_at = now
    deliver = []
    for command in commands:
        if command.type == "patch.install" and command.status == "pending" and rmm.patch_window_closed(command, now):
            rmm.defer_window_install(db, command, now)
            continue
        deliver.append(command)
        if command.status == "pending":
            command.status, command.dispatched_at, command.updated_at = "dispatched", now, now
    db.commit()
    return {
        "polledAt": _iso(now),
        "items": [
            {"id": c.id, "type": c.type, "issuedBy": c.issued_by, "createdAt": _iso(c.created_at), "updatedAt": _iso(c.updated_at),
             "targetPath": c.target_path, "recordId": c.record_id, "payloadJson": json.dumps({k: v for k, v in c.payload.items() if k != "secretEnvelope"}) if c.payload else ""}
            for c in deliver
        ],
    }


@router.get("/devices/{device_id}/commands/{command_id}/state")
def command_state(command_id: str, device: Device = Depends(current_command_device), db: Session = Depends(get_db)):
    command = db.get(Command, command_id)
    if command is None or command.device_id != device.id or command.tenant_id != device.tenant_id:
        raise HTTPException(404, "Unknown command")
    db.commit()  # long-running commands retain presence while their independent monitor checks in
    return {"id": command.id, "status": command.status,
            "cancelRequested": command.status in {"cancelling", "cancelled", "expired"},
            "cancelRequestedAt": _iso(command.cancel_requested_at)}


@router.post("/devices/{device_id}/commands/{command_id}/complete")
def complete_command(command_id: str, body: dict = Body(...), device: Device = Depends(current_command_device),
                     db: Session = Depends(get_db)):
    # Same lock order as polling/retirement; result callbacks may update the device too.
    device = db.execute(select(Device).where(Device.id == device.id).with_for_update()
                        .execution_options(populate_existing=True)).scalar_one()
    query = select(Command).where(Command.id == command_id)
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        # Lock the command until commit: concurrent agent retries must not
        # trigger duplicate monitoring/RMM callbacks.
        query = query.with_for_update()
    command = db.execute(query).scalar_one_or_none()
    if command is None or command.device_id != device.id or command.tenant_id != device.tenant_id:
        raise HTTPException(404, "Unknown command")
    status = str(body.get("status") or "completed").lower()
    if status not in {"completed", "succeeded", "success", "ok", "failed", "error", "cancelled"}:
        raise HTTPException(422, "Invalid command completion status")
    requested_status = "cancelled" if status == "cancelled" else "completed" if status in {"completed", "succeeded", "success", "ok"} else "failed"
    raw = body.get("resultJson")
    if isinstance(raw, str) and len(raw) > 1_048_576:
        raise HTTPException(413, "Command result exceeds the maximum size")
    try:
        result = json.loads(raw) if isinstance(raw, str) and raw else (raw or {})
    except json.JSONDecodeError:
        raise HTTPException(422, "Command result must be valid JSON") from None
    if not isinstance(result, dict):
        raise HTTPException(422, "Command result must be a JSON object")
    # Derive the *effective* result before idempotency checks; a retry of the
    # same non-zero exit code must acknowledge the same failed outcome.
    if requested_status != "cancelled" and isinstance(result.get("exitCode"), int) and result["exitCode"] != 0:
        requested_status = "failed"
    if command.status in {"completed", "failed", "cancelled"}:
        if command.status != requested_status:
            raise HTTPException(409, "Command was already completed with a different outcome")
        return {"id": command.id, "status": command.status, "duplicate": True}
    if command.status == "expired":
        raise HTTPException(409, "Command can no longer be completed")
    if requested_status == "cancelled" and command.cancel_requested_at is None:
        raise HTTPException(409, "Cancellation has not been requested")
    if command.status not in {"pending", "dispatched", "cancelling"}:
        raise HTTPException(409, "Command is not active")
    command.status = requested_status
    if requested_status == "cancelled":
        result["stopConfirmed"] = True
    command.result = result
    command.completed_at = command.updated_at = utcnow()
    if command.type == "device.isolate" and command.status == "completed":
        device.isolated = True
    elif command.type == "device.release" and command.status == "completed":
        device.isolated = False
    audit.record(db, f"device:{device.hostname}", "command.completed", command.id, device.tenant_id,
                 type=command.type, status=command.status)
    rmm.on_command_complete(db, device, command)
    from . import elevation

    elevation.on_command_complete(db, device, command)
    db.commit()
    return {"id": command.id, "status": command.status}


def _version_tuple(version: str) -> tuple:
    return tuple(int(part) if part.isdigit() else 0 for part in re.split(r"[.\-+]", version or "0"))


def _windows_build() -> dict | None:
    """The Windows agent this server's image ships: build id and SHA-256 of FenrirSetup.exe."""
    from .. import deployment_installers

    mode, _ = deployment_installers.windows_release_mode()  # also verifies the SHA-256
    meta_file = deployment_installers.release_file("windows/build.json")
    if mode is None or meta_file is None:
        return None
    try:
        meta = json.loads(meta_file.read_text())
    except (OSError, ValueError):
        return None
    build_id = str(meta.get("buildId") or "")
    if not re.fullmatch(r"[a-f0-9]{8,64}", build_id):
        return None  # images built before build ids existed cannot be compared safely
    return {"buildId": build_id, "sha256": str(meta["sha256"]).lower()}


@router.get("/agent/update/windows")
def agent_update_windows(device: Device = Depends(current_device_by_key), db: Session = Depends(get_db)):
    """What a Windows agent should be running. It upgrades itself when its build id differs."""
    build = _windows_build()
    resolution, _ = services.effective_policy(db, device)
    allowed = bool(resolution["settings"].get("updates", {}).get("autoUpdateAgent", True))
    if build is not None:
        offered, reason = rollouts.offer(db, device, "windows", build["buildId"], record=allowed)
    db.commit()  # records last_seen from the device lookup, and the rollout offer
    if build is None:
        return {"available": False, "autoUpdate": allowed, "buildId": "", "sha256": "", "url": ""}
    if not offered:  # staged rollout: not this device's turn yet, or paused
        return {"available": False, "autoUpdate": allowed, "buildId": "", "sha256": "", "url": "", "rollout": reason}
    return {"available": True, "autoUpdate": allowed, **build, "url": "/api/v1/agent/update/windows/package"}


@router.get("/agent/update/windows/package")
def agent_update_windows_package(device: Device = Depends(current_device_by_key), db: Session = Depends(get_db)):
    from fastapi.responses import FileResponse

    from .. import deployment_installers

    if _windows_build() is None:
        raise HTTPException(404, "No Windows agent build is available on this server")
    audit.record(db, f"device:{device.hostname}", "agent.update.downloaded", "windows", device.tenant_id)
    db.commit()
    return FileResponse(deployment_installers.release_file("windows/FenrirSetup.exe"), filename="FenrirSetup.exe",
                        media_type="application/vnd.microsoft.portable-executable")


@router.get("/agent/update/{os_name}")
def agent_update(os_name: str = Path(pattern="^(linux|macos)$"), arch: str = Query(pattern="^(amd64|arm64)$"),
                 device: Device = Depends(current_device_by_key), db: Session = Depends(get_db)):
    """The Linux/macOS agent build this server ships (version and SHA-256 from the image's build metadata)."""
    from .. import deployment_installers

    goos, sha_key = ("darwin", "darwinSha256") if os_name == "macos" else ("linux", "sha256")
    name = f"fenrir-agent-{goos}-{arch}"
    empty = {"available": False, "version": "", "sha256": "", "url": ""}
    binary = deployment_installers.release_file(name)
    meta_file = deployment_installers.release_file("linux-build.json")
    if binary is None or meta_file is None:
        return empty
    try:
        meta = json.loads(meta_file.read_text())
        version, sha = str(meta["version"]), str(meta[sha_key][arch]).lower()
        build_id = str(meta.get("buildId") or "")
    except (OSError, ValueError, KeyError, TypeError):
        return empty
    # Signed release manifest (FIX-07/AGT-03): agents built with a pinned release key install only what it signs.
    # Signed at image build time, or offline and dropped into deploy/releases (see docs/AUTO_UPDATE.md).
    manifest = signature = ""
    manifest_file = deployment_installers.signed_release_file(f"{os_name}-{arch}.manifest.json")
    signature_file = manifest_file and manifest_file.with_suffix(".sig")
    if signature_file is not None and (signature_file.is_symlink() or not signature_file.is_file()):
        signature_file = None
    if manifest_file is not None and signature_file is not None:
        try:
            manifest, signature = manifest_file.read_text(), signature_file.read_text().strip()
            signed = json.loads(manifest)
            version, sha = str(signed.get("version") or version), str(signed.get("sha256") or sha).lower()
        except (OSError, ValueError):
            manifest = signature = ""
    resolution, _ = services.effective_policy(db, device)
    allowed = bool(resolution["settings"].get("updates", {}).get("autoUpdateAgent", True))
    offered, reason = rollouts.offer(db, device, os_name, build_id, version, record=allowed) if build_id else (True, "")
    db.commit()  # records last_seen from the device lookup, and the rollout offer
    if not offered:  # staged rollout: not this device's turn yet, or paused
        return {**empty, "rollout": reason, "autoUpdate": allowed}
    return {"available": True, "version": version, "buildId": build_id, "sha256": sha, "url": f"/downloads/{name}",
            "autoUpdate": allowed, "manifest": manifest, "signature": signature}


@router.post("/update-check")
def update_check(body: dict = Body(default={}), x_device_api_key: str | None = Header(default=None), db: Session = Depends(get_db)):
    channel = str(body.get("channel") or "stable")
    platform = str(body.get("platform") or "")
    if x_device_api_key:
        device = devicekeys.find(db, x_device_api_key)
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
        device = devicekeys.find(db, x_device_api_key)
        if device is not None:
            return device.tenant_id
    feed_token = get_settings().feed_token
    if feed_token and x_fenrir_token != feed_token and not x_device_api_key:
        raise HTTPException(401, "A device key or feed token is required")
    return None


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


# One handler serves both paths and methods; each registration needs its own OpenAPI operation ID.
for _path, _name in (("/agent/bundle", "agent_bundle"), ("/signatures/delta", "signatures_delta")):
    for _method in ("GET", "POST"):
        router.add_api_route(_path, agent_bundle, methods=[_method], operation_id=f"{_name}_{_method.lower()}")


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
        device = devicekeys.find(db, x_device_api_key)
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
    device = devicekeys.find(db, x_device_api_key)
    if device is None:
        raise HTTPException(401, "Unknown device credentials")
    device.last_seen_at = utcnow()
    result = ingest(db, device, [body])
    db.commit()
    return {"status": "success", "eventId": body.get("eventId"), "alertsGenerated": result.alerts}
