"""Privileged access management on Windows: temporary local administrator accounts on request.

A signed-in user asks from the agent window or the PAM tray, either for admin access in general (``session``) or to
run one program elevated (``run``). The policy decides (privilege.elevationRequests): "off" refuses, "auto-approve"
grants straight away, "approval" waits for a technician in the console.

A grant queues ``elevation.grant``. The agent creates a temporary local administrator for that user (``fadm-<user>-<id>``)
with a random password that never leaves the device, and a Windows account expiry as a backstop.
- session: the agent window shows the account and password; the user enters them when Windows asks for an administrator.
- run: the agent launches the program as that account; the user only confirms the Windows prompt.
The account and its profile are deleted when the time is up, when the launched program exits, when the user is done,
or when a technician revokes it. Each step is reported back (``/events``) and audited against the device and the user.
"""
from __future__ import annotations

import re
from datetime import timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, elevation_rules, ratelimit, services
from ..db import get_db
from ..deps import Principal, current_device, current_principal
from ..models import Command, Device, ElevationAllowance, ElevationRequest, utcnow

agent = APIRouter(prefix="/api/v1/devices/{device_id}/elevation-requests", tags=["Agent"])
console = APIRouter(prefix="/api/console/elevation-requests", tags=["Devices"])
allowances = APIRouter(prefix="/api/console/elevation-allowances", tags=["Devices"])

_SID = re.compile(r"S-1-(5-21|12-1)(-\d{1,10}){3,8}")
_ACCOUNT = re.compile(r"fadm-[a-z0-9]{1,8}-[a-z0-9]{1,6}")
_WINDOWS_PATH = re.compile(r"[A-Za-z]:\\[^<>\"|?*]{1,1000}")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")
DEVICE_EVENTS = {"launched", "ended", "finished"}
# An approved request the device has not confirmed within this time is treated as lost, so asking again works.
STALE_APPROVAL = timedelta(minutes=10)
# A request nobody decided on within this time lapses, so a new one is evaluated against the current policy.
PENDING_LIFETIME = timedelta(hours=24)


def _resolution(db: Session, device: Device) -> dict:
    resolution, _ = services.effective_policy(db, device)
    return resolution


def _event(row: ElevationRequest, kind: str, by: str, **details) -> None:
    row.events = [*(row.events or []), {"at": utcnow().isoformat() + "Z", "type": kind, "by": by,
                                        **{k: v for k, v in details.items() if v not in (None, "")}}][-50:]


def _record(db: Session, actor: str, action: str, row: ElevationRequest, device: Device | None, **details) -> None:
    """Every audit entry names the device and the user the temporary admin session belongs to."""
    hostname = device.hostname if device else row.device_id
    audit.record(db, actor, action, f"{hostname}:{row.user}", row.tenant_id, request=row.id, device=row.device_id,
                 deviceName=hostname, user=row.user, userSid=row.user_sid, kind=row.kind or "session",
                 **{k: v for k, v in details.items() if v not in (None, "")})


def _view(row: ElevationRequest, device: Device | None) -> dict:
    status = row.status
    expires = row.granted_at + timedelta(minutes=row.minutes) if row.granted_at else None
    if status == "granted" and expires and expires < utcnow() and not row.ended_at:
        status = "expired"
    return {"id": row.id, "deviceId": row.device_id, "hostname": device.hostname if device else "", "user": row.user,
            "userSid": row.user_sid, "reason": row.reason, "minutes": row.minutes, "status": status, "kind": row.kind or "session",
            "target": row.target or "", "arguments": row.arguments or "", "account": row.account or "",
            "decidedBy": row.decided_by, "note": row.note, "createdAt": row.created_at.isoformat() + "Z",
            "decidedAt": row.decided_at.isoformat() + "Z" if row.decided_at else None,
            "grantedAt": row.granted_at.isoformat() + "Z" if row.granted_at else None,
            "expiresAt": expires.isoformat() + "Z" if expires else None,
            "endedAt": row.ended_at.isoformat() + "Z" if row.ended_at else None, "endReason": row.end_reason or "",
            "publisher": row.publisher or "", "sha256": row.sha256 or "", "approvedByRule": row.approved_by_rule or "",
            "events": row.events or []}


def _grant(db: Session, device: Device, row: ElevationRequest, actor: str) -> None:
    command = services.enqueue_command(db, device, "elevation.grant", actor, reason=f"Temporary admin for {row.user}",
                                       payload={"requestId": row.id, "userSid": row.user_sid, "user": row.user,
                                                "minutes": row.minutes, "kind": row.kind or "session",
                                                "target": row.target or "", "arguments": row.arguments or ""})
    row.status, row.command_id = "approved", command.id
    row.decided_by, row.decided_at = actor, utcnow()


def _auto_approve(db: Session, device: Device, row: ElevationRequest, decision: elevation_rules.Decision) -> None:
    _grant(db, device, row, decision.actor)
    row.approved_by_rule = decision.rule[:200]
    if decision.allowance is not None:
        row.minutes = max(5, min(480, decision.allowance.minutes or row.minutes))
        if row.command_id:
            _set_command_minutes(db, row)
        decision.allowance.uses = (decision.allowance.uses or 0) + 1
        decision.allowance.last_used_at = utcnow()
    _event(row, "approved", decision.actor, minutes=row.minutes, rule=decision.rule)
    _record(db, decision.actor, "elevation.approved", row, device, minutes=row.minutes, program=row.target, rule=decision.rule)


def _set_command_minutes(db: Session, row: ElevationRequest) -> None:
    command = db.get(Command, row.command_id)
    if command is not None and isinstance(command.payload, dict):
        command.payload = {**command.payload, "minutes": row.minutes}


def _settle_open(db: Session, device: Device, row: ElevationRequest) -> bool:
    """Lapses an open request that can no longer complete. Returns True when it is still open."""
    now = utcnow()
    if row.status == "pending" and row.created_at < now - PENDING_LIFETIME:
        row.status, row.note = "expired", "Nobody decided within 24 hours"
        _event(row, "expired", "system")
        return False
    if row.status == "approved":
        command = db.get(Command, row.command_id) if row.command_id else None
        lost = command is None or command.status in ("failed", "cancelled") or (
            row.decided_at is not None and row.decided_at < now - STALE_APPROVAL)
        if lost:
            if command is not None and command.status == "pending":
                command.status = "cancelled"
            row.status, row.note = "failed", "The device did not confirm it in time; it can be asked for again"
            _event(row, "failed", "system", error=row.note)
            return False
    return True


@agent.post("")
def request_elevation(body: dict = Body(...), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    user = str(body.get("user") or "")[:200]
    sid = str(body.get("userSid") or "")
    reason = str(body.get("reason") or "").strip()[:1000]
    kind = str(body.get("kind") or "session")
    target = str(body.get("target") or "").strip()[:1024]
    arguments = str(body.get("arguments") or "")[:2000]
    publisher = str(body.get("publisher") or "").strip()[:200]
    sha256 = str(body.get("sha256") or "").strip().lower()
    sha256 = sha256 if _SHA256.fullmatch(sha256) else ""
    if not user or not _SID.fullmatch(sid):
        raise HTTPException(422, "A signed-in local or domain user is required")
    if kind not in ("session", "run"):
        raise HTTPException(422, "kind must be session or run")
    if kind == "run" and not _WINDOWS_PATH.fullmatch(target):
        raise HTTPException(422, "A program to run is required (a full Windows path)")
    if (device.platform or "windows").lower() != "windows":
        raise HTTPException(422, "Elevation requests are available on Windows")
    resolution = _resolution(db, device)
    decision = elevation_rules.decide(db, device, resolution, user=user, sid=sid, kind=kind, target=target if kind == "run" else "",
                                      publisher=publisher if kind == "run" else "", sha256=sha256 if kind == "run" else "")
    if decision.outcome == "refused":
        raise HTTPException(403, "Admin access requests are turned off for this device")
    ratelimit.check(f"elevation:{device.id}", 30, 3600)
    open_requests = db.execute(select(ElevationRequest).where(
        ElevationRequest.device_id == device.id, ElevationRequest.user_sid == sid,
        ElevationRequest.status.in_(("pending", "approved")))).scalars().all()
    for open_request in open_requests:
        if not _settle_open(db, device, open_request):
            continue
        same = (open_request.kind or "session") == kind and (open_request.target or "") == (target if kind == "run" else "")
        if not same:
            continue
        if open_request.status == "pending" and decision.outcome == "auto":
            # The policy or an allowance changed since it was asked: grant it now rather than leave it waiting.
            _auto_approve(db, device, open_request, decision)
        db.commit()
        return {"id": open_request.id, "status": open_request.status, "minutes": open_request.minutes,
                "rule": open_request.approved_by_rule or ""}
    privilege = resolution["settings"].get("privilege", {})
    minutes = max(5, min(480, int(privilege.get("elevationMinutes", 30) or 30)))
    row = ElevationRequest(tenant_id=device.tenant_id, device_id=device.id, user=user, user_sid=sid, reason=reason,
                           minutes=minutes, kind=kind, target=target if kind == "run" else None,
                           arguments=arguments if kind == "run" else None,
                           publisher=(publisher or None) if kind == "run" else None, sha256=(sha256 or None) if kind == "run" else None)
    db.add(row)
    db.flush()
    _event(row, "requested", user, reason=reason, target=row.target, publisher=row.publisher)
    _record(db, f"device:{device.hostname}", "elevation.requested", row, device, mode=policy_mode(resolution), program=row.target,
            publisher=row.publisher, reason=reason)
    if decision.outcome == "auto":
        _auto_approve(db, device, row, decision)
    else:
        services.fire_webhooks(db, device.tenant_id, "elevation.requested",
                               {"id": row.id, "hostname": device.hostname, "user": user, "reason": reason, "minutes": minutes,
                                "kind": kind, "target": row.target, "publisher": row.publisher})
    db.commit()
    return {"id": row.id, "status": row.status, "minutes": row.minutes, "rule": row.approved_by_rule or ""}


def policy_mode(resolution: dict) -> str:
    from .. import policy_schema

    return policy_schema.elevation_mode(resolution)


@agent.post("/{request_id}/events")
def device_event(request_id: str, body: dict = Body(...), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    """The device reports the temporary admin account's life: a program launched as it, and its removal."""
    row = db.get(ElevationRequest, request_id)
    if row is None or row.device_id != device.id:
        raise HTTPException(404, "Request not found")
    kind = str(body.get("type") or "")
    if kind not in DEVICE_EVENTS:
        raise HTTPException(422, f"type must be one of {', '.join(sorted(DEVICE_EVENTS))}")
    account = str(body.get("account") or row.account or "")[:40]
    actor = f"device:{device.hostname}"
    if kind == "launched":
        target = str(body.get("target") or row.target or "")[:1024]
        _event(row, "launched", actor, account=account, target=target, pid=body.get("pid"))
        _record(db, actor, "elevation.program_launched", row, device, account=account, program=target, pid=body.get("pid"))
    else:
        reason = str(body.get("reason") or ("finished by the user" if kind == "finished" else "ended"))[:200]
        if not row.ended_at:
            row.ended_at, row.end_reason = utcnow(), reason
            if row.status in ("granted", "approved"):
                row.status = "ended"
        removed, profile = bool(body.get("accountRemoved", True)), body.get("profileRemoved")
        _event(row, "ended", actor, account=account, reason=reason, accountRemoved=removed, profileRemoved=profile)
        _record(db, actor, "elevation.account_removed" if removed else "elevation.account_removal_failed", row, device,
                account=account, reason=reason, profileRemoved=profile, error=str(body.get("error") or "")[:300])
    db.commit()
    return _view(row, device)


@console.get("")
def list_requests(status: str = Query(""), tenant_id: str = Query(""), device_id: str = Query(""),
                  principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    tenants = [tenant_id] if tenant_id else list(principal.tenant_ids)
    if tenant_id and tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Tenant not found")
    query = select(ElevationRequest).where(ElevationRequest.tenant_id.in_(tenants))
    if status:
        query = query.where(ElevationRequest.status == status)
    if device_id:
        query = query.where(ElevationRequest.device_id == device_id)
    rows = db.execute(query.order_by(ElevationRequest.created_at.desc()).limit(200)).scalars().all()
    devices = {d.id: d for d in db.execute(select(Device).where(Device.id.in_({r.device_id for r in rows}))).scalars()} if rows else {}
    return [_view(r, devices.get(r.device_id)) for r in rows]


@console.post("")
def grant_directly(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """A technician gives a user temporary admin rights on a device without a request from the agent window (for
    example while on the phone with them). Same temporary account, timeline and audit trail as an approved request.
    Without ``userSid``, the user signed in at the device (from its last check-in) is used."""
    principal.require("configure")
    principal.require("approve")
    device = db.get(Device, str(body.get("deviceId") or ""))
    if device is None or device.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Device not found")
    if (device.platform or "windows").lower() != "windows":
        raise HTTPException(422, "Temporary admin accounts are available on Windows")
    metrics = device.metrics or {}
    user = str(body.get("user") or metrics.get("loggedOnUser") or "").strip()[:200]
    sid = str(body.get("userSid") or (metrics.get("loggedOnUserSid") if user == metrics.get("loggedOnUser") else "") or "")
    if not user or not _SID.fullmatch(sid):
        raise HTTPException(422, "Nobody is signed in at this device; give the user's name and SID")
    reason = str(body.get("reason") or "").strip()[:1000]
    if len(reason) < 4:
        raise HTTPException(422, "Say why admin access is needed (it goes in the audit log)")
    try:
        minutes = max(5, min(480, int(body.get("minutes") or 30)))
    except (TypeError, ValueError):
        raise HTTPException(422, "minutes must be a number") from None
    row = ElevationRequest(tenant_id=device.tenant_id, device_id=device.id, user=user, user_sid=sid, reason=reason,
                           minutes=minutes, kind="session")
    db.add(row)
    db.flush()
    _event(row, "requested", principal.actor, reason=reason, note="Granted by a technician")
    _record(db, principal.actor, "elevation.requested", row, device, mode="technician", reason=reason)
    try:
        _grant(db, device, row, principal.actor)
    except services.CommandError as exc:
        raise HTTPException(409, str(exc)) from None
    _event(row, "approved", principal.actor, minutes=minutes)
    _record(db, principal.actor, "elevation.approved", row, device, minutes=minutes)
    db.commit()
    return _view(row, device)


def _owned(db: Session, principal: Principal, request_id: str) -> tuple[ElevationRequest, Device]:
    row = db.get(ElevationRequest, request_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Request not found")
    device = db.get(Device, row.device_id)
    if device is None:
        raise HTTPException(404, "Device not found")
    return row, device


@console.get("/{request_id}")
def get_request(request_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    row, device = _owned(db, principal, request_id)
    return _view(row, device)


@console.post("/{request_id}/approve")
def approve(request_id: str, body: dict = Body(default={}), principal: Principal = Depends(current_principal),
            db: Session = Depends(get_db)):
    principal.require("configure")
    principal.require("approve")
    row, device = _owned(db, principal, request_id)
    if row.status != "pending":
        raise HTTPException(409, f"This request is already {row.status}")
    if isinstance(body.get("minutes"), int):
        row.minutes = max(5, min(480, body["minutes"]))
    row.note = str(body.get("note") or "")[:500]
    try:
        _grant(db, device, row, principal.actor)
    except services.CommandError as exc:
        raise HTTPException(409, str(exc)) from None
    _event(row, "approved", principal.actor, minutes=row.minutes, note=row.note)
    _record(db, principal.actor, "elevation.approved", row, device, minutes=row.minutes, program=row.target)
    db.commit()
    return _view(row, device)


@console.post("/{request_id}/deny")
def deny(request_id: str, body: dict = Body(default={}), principal: Principal = Depends(current_principal),
         db: Session = Depends(get_db)):
    principal.require("respond")
    row, device = _owned(db, principal, request_id)
    if row.status != "pending":
        raise HTTPException(409, f"This request is already {row.status}")
    row.status, row.decided_by, row.decided_at = "denied", principal.actor, utcnow()
    row.note = str(body.get("note") or "")[:500]
    _event(row, "denied", principal.actor, note=row.note)
    _record(db, principal.actor, "elevation.denied", row, device, note=row.note)
    db.commit()
    return _view(row, device)


@console.post("/{request_id}/revoke")
def revoke(request_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """End a session early: the device deletes the temporary admin account now."""
    principal.require("configure")
    row, device = _owned(db, principal, request_id)
    if row.status not in {"approved", "granted"}:
        raise HTTPException(409, f"This request is {row.status}; there is nothing to revoke")
    services.enqueue_command(db, device, "elevation.revoke", principal.actor, reason=f"Revoke temporary admin for {row.user}",
                             payload={"requestId": row.id, "userSid": row.user_sid, "user": row.user, "account": row.account or ""})
    row.status = "revoked"
    _event(row, "revoked", principal.actor)
    _record(db, principal.actor, "elevation.revoked", row, device, account=row.account)
    db.commit()
    return _view(row, device)


def on_command_complete(db: Session, device: Device, command: Command) -> None:
    """Called when the agent reports an elevation.grant result: the temporary account it created (or why not)."""
    if command.type != "elevation.grant":
        return
    request_id = str((command.payload or {}).get("requestId") or "")
    row = db.get(ElevationRequest, request_id) if request_id else None
    if row is None or row.device_id != device.id or row.status != "approved":
        return
    result = command.result if isinstance(command.result, dict) else {}
    actor = f"device:{device.hostname}"
    if command.status == "completed":
        row.status, row.granted_at = "granted", utcnow()
        account = str(result.get("account") or "")
        row.account = account if _ACCOUNT.fullmatch(account) else None
        row.account_sid = str(result.get("accountSid") or "")[:200] or None
        if result.get("alreadyAdmin"):
            _event(row, "granted", actor, note="The user is already an administrator; no temporary account was needed")
            _record(db, actor, "elevation.granted", row, device, alreadyAdmin=True)
        else:
            _event(row, "granted", actor, account=row.account, minutes=row.minutes)
            _record(db, actor, "elevation.account_created", row, device, account=row.account, accountSid=row.account_sid,
                    minutes=row.minutes, program=row.target)
    else:
        row.status = "failed"
        row.note = str(result.get("error") or "The device could not create the temporary admin account")[:500]
        _event(row, "failed", actor, error=row.note)
        _record(db, actor, "elevation.failed", row, device, error=row.note)


# ---------------------------------------------------------------------------
# Allowances: admin access without asking each time
# ---------------------------------------------------------------------------


def _allowance_view(row: ElevationAllowance, device: Device | None) -> dict:
    now = utcnow()
    active = row.revoked_at is None and (row.expires_at is None or row.expires_at > now)
    return {"id": row.id, "tenantId": row.tenant_id, "deviceId": row.device_id, "hostname": device.hostname if device else "",
            "scope": "device" if row.device_id else "customer", "user": row.user, "userSid": row.user_sid,
            "anyUser": not row.user and not row.user_sid, "kinds": row.kinds, "programs": row.programs or [],
            "minutes": row.minutes, "expiresAt": row.expires_at.isoformat() + "Z" if row.expires_at else None,
            "note": row.note, "createdBy": row.created_by, "createdAt": row.created_at.isoformat() + "Z",
            "revokedAt": row.revoked_at.isoformat() + "Z" if row.revoked_at else None, "revokedBy": row.revoked_by,
            "uses": row.uses or 0, "lastUsedAt": row.last_used_at.isoformat() + "Z" if row.last_used_at else None,
            "active": active, "status": "active" if active else ("revoked" if row.revoked_at else "expired")}


def _allowance_target(row: ElevationAllowance, device: Device | None) -> str:
    who = row.user or "any user"
    return f"{device.hostname if device else 'all devices'}:{who}"


@allowances.get("")
def list_allowances(tenant_id: str = Query(""), device_id: str = Query(""), include_ended: bool = Query(False),
                    principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    if tenant_id and tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Tenant not found")
    tenants = [tenant_id] if tenant_id else list(principal.tenant_ids)
    query = select(ElevationAllowance).where(ElevationAllowance.tenant_id.in_(tenants))
    if device_id:
        device = db.get(Device, device_id)
        if device is None or device.tenant_id not in principal.tenant_ids:
            raise HTTPException(404, "Device not found")
        # This device's allowances and the customer-wide ones that also apply to it.
        query = query.where((ElevationAllowance.device_id == device_id) |
                            ((ElevationAllowance.device_id.is_(None)) & (ElevationAllowance.tenant_id == device.tenant_id)))
    rows = db.execute(query.order_by(ElevationAllowance.created_at.desc()).limit(500)).scalars().all()
    views = []
    devices = {d.id: d for d in db.execute(select(Device).where(Device.id.in_({r.device_id for r in rows if r.device_id}))).scalars()} if rows else {}
    for row in rows:
        view = _allowance_view(row, devices.get(row.device_id or ""))
        if include_ended or view["active"]:
            views.append(view)
    return views


@allowances.post("")
def create_allowance(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Let a user (or anyone) get admin access on a device, or on all of a customer's devices, without approval."""
    principal.require("configure")
    principal.require("approve")
    device = None
    if body.get("deviceId"):
        device = db.get(Device, str(body["deviceId"]))
        if device is None or device.tenant_id not in principal.tenant_ids:
            raise HTTPException(404, "Device not found")
        if (device.platform or "windows").lower() != "windows":
            raise HTTPException(422, "Admin access allowances are available on Windows")
        tenant_id = device.tenant_id
    else:
        tenant_id = str(body.get("tenantId") or "")
        if tenant_id not in principal.tenant_ids:
            raise HTTPException(404, "Choose a device or a customer")
    any_user = bool(body.get("anyUser"))
    user = "" if any_user else str(body.get("user") or "").strip()[:200]
    sid = "" if any_user else str(body.get("userSid") or "").strip()
    if not any_user and not user and device is not None:
        metrics = device.metrics or {}
        user = str(metrics.get("loggedOnUser") or "")[:200]
        sid = str(metrics.get("loggedOnUserSid") or "")
    if sid and not _SID.fullmatch(sid):
        raise HTTPException(422, "userSid is not a valid Windows user SID")
    if not any_user and not user and not sid:
        raise HTTPException(422, "Name the user, or choose any user")
    kinds = str(body.get("kinds") or "any")
    if kinds not in ("any", "session", "run"):
        raise HTTPException(422, "kinds must be any, session or run")
    programs = [str(p).strip()[:1024] for p in (body.get("programs") or []) if str(p).strip()][:50]
    try:
        minutes = max(5, min(480, int(body.get("minutes") or 60)))
        hours = body.get("hours")
        hours = None if hours in (None, "", 0, "0") else max(1, min(24 * 365, int(hours)))
    except (TypeError, ValueError):
        raise HTTPException(422, "minutes and hours must be numbers") from None
    note = str(body.get("note") or "").strip()[:500]
    if len(note) < 4:
        raise HTTPException(422, "Say why (it goes in the audit log)")
    row = ElevationAllowance(tenant_id=tenant_id, device_id=device.id if device else None, user=user, user_sid=sid, kinds=kinds,
                             programs=programs, minutes=minutes, expires_at=utcnow() + timedelta(hours=hours) if hours else None,
                             note=note, created_by=principal.actor)
    db.add(row)
    db.flush()
    audit.record(db, principal.actor, "elevation.allowance_created", _allowance_target(row, device), tenant_id, allowance=row.id,
                 device=row.device_id, user=user or "any user", userSid=sid, kinds=kinds, programs=programs, minutes=minutes,
                 hours=hours, note=note)
    db.commit()
    return _allowance_view(row, device)


@allowances.post("/{allowance_id}/revoke")
def revoke_allowance(allowance_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = db.get(ElevationAllowance, allowance_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Allowance not found")
    device = db.get(Device, row.device_id) if row.device_id else None
    if row.revoked_at is None:
        row.revoked_at, row.revoked_by = utcnow(), principal.actor
        audit.record(db, principal.actor, "elevation.allowance_revoked", _allowance_target(row, device), row.tenant_id, allowance=row.id,
                     device=row.device_id, user=row.user or "any user")
        db.commit()
    return _allowance_view(row, device)
