"""Remote access API: start/end sessions, viewer tokens, the relay WebSockets and the agent wake channel."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Body, Depends, HTTPException, Query, WebSocket
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, psa, remote
from ..db import get_db, session_factory
from ..deps import Principal, current_principal, scoped_tenant
from ..config import get_settings
from ..models import Command, Device, DeviceArtifact, RemoteSession, Tenant, Ticket, utcnow
from ..security import digest
from ..serialize import to_dict

log = logging.getLogger("fenrir.remote")
# Security analysts (not technicians or admins) get a remote shell only when response.remoteShell allows it.
ANALYST_ROLES = {"soc_analyst", "tenant_analyst"}

router = APIRouter(prefix="/api/console/remote", tags=["Remote access"])
sockets = APIRouter(tags=["Remote access"])


def _session_view(db: Session, session: RemoteSession) -> dict:
    device = db.get(Device, session.device_id)
    connected_minutes = 0.0
    if session.connected_at:
        end = session.ended_at or utcnow()
        connected_minutes = round((end - session.connected_at).total_seconds() / 60, 1)
    command = db.get(Command, session.command_id) if session.command_id else None
    start = None
    if command is not None:
        result = command.result or {}
        start = {"status": command.status, "updatedAt": to_dict(command).get("updatedAt"),
                 "reachedRelay": result.get("reachedRelay"), "logPath": result.get("logPath"), "error": result.get("error")}
    return {**to_dict(session), "startCommand": start,
            "deviceLastSeenAt": device.last_seen_at.isoformat() + "Z" if device and device.last_seen_at else None,
            "hostname": device.hostname if device else "", "platform": device.platform if device else "",
            "deviceOnline": remote.hub.device_online(session.device_id), "agentConnected": session.id in remote.hub.rooms
            and remote.hub.rooms[session.id].agent is not None, "connectedMinutes": connected_minutes,
            "recorded": bool(device and remote.remote_policy(db, device).get("recordSessions")),
            "recordingId": db.scalar(select(DeviceArtifact.id).where(DeviceArtifact.command_id == session.id,
                                                                     DeviceArtifact.kind == "remote.recording"))}


@router.post("/sessions")
def create_session(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    principal.require("remote")
    device = db.get(Device, str(body.get("deviceId") or ""))
    if device is None or device.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Device not found")
    if not device.approved:
        raise HTTPException(409, "Approve the device before connecting to it")
    mode = str(body.get("mode") or "desktop")
    if mode not in {"desktop", "terminal", "files"}:
        raise HTTPException(400, "mode must be desktop, terminal or files")
    ticket_id = body.get("ticketId")
    if ticket_id:
        ticket = db.get(Ticket, ticket_id)
        if ticket is None or (ticket.tenant_id not in principal.tenant_ids and ticket.account_tenant_id not in principal.tenant_ids):
            raise HTTPException(404, "Ticket not found")
        if ticket.account_tenant_id != device.tenant_id:
            raise HTTPException(422, "The ticket and remote-support device must belong to the same customer")
        if ticket.device_id and ticket.device_id != device.id:
            raise HTTPException(422, "The ticket is linked to a different managed device")
    if mode == "terminal" and principal.user.role in ANALYST_ROLES:
        from .. import services
        settings, _ = services.effective_policy(db, device)
        if not settings["settings"]["response"].get("remoteShell", False):
            raise HTTPException(403, "Analysts need the policy's 'Allow remote shell for analysts' setting to open a terminal")
    try:
        session = remote.start_session(db, device, principal.actor, mode, bool(body.get("viewOnly")), ticket_id,
                                       str(body.get("reason") or ""))
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    db.commit()
    return {**_session_view(db, session), "viewerPath": f"/remote/{session.id}"}


@router.get("/sessions")
def list_sessions(device_id: str | None = Query(default=None, alias="deviceId"), active: bool = False, tenant_id: str | None = None,
                  principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    scope = scoped_tenant(principal, tenant_id)
    query = select(RemoteSession).where(RemoteSession.tenant_id.in_(scope))
    if device_id:
        query = query.where(RemoteSession.device_id == device_id)
    if active:
        query = query.where(RemoteSession.status.in_(("waiting", "connected")))
    rows = db.execute(query.order_by(RemoteSession.created_at.desc()).limit(500)).scalars().all()
    return [_session_view(db, r) for r in rows]


def _owned_session(db: Session, principal: Principal, session_id: str) -> RemoteSession:
    session = db.get(RemoteSession, session_id)
    if session is None or session.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Session not found")
    return session


@router.get("/sessions/{session_id}")
def get_session(session_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    session = _owned_session(db, principal, session_id)
    view = _session_view(db, session)
    device = db.get(Device, session.device_id)
    tenant = db.get(Tenant, session.tenant_id)
    view["device"] = {"id": device.id, "hostname": device.hostname, "osVersion": device.os_version, "platform": device.platform,
                      "metrics": device.metrics or {}, "ipAddress": device.ip_address} if device else None
    view["tenantName"] = tenant.name if tenant else ""
    return view


@router.post("/sessions/{session_id}/viewer-token")
def mint_viewer_token(session_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    session = _owned_session(db, principal, session_id)
    if session.status in {"ended", "failed", "denied"}:
        raise HTTPException(409, f"Session {session.status}")
    return {"token": remote.viewer_token(session, principal.actor, principal.session_id), "path": f"/ws/remote/{session.id}/viewer"}


@router.post("/sessions/{session_id}/end")
def end_remote_session(session_id: str, body: dict = Body(default={}), principal: Principal = Depends(current_principal),
                       db: Session = Depends(get_db)):
    principal.require("respond")
    session = _owned_session(db, principal, session_id)
    remote.end_session(db, session, principal.actor, "ended")
    entry = None
    if body.get("logTime") and session.connected_at:
        ticket = db.get(Ticket, body.get("ticketId") or session.ticket_id) if (body.get("ticketId") or session.ticket_id) else None
        minutes = max(1.0, (session.ended_at - session.connected_at).total_seconds() / 60)
        try:
            entry = psa.create_time_entry(
                db, member=principal.actor, owner_tenant_id=ticket.tenant_id if ticket else session.tenant_id,
                account_tenant_id=ticket.account_tenant_id if ticket else session.tenant_id, hours=round(minutes / 60, 2),
                ticket=ticket, work_type=str(body.get("workType") or "Remote Support"),
                notes=str(body.get("notes") or f"Remote {session.mode} session"), remote_session_id=session.id,
                started_at=session.connected_at, ended_at=session.ended_at)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    db.commit()
    room = remote.hub.rooms.get(session.id)
    if room is not None and remote.hub.loop is not None:
        import asyncio

        message = json.dumps({"ch": "sys", "t": "end", "by": principal.actor})
        for peer in ([room.agent] if room.agent else []) + list(room.viewers):
            asyncio.run_coroutine_threadsafe(peer.send(message), remote.hub.loop)
    return {"session": _session_view(db, session), "timeEntry": to_dict(entry) if entry else None}


# --------------------------------------------------------------------------- relay sockets


def _db_call(fn, *args):
    db = session_factory()()
    try:
        result = fn(db, *args)
        db.commit()
        return result
    finally:
        db.close()


def _agent_join(db: Session, session_id: str, device_id: str) -> dict | None:
    session = db.get(RemoteSession, session_id)
    if session is None or session.device_id != device_id or session.status in {"ended", "failed", "denied"}:
        return None
    now = utcnow()
    session.status = "connected"
    session.connected_at = session.connected_at or now
    session.events = (session.events or []) + [{"at": now.isoformat(), "by": f"device:{device_id}", "type": "agent.connected"}]
    device = db.get(Device, device_id)
    policy = remote.remote_policy(db, device) if device else {}
    return {"viewOnly": session.view_only, "allow": policy}


def _console_session_active(db: Session, console_session: str) -> bool:
    from ..models import UserSession

    row = db.get(UserSession, console_session)
    return row is not None and row.revoked_at is None and row.expires_at > utcnow()


def _viewer_join(db: Session, session_id: str, actor: str) -> dict | None:
    session = db.get(RemoteSession, session_id)
    if session is None or session.status in {"ended", "failed", "denied"}:
        return None
    session.events = (session.events or []) + [{"at": utcnow().isoformat(), "by": actor, "type": "viewer.connected"}]
    device = db.get(Device, session.device_id)
    policy = remote.remote_policy(db, device) if device else {}
    return {"viewOnly": session.view_only, "allow": policy, "mode": session.mode, "deviceId": session.device_id}


def _flush_room(db: Session, session_id: str, events: list[dict], bytes_relayed: int, end_reason: str | None, by: str) -> None:
    session = db.get(RemoteSession, session_id)
    if session is None:
        return
    if events:
        session.events = (session.events or []) + events
        for item in events:
            audit.record(db, item.get("by", by), f"remote.{item['type']}", session.id, session.tenant_id, path=item.get("path", ""))
    session.bytes_relayed = (session.bytes_relayed or 0) + bytes_relayed
    if end_reason:
        remote.end_session(db, session, by, end_reason)


async def _close(websocket: WebSocket, code: int, reason: str) -> None:
    try:
        await websocket.close(code=code, reason=reason)
    except Exception:  # noqa: BLE001
        pass


@sockets.websocket("/ws/remote/{session_id}/agent")
async def agent_socket(websocket: WebSocket, session_id: str, token: str | None = None):
    claims = remote.check_token(token or websocket.headers.get("x-fenrir-session-token"), session_id, "remote-agent")
    if claims is None:
        await _close(websocket, 4401, "invalid token")
        return
    info = await run_in_threadpool(_db_call, _agent_join, session_id, claims.get("dev", ""))
    if info is None:
        await _close(websocket, 4404, "session not available")
        return
    await websocket.accept()
    room = remote.hub.room(session_id, info["viewOnly"], info["allow"])
    if info["allow"].get("recordSessions") and room.recorder is None:
        try:
            from .artifacts import artifact_dir
            room.recorder = remote.Recorder(artifact_dir() / f"rec-{session_id}", get_settings().artifact_max_bytes * 5)
        except OSError as exc:
            log.warning("cannot record remote session %s: %s", session_id, exc)
    if room.agent is not None:
        await room.agent.send(json.dumps({"ch": "sys", "t": "end", "reason": "replaced"}))
    peer = remote.Peer(websocket, actor=f"device:{claims.get('dev')}")
    room.agent = peer
    room.agent_ready.set()
    announce = json.dumps({"ch": "sys", "t": "agent.connected"})
    for viewer in list(room.viewers):
        await viewer.send(announce)
    if room.viewers:
        await peer.send(json.dumps({"ch": "sys", "t": "viewer.joined", "by": room.viewers[0].actor, "viewOnly": room.view_only}))
    reason = "agent disconnected"
    try:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                break
            data = message.get("bytes") if message.get("bytes") is not None else message.get("text")
            if data is None:
                continue
            room.bytes_relayed += len(data)
            if room.recorder is not None:
                room.recorder.add(data)
            if isinstance(data, str) and _is_end(data):
                reason = "ended by device"
            for viewer in list(room.viewers):
                if remote.hub.viewer_revoked(viewer):  # the technician signed out or was signed out
                    room.viewers.remove(viewer)
                    await _close(viewer.websocket, 4401, "session ended")
                    continue
                if not await viewer.send(data):
                    room.viewers.remove(viewer)
    finally:
        if room.agent is peer and room.recorder is not None:
            # Save before any await: cleanup can be cancelled (server shutdown) and the recording must survive.
            recording, room.recorder = room.recorder.close(), None
            try:
                _db_call(_save_recording, session_id, *recording)
            except Exception as exc:  # noqa: BLE001 - never lose the relay cleanup over a recording
                log.warning("could not save recording for %s: %s", session_id, exc)
        if room.agent is peer:
            room.agent = None
            gone = json.dumps({"ch": "sys", "t": "agent.disconnected", "reason": reason})
            for viewer in list(room.viewers):
                await viewer.send(gone)
                await _close(viewer.websocket, 1000, reason)
            events, relayed = room.events, room.bytes_relayed
            room.events, room.bytes_relayed = [], 0
            remote.hub.drop(session_id)
            await run_in_threadpool(_db_call, _flush_room, session_id, events, relayed, reason, peer.actor)


def _save_recording(db: Session, session_id: str, size: int, sha256: str, records: int) -> None:
    """Keep a recording that captured something as a device artifact (same retention and access as bundles)."""
    from .artifacts import artifact_dir

    path = artifact_dir() / f"rec-{session_id}"
    session = db.get(RemoteSession, session_id)
    if session is None or records == 0:
        path.unlink(missing_ok=True)
        return
    device = db.get(Device, session.device_id)
    stamp = (session.connected_at or utcnow()).strftime("%Y%m%d-%H%M")
    db.add(DeviceArtifact(tenant_id=session.tenant_id, device_id=session.device_id, command_id=session.id, kind="remote.recording",
                          filename=f"{device.hostname if device else 'device'}-remote-{stamp}.fenrec", size=size, sha256=sha256,
                          storage_name=path.name))
    audit.record(db, "system:relay", "remote.recording.saved", session.id, session.tenant_id, size=size, technician=session.technician)


@sockets.websocket("/ws/remote/{session_id}/viewer")
async def viewer_socket(websocket: WebSocket, session_id: str, token: str | None = None):
    claims = remote.check_token(token, session_id, "remote-viewer")
    if claims is None:
        await _close(websocket, 4401, "invalid token")
        return
    actor = str(claims.get("act") or "technician")
    console_session = str(claims.get("ses") or "")
    if not console_session or remote.hub.viewer_revoked(remote.Peer(None, console_session=console_session)) \
            or not await run_in_threadpool(_db_call, _console_session_active, console_session):
        await _close(websocket, 4401, "session ended")
        return
    info = await run_in_threadpool(_db_call, _viewer_join, session_id, actor)
    if info is None:
        await _close(websocket, 4404, "session not available")
        return
    await websocket.accept()
    room = remote.hub.room(session_id, info["viewOnly"], info["allow"])
    peer = remote.Peer(websocket, actor=actor, console_session=console_session)
    room.viewers.append(peer)
    await peer.send(json.dumps({"ch": "sys", "t": "hello", "sessionId": session_id, "mode": info["mode"],
                                "agentConnected": room.agent is not None, "viewOnly": room.view_only,
                                "allowTerminal": room.allow.get("allowTerminal", True),
                                "allowFileTransfer": room.allow.get("allowFileTransfer", True),
                                "allowBlank": room.allow.get("blankScreen", False)}))
    if room.agent is not None:
        await room.agent.send(json.dumps({"ch": "sys", "t": "viewer.joined", "by": actor, "viewOnly": room.view_only}))
    ended_by_viewer = False
    try:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                break
            if message.get("bytes") is not None:
                # Binary from the viewer is only ever file-upload data.
                if remote.hub.viewer_revoked(peer):
                    await _close(websocket, 4401, "session ended")
                    break
                if not room.allow.get("allowFileTransfer", True) or room.agent is None:
                    continue
                room.bytes_relayed += len(message["bytes"])
                await room.agent.send(message["bytes"])
                continue
            if remote.hub.viewer_revoked(peer):
                await _close(websocket, 4401, "session ended")
                break
            text = message.get("text") or ""
            forward, audit_event = remote.hub.filter_viewer_message(room, text)
            if audit_event:
                room.events.append({**audit_event, "by": actor, "at": utcnow().isoformat()})
            if _is_end(text):
                ended_by_viewer = True
            if forward and room.agent is not None:
                room.bytes_relayed += len(text)
                await room.agent.send(text)
            if ended_by_viewer:
                break
    finally:
        if peer in room.viewers:
            room.viewers.remove(peer)
        if not room.viewers:
            if room.agent is not None:
                await room.agent.send(json.dumps({"ch": "sys", "t": "end", "reason": "viewer closed"}))
            events, relayed = room.events, room.bytes_relayed
            room.events, room.bytes_relayed = [], 0
            await run_in_threadpool(_db_call, _flush_room, session_id, events, relayed,
                                    "ended" if ended_by_viewer else "viewer closed", actor)


# --------------------------------------------------------------------------- agent wake channel


def _is_end(text: str) -> bool:
    """A small {"ch": "sys", "t": "end"} control message."""
    if len(text) > 512:
        return False
    try:
        message = json.loads(text)
    except json.JSONDecodeError:
        return False
    return isinstance(message, dict) and message.get("ch") == "sys" and message.get("t") == "end"


def _device_for_key(db: Session, device_id: str, api_key: str | None) -> bool:
    if not api_key:
        return False
    device = db.execute(select(Device).where(Device.api_key_hash == digest(api_key))).scalar_one_or_none()
    if device is None or device.id != device_id:
        return False
    device.last_seen_at = utcnow()
    return True


@sockets.websocket("/api/v1/devices/{device_id}/realtime")
async def device_realtime(websocket: WebSocket, device_id: str, key: str | None = None):
    """A long-lived socket agents hold so actions (remote sessions, scripts) start instantly instead of on the next poll."""
    api_key = websocket.headers.get("x-device-api-key") or key
    if not await run_in_threadpool(_db_call, _device_for_key, device_id, api_key):
        await _close(websocket, 4401, "unknown device")
        return
    await websocket.accept()
    peer = remote.Peer(websocket, actor=f"device:{device_id}")
    remote.hub.register_device(device_id, peer)
    await peer.send(json.dumps({"type": "hello", "pollNow": True}))
    try:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                break
            if (message.get("text") or "").strip() == "ping":
                await peer.send("pong")
    finally:
        remote.hub.unregister_device(device_id, peer)
