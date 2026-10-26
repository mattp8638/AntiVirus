"""Remote access broker: session lifecycle, short-lived tokens and the WebSocket relay.

How a session works:

1. A technician presses Connect. The cloud creates a ``RemoteSession`` and
   queues ``remote.session.start`` for the device with a one-time agent token
   and the relay URL. Devices holding a realtime channel are woken instantly.
2. The agent (or its desktop helper on Windows) dials
   ``/ws/remote/<id>/agent``. The pop-out viewer dials ``/ws/remote/<id>/viewer``.
3. The relay pairs them and forwards frames both ways. It never decodes
   screen data. It does read the small JSON control messages so it can
   enforce view-only and policy (terminal, file transfer) and keep an audit
   trail of what the technician did.

The relay keeps state in process memory, so one cloud instance owns a session.
Scale-out deployments route ``/ws/remote/<id>`` by session id (sticky).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import event, select
from sqlalchemy.orm import Session

from . import audit
from .config import get_settings
from .models import Command, Device, RemoteSession, utcnow
from .security import issue_token, read_token

log = logging.getLogger("fenrir.remote")

AGENT_CONNECT_MINUTES = 10
VIEWER_TOKEN_MINUTES = 15
MAX_SESSION_HOURS = 12
INPUT_TYPES = {"mm", "md", "mu", "wh", "kd", "ku", "type", "cad", "clip.set", "blank", "lock"}
CHANNEL_POLICY = {"term": "allowTerminal", "files": "allowFileTransfer"}
AUDITED = {("files", "get"), ("files", "put"), ("files", "delete"), ("files", "mkdir"), ("input", "cad"), ("term", "open"),
           ("sys", "blank"), ("input", "lock"), ("sys", "reboot")}


# --------------------------------------------------------------------------- tokens


def agent_token(session: RemoteSession) -> str:
    return issue_token(get_settings().secret_key, session.id, AGENT_CONNECT_MINUTES, aud="remote-agent", dev=session.device_id)


def viewer_token(session: RemoteSession, actor: str) -> str:
    return issue_token(get_settings().secret_key, session.id, VIEWER_TOKEN_MINUTES, aud="remote-viewer", act=actor)


def check_token(token: str | None, session_id: str, audience: str) -> dict | None:
    if not token:
        return None
    payload = read_token(get_settings().secret_key, token)
    if not payload or payload.get("sub") != session_id or payload.get("aud") != audience:
        return None
    return payload


def relay_url(session: RemoteSession, role: str = "agent") -> str:
    base = get_settings().public_base_url.rstrip("/")
    ws_base = "wss://" + base[len("https://"):] if base.startswith("https://") else "ws://" + base.removeprefix("http://")
    return f"{ws_base}/ws/remote/{session.id}/{role}"


# --------------------------------------------------------------------------- session lifecycle


def remote_policy(db: Session, device: Device) -> dict:
    from . import services

    resolution, _ = services.effective_policy(db, device)
    return resolution["settings"].get("remoteAccess", {})


def start_session(db: Session, device: Device, technician: str, mode: str = "desktop", view_only: bool = False,
                  ticket_id: str | None = None, reason: str = "") -> RemoteSession:
    from . import services

    policy = remote_policy(db, device)
    if not policy.get("enabled", True):
        raise PermissionError("Remote access is turned off by this device's policy")
    if mode == "terminal" and not policy.get("allowTerminal", True):
        raise PermissionError("Remote terminal is turned off by this device's policy")
    if mode == "files" and not policy.get("allowFileTransfer", True):
        raise PermissionError("File transfer is turned off by this device's policy")
    view_only = view_only or not policy.get("allowControl", True)
    now = utcnow()
    session = RemoteSession(tenant_id=device.tenant_id, device_id=device.id, technician=technician, mode=mode, view_only=view_only,
                            ticket_id=ticket_id, reason=reason, created_at=now, expires_at=now + timedelta(hours=MAX_SESSION_HOURS),
                            consent="pending" if policy.get("consent", "when_user_present") != "never" else "not_required",
                            events=[{"at": now.isoformat(), "by": technician, "type": "requested", "mode": mode}])
    db.add(session)
    db.flush()
    payload = {
        "sessionId": session.id, "relayUrl": relay_url(session), "token": agent_token(session), "mode": mode,
        "viewOnly": view_only, "technician": technician,
        "consent": policy.get("consent", "when_user_present"),
        "consentTimeoutSeconds": policy.get("consentTimeoutSeconds", 30),
        "onConsentTimeout": policy.get("onConsentTimeout", "deny"),
        "allowTerminal": policy.get("allowTerminal", True), "allowFileTransfer": policy.get("allowFileTransfer", True),
        "showBanner": policy.get("showBanner", True), "maxFps": policy.get("maxFps", 15),
        "quality": policy.get("defaultQuality", 70), "idleTimeoutMinutes": policy.get("idleTimeoutMinutes", 30),
    }
    command = services.enqueue_command(db, device, "remote.session.start", technician, payload=payload,
                                       reason=reason or f"Remote {mode} session")
    db.flush()
    session.command_id = command.id
    audit.record(db, technician, "remote.session.requested", f"{device.hostname}:{mode}", device.tenant_id, session=session.id)
    return session


def end_session(db: Session, session: RemoteSession, by: str, reason: str = "ended") -> None:
    if session.status in {"ended", "failed", "denied"}:
        return
    from . import services

    now = utcnow()
    session.status = "ended"
    session.ended_at = now
    session.events = (session.events or []) + [{"at": now.isoformat(), "by": by, "type": "ended", "reason": reason}]
    device = db.get(Device, session.device_id)
    if device is not None:
        try:
            services.enqueue_command(db, device, "remote.session.end", by, payload={"sessionId": session.id},
                                     reason="Close remote session")
        except services.CommandError:
            pass
    # Drop the start command if the agent never picked it up.
    if session.command_id:
        command = db.get(Command, session.command_id)
        if command is not None and command.status == "pending":
            command.status, command.updated_at = "cancelled", now
    audit.record(db, by, "remote.session.ended", session.id, session.tenant_id, reason=reason,
                 minutes=round(((now - (session.connected_at or now)).total_seconds()) / 60, 1))


def on_command_complete(db: Session, device: Device, command: Command) -> None:
    session_id = (command.payload or {}).get("sessionId")
    session = db.get(RemoteSession, session_id) if session_id else None
    if session is None or command.type != "remote.session.start":
        return
    result = command.result or {}
    if command.status == "failed":
        denied = "denied" in str(result.get("error", "")).lower() or result.get("consent") == "denied"
        session.status = "denied" if denied else "failed"
        session.consent = "denied" if denied else session.consent
        session.ended_at = utcnow()
        session.events = (session.events or []) + [{"at": utcnow().isoformat(), "by": f"device:{device.hostname}",
                                                    "type": session.status, "detail": str(result.get("error", ""))[:600]}]
    elif result.get("consent") in {"granted", "not_required"}:
        session.consent = result["consent"]


def expire_sessions(db: Session) -> int:
    now = utcnow()
    count = 0
    for session in db.execute(select(RemoteSession).where(RemoteSession.status.in_(("waiting", "connected")))).scalars():
        stale_wait = session.status == "waiting" and now - session.created_at > timedelta(minutes=AGENT_CONNECT_MINUTES + 5)
        if stale_wait or (session.expires_at and now > session.expires_at):
            end_session(db, session, "system", "expired")
            count += 1
    return count


# --------------------------------------------------------------------------- relay hub


@dataclass(eq=False)
class Peer:
    websocket: object
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    actor: str = ""

    async def send(self, message: str | bytes) -> bool:
        async with self.lock:
            try:
                if isinstance(message, bytes):
                    await self.websocket.send_bytes(message)
                else:
                    await self.websocket.send_text(message)
                return True
            except Exception:  # noqa: BLE001 - peer went away
                return False


class Recorder:
    """Writes a session's screen tiles and terminal output to a playback file.

    Format: b"FENREC1\n", then records of [uint32 ms since start][uint8 kind][uint32 length][payload]
    (kind 1 = binary screen tile as relayed, kind 0 = JSON text message from the screen or terminal channel).
    Viewer input is never recorded.
    """

    MAGIC = b"FENREC1\n"

    def __init__(self, path, limit: int) -> None:
        import hashlib
        import time

        self.path, self.limit = path, limit
        self.file = open(path, "wb")
        self.digest = hashlib.sha256()
        self.started = time.monotonic()
        self.size = 0
        self.records = 0
        self._write(self.MAGIC)

    def _write(self, data: bytes) -> None:
        self.file.write(data)
        self.digest.update(data)
        self.size += len(data)

    def add(self, data: str | bytes) -> None:
        import struct
        import time

        if self.file is None or self.size >= self.limit:
            return
        if isinstance(data, bytes):
            if not data or data[0] != 0x01:  # screen tiles only (file transfers are not recorded)
                return
            kind, payload = 1, data
        else:
            if '"ch":"screen"' not in data and '"ch":"term"' not in data:
                return
            kind, payload = 0, data.encode()
        elapsed = int((time.monotonic() - self.started) * 1000)
        self._write(struct.pack(">IBI", elapsed, kind, len(payload)) + payload)
        self.records += 1

    def close(self) -> tuple[int, str, int]:
        if self.file is not None:
            self.file.close()
            self.file = None
        return self.size, self.digest.hexdigest(), self.records


@dataclass
class Room:
    session_id: str
    view_only: bool
    allow: dict
    agent: Peer | None = None
    viewers: list[Peer] = field(default_factory=list)
    bytes_relayed: int = 0
    events: list[dict] = field(default_factory=list)
    agent_ready: asyncio.Event = field(default_factory=asyncio.Event)
    recorder: "Recorder | None" = None


class RelayHub:
    def __init__(self) -> None:
        self.rooms: dict[str, Room] = {}
        self.devices: dict[str, set[Peer]] = {}
        self.loop: asyncio.AbstractEventLoop | None = None

    # -- device wake channel ------------------------------------------------
    def register_device(self, device_id: str, peer: Peer) -> None:
        self.loop = asyncio.get_running_loop()
        self.devices.setdefault(device_id, set()).add(peer)

    def unregister_device(self, device_id: str, peer: Peer) -> None:
        peers = self.devices.get(device_id)
        if peers:
            peers.discard(peer)
            if not peers:
                self.devices.pop(device_id, None)

    def device_online(self, device_id: str) -> bool:
        return bool(self.devices.get(device_id))

    def wake(self, device_ids: set[str]) -> None:
        """Tell connected agents to poll for commands now. Safe to call from any thread."""
        loop = self.loop
        if loop is None or loop.is_closed():
            return
        targets = [peer for device_id in device_ids for peer in self.devices.get(device_id, ())]
        if not targets:
            return
        message = json.dumps({"type": "commands"})
        for peer in targets:
            asyncio.run_coroutine_threadsafe(peer.send(message), loop)

    # -- session rooms --------------------------------------------------------
    def room(self, session_id: str, view_only: bool, allow: dict) -> Room:
        self.loop = asyncio.get_running_loop()
        room = self.rooms.get(session_id)
        if room is None:
            room = Room(session_id=session_id, view_only=view_only, allow=allow)
            self.rooms[session_id] = room
        return room

    def drop(self, session_id: str) -> None:
        self.rooms.pop(session_id, None)

    def filter_viewer_message(self, room: Room, text: str) -> tuple[bool, dict | None]:
        """Decide whether a viewer control message may reach the agent. Returns (forward, audit_event)."""
        try:
            message = json.loads(text)
        except json.JSONDecodeError:
            return False, None
        channel, kind = message.get("ch"), message.get("t")
        if channel == "input" and kind in INPUT_TYPES and room.view_only:
            return False, None
        if channel in CHANNEL_POLICY and not room.allow.get(CHANNEL_POLICY[channel], True):
            return False, None
        audit_event = None
        if (channel, kind) in AUDITED:
            audit_event = {"type": f"{channel}.{kind}", "path": str(message.get("path", ""))[:300]}
        return True, audit_event


hub = RelayHub()


def _wake_after_commit(session: Session) -> None:
    devices = session.info.pop("wake_devices", None)
    if devices:
        hub.wake(set(devices))


def install_wake_hook() -> None:
    """Wake devices once the transaction that queued their commands has committed."""
    if not event.contains(Session, "after_commit", _wake_after_commit):
        event.listen(Session, "after_commit", _wake_after_commit)
