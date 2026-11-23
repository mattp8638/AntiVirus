"""NAS gateway, server side (backup/crates/protocol/src/gateway.rs).

A backup agent inside a network serves a repository on a NAS or file server to chosen agents elsewhere. This server
tells the gateway what to serve and to whom (heartbeat), tells each client how to reach it (job specs), and relays
messages when a client cannot reach the gateway directly. Messages are encrypted and authenticated end to end
between the two agents: the relay moves bytes it can neither read nor forge.

The relay keeps requests in memory and needs the single-worker server process the image runs (uvicorn --workers 1).
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import BackupAgent, BackupRepoAccess, BackupRepository

DEFAULT_PORT = 8475
MAX_MESSAGE = (64 << 20) + 8192
REPLY_TIMEOUT = 120.0
POLL_TIMEOUT = 25.0
MAX_QUEUED_BYTES = 512 << 20


def gateway_config(db: Session, agent: BackupAgent) -> dict | None:
    """What `agent` serves, for its heartbeat (protocol GatewayConfig)."""
    repos = db.execute(select(BackupRepository).where(BackupRepository.gateway_agent_id == agent.id)).scalars().all()
    out = []
    for repo in repos:
        own = db.get(BackupRepoAccess, (repo.id, agent.id))
        if own is None:
            continue  # the gateway lost its own access: it cannot serve the repository
        clients = db.execute(select(BackupAgent).join(BackupRepoAccess, BackupRepoAccess.agent_id == BackupAgent.id).where(
            BackupRepoAccess.repository_id == repo.id, BackupRepoAccess.via_gateway.is_(True),
            BackupAgent.revoked.is_(False), BackupAgent.id != agent.id)).scalars().all()
        out.append({"repository_id": repo.id, "path": repo.path, "sealed_share": own.sealed_share,
                    "clients": [{"agent_id": c.id, "public_key": c.public_key} for c in clients]})
    if not out:
        return None
    return {"listen_port": agent.gateway_port or 0, "repositories": out}


def addresses(agent: BackupAgent) -> list[str]:
    """Where clients try the gateway directly: an address set in the console first, then what it reports."""
    found = []
    if agent.gateway_address:
        found.append(agent.gateway_address)
    if agent.gateway_port:
        found += [a for a in ((agent.inventory or {}).get("gateway_addresses") or []) if isinstance(a, str)]
    return list(dict.fromkeys(found))[:8]


def route(db: Session, repo: BackupRepository, access: BackupRepoAccess) -> dict | None:
    """How a client reaches `repo` (protocol GatewayRoute), when it goes through the gateway."""
    if not access.via_gateway or not repo.gateway_agent_id or access.agent_id == repo.gateway_agent_id:
        return None
    gw = db.get(BackupAgent, repo.gateway_agent_id)
    if gw is None or gw.revoked:
        return None
    return {"agent_id": gw.id, "public_key": gw.public_key, "addresses": addresses(gw), "relay": True}


def may_relay(db: Session, client: BackupAgent, gateway_id: str) -> bool:
    """Is `client` routed through `gateway_id` for at least one repository?"""
    return db.execute(select(BackupRepoAccess.repository_id).join(
        BackupRepository, BackupRepository.id == BackupRepoAccess.repository_id).where(
        BackupRepoAccess.agent_id == client.id, BackupRepoAccess.via_gateway.is_(True),
        BackupRepository.gateway_agent_id == gateway_id)).first() is not None


# --------------------------------------------------------------------------
# Relay
# --------------------------------------------------------------------------


@dataclass
class _Pending:
    gateway: str
    body: bytes
    reply: asyncio.Future


@dataclass
class Relay:
    queues: dict[str, asyncio.Queue] = field(default_factory=dict)
    pending: dict[str, _Pending] = field(default_factory=dict)
    queued_bytes: int = 0
    # (client, gateway) -> time the permission was checked; checked again after a minute.
    allowed: dict[tuple[str, str], float] = field(default_factory=dict)
    loop: object = None

    def _same_loop(self) -> None:
        """Queues belong to one event loop; start afresh if the server runs in a new one."""
        loop = asyncio.get_running_loop()
        if self.loop is not loop:
            self.queues, self.pending, self.queued_bytes, self.loop = {}, {}, 0, loop

    def queue(self, gateway: str) -> asyncio.Queue:
        self._same_loop()
        q = self.queues.get(gateway)
        if q is None:
            q = self.queues[gateway] = asyncio.Queue()
        return q

    async def forward(self, gateway: str, body: bytes) -> bytes | None:
        """Hand a client's message to the gateway and wait for the answer. None: no answer in time."""
        self._same_loop()
        if self.queued_bytes + len(body) > MAX_QUEUED_BYTES:
            raise OverflowError("relay busy")
        rid = uuid.uuid4().hex
        fut = asyncio.get_running_loop().create_future()
        self.pending[rid] = _Pending(gateway, body, fut)
        self.queued_bytes += len(body)
        await self.queue(gateway).put(rid)
        try:
            return await asyncio.wait_for(fut, REPLY_TIMEOUT)
        except asyncio.TimeoutError:
            return None
        finally:
            p = self.pending.pop(rid, None)
            if p is not None and p.body:
                self.queued_bytes -= len(p.body)

    async def next(self, gateway: str) -> tuple[str, bytes] | None:
        """The next message for `gateway` (long poll)."""
        self._same_loop()
        q = self.queue(gateway)
        deadline = time.monotonic() + POLL_TIMEOUT
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            try:
                rid = await asyncio.wait_for(q.get(), left)
            except asyncio.TimeoutError:
                return None
            p = self.pending.get(rid)
            if p is None or p.reply.done():
                continue  # the client gave up
            body, p.body = p.body, b""
            self.queued_bytes -= len(body)
            return rid, body

    def answer(self, gateway: str, rid: str, body: bytes) -> bool:
        self._same_loop()
        p = self.pending.get(rid)
        if p is None or p.gateway != gateway or p.reply.done():
            return False
        p.reply.set_result(body)
        return True


RELAY = Relay()
