"""Online/offline status evaluation for MVP-2."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List

from .agents import AgentState


@dataclass
class AgentPresence:
    identity_id: str
    hostname: str
    os: str
    trust_state: str
    last_seen_at: datetime
    status: str


def evaluate_presence(agents: List[AgentState], threshold_seconds: int) -> List[AgentPresence]:
    threshold = timedelta(seconds=threshold_seconds)
    now = datetime.now(timezone.utc)
    presence: List[AgentPresence] = []
    for agent in agents:
        status = "online" if now - agent.last_seen_at <= threshold else "offline"
        presence.append(
            AgentPresence(
                identity_id=agent.identity_id,
                hostname=agent.hostname,
                os=agent.os,
                trust_state=agent.trust_state,
                last_seen_at=agent.last_seen_at,
                status=status,
            )
        )
    return presence
