"""In-memory agent state registry for MVP-2."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List


@dataclass
class AgentState:
    identity_id: str
    hostname: str
    os: str
    last_seen_at: datetime
    trust_state: str


class AgentStore:
    def __init__(self) -> None:
        self._agents: Dict[str, AgentState] = {}

    def upsert(self, identity_id: str, hostname: str, os_name: str, trust_state: str) -> None:
        self._agents[identity_id] = AgentState(
            identity_id=identity_id,
            hostname=hostname,
            os=os_name,
            last_seen_at=datetime.now(timezone.utc),
            trust_state=trust_state,
        )

    def list_all(self) -> List[AgentState]:
        return list(self._agents.values())


store = AgentStore()
