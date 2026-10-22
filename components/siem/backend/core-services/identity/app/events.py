"""In-memory event registry for agent heartbeats.

This provides a temporary storage for MVP-2 visibility. Replace with database
persistence in later phases.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List


@dataclass
class HeartbeatEvent:
    event_id: str
    agent_id: str
    hostname: str
    os: str
    uptime_seconds: int
    trust_state: str
    received_at: datetime


class HeartbeatStore:
    def __init__(self) -> None:
        self._events: Dict[str, HeartbeatEvent] = {}

    def record(self, event: HeartbeatEvent) -> None:
        self._events[event.event_id] = event

    def list_recent(self, limit: int = 100) -> List[HeartbeatEvent]:
        return list(self._events.values())[-limit:]


store = HeartbeatStore()
