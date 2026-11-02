"""Persistence for PSA workflow state."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, Optional
from uuid import UUID

from .models import ActionRecord, EvidenceRecord, TicketRecord


@dataclass
class PsaStore:
    """Simple JSON-backed storage for PSA ticketing state."""

    storage_path: str
    _lock: Lock = field(default_factory=Lock)
    _data: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._data = {
            "tickets": {},
            "actions": {},
            "evidence": {},
        }
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.storage_path):
            return
        with self._lock:
            with open(self.storage_path, "r", encoding="utf-8") as handle:
                self._data.update(json.load(handle))

    def _persist(self) -> None:
        directory = os.path.dirname(self.storage_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with self._lock:
            with open(self.storage_path, "w", encoding="utf-8") as handle:
                json.dump(self._data, handle, indent=2, sort_keys=True)

    def list_tickets(self) -> list[dict]:
        return list(self._data["tickets"].values())

    def get_ticket(self, ticket_id: UUID) -> Optional[dict]:
        return self._data["tickets"].get(str(ticket_id))

    def find_ticket_by_source(
        self,
        tenant_id: str,
        asset_id: str,
        source_type: str,
        source_reference_id: str,
    ) -> Optional[dict]:
        for ticket in self._data["tickets"].values():
            if (
                ticket.get("tenant_id") == tenant_id
                and ticket.get("asset_id") == asset_id
                and ticket.get("source_type") == source_type
                and ticket.get("source_reference_id") == source_reference_id
            ):
                return ticket
        return None

    def record_ticket(self, ticket: TicketRecord) -> None:
        ticket_id = str(ticket.ticket_id)
        self._data["tickets"][ticket_id] = _serialise(ticket.model_dump())
        self._persist()

    def update_ticket(self, ticket: TicketRecord) -> None:
        ticket_id = str(ticket.ticket_id)
        if ticket_id not in self._data["tickets"]:
            raise ValueError("ticket_not_found")
        self._data["tickets"][ticket_id] = _serialise(ticket.model_dump())
        self._persist()

    def record_action(self, action: ActionRecord) -> None:
        ticket_id = str(action.ticket_id)
        actions = self._data["actions"].setdefault(ticket_id, [])
        actions.append(_serialise(action.model_dump()))
        self._persist()

    def list_actions(self, ticket_id: UUID) -> list[dict]:
        return list(self._data["actions"].get(str(ticket_id), []))

    def record_evidence(self, evidence: EvidenceRecord) -> None:
        ticket_id = str(evidence.ticket_id)
        evidence_list = self._data["evidence"].setdefault(ticket_id, [])
        evidence_list.append(_serialise(evidence.model_dump()))
        self._persist()

    def list_evidence(self, ticket_id: UUID) -> list[dict]:
        return list(self._data["evidence"].get(str(ticket_id), []))

    def list_evidence_hashes(self, ticket_id: UUID) -> set[str]:
        evidence = self._data["evidence"].get(str(ticket_id), [])
        return {record.get("hash_sha256") for record in evidence if record.get("hash_sha256")}

    def trim_actions(self, ticket_id: UUID, limit: int) -> None:
        ticket_key = str(ticket_id)
        actions = self._data["actions"].get(ticket_key, [])
        if len(actions) > limit:
            self._data["actions"][ticket_key] = actions[-limit:]
            self._persist()

    def trim_evidence(self, ticket_id: UUID, limit: int) -> None:
        ticket_key = str(ticket_id)
        evidence = self._data["evidence"].get(ticket_key, [])
        if len(evidence) > limit:
            self._data["evidence"][ticket_key] = evidence[-limit:]
            self._persist()


def _serialise(payload: Any) -> Any:
    if isinstance(payload, datetime):
        return payload.isoformat()
    if isinstance(payload, dict):
        return {key: _serialise(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [_serialise(value) for value in payload]
    return payload


def build_store(storage_path: str) -> PsaStore:
    return PsaStore(storage_path=storage_path)
