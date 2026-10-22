"""Persistence for MVP-12 penetration test orchestration."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Any, Dict, Optional
from uuid import UUID

from .models import EvidenceRecord, IntegrationDispatch, NormalisedResult, PenTestPlan


@dataclass
class PenTestStore:
    """JSON-backed storage for penetration testing data."""

    storage_path: str
    _lock: Lock = field(default_factory=Lock)
    _data: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._data = {
            "tests": {},
            "results": {},
            "evidence": {},
            "dispatches": {},
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

    def list_tests(self) -> list[dict]:
        return list(self._data["tests"].values())

    def get_test(self, test_id: UUID) -> Optional[dict]:
        return self._data["tests"].get(str(test_id))

    def record_test(self, plan: PenTestPlan) -> None:
        self._data["tests"][str(plan.test_id)] = _serialise(plan.model_dump())
        self._persist()

    def update_test(self, plan: PenTestPlan) -> None:
        test_id = str(plan.test_id)
        if test_id not in self._data["tests"]:
            raise ValueError("test_not_found")
        self._data["tests"][test_id] = _serialise(plan.model_dump())
        self._persist()

    def record_results(self, results: list[NormalisedResult]) -> None:
        if not results:
            return
        test_id = str(results[0].test_id)
        stored = self._data["results"].setdefault(test_id, [])
        stored.extend(_serialise(result.model_dump()) for result in results)
        self._persist()

    def list_results(self, test_id: UUID) -> list[dict]:
        return list(self._data["results"].get(str(test_id), []))

    def record_evidence(self, evidence: EvidenceRecord) -> None:
        test_id = str(evidence.test_id)
        stored = self._data["evidence"].setdefault(test_id, [])
        stored.append(_serialise(evidence.model_dump()))
        self._persist()

    def list_evidence(self, test_id: UUID) -> list[dict]:
        return list(self._data["evidence"].get(str(test_id), []))

    def trim_evidence(self, test_id: UUID, limit: int) -> None:
        test_key = str(test_id)
        evidence = self._data["evidence"].get(test_key, [])
        if len(evidence) > limit:
            self._data["evidence"][test_key] = evidence[-limit:]
            self._persist()

    def record_dispatches(self, dispatches: list[IntegrationDispatch]) -> None:
        if not dispatches:
            return
        test_id = str(dispatches[0].test_id)
        stored = self._data["dispatches"].setdefault(test_id, [])
        stored.extend(_serialise(dispatch.model_dump()) for dispatch in dispatches)
        self._persist()

    def list_dispatches(self, test_id: UUID) -> list[dict]:
        return list(self._data["dispatches"].get(str(test_id), []))


def _serialise(payload: Any) -> Any:
    if isinstance(payload, datetime):
        return payload.isoformat()
    if isinstance(payload, dict):
        return {key: _serialise(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [_serialise(value) for value in payload]
    return payload


def build_store(storage_path: str) -> PenTestStore:
    return PenTestStore(storage_path=storage_path)
