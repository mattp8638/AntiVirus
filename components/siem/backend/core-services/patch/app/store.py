"""Persistence for patch management state."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from threading import Lock
from typing import Any, Dict, Optional
from uuid import UUID

from .models import (
    DetectionBatch,
    EvidenceRecord,
    ExecutionPlan,
    PatchPolicy,
)


@dataclass
class PatchStore:
    """Simple JSON-backed storage for patch management state."""

    storage_path: str
    _lock: Lock = field(default_factory=Lock)
    _data: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._data = {
            "detections": {},
            "policies": {},
            "plans": {},
            "evidence": {},
            "assets": {},
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

    def record_detection(self, batch: DetectionBatch) -> None:
        detection_id = str(batch.detection_id)
        if detection_id in self._data["detections"]:
            raise ValueError("detection_id_exists")
        self._data["detections"][detection_id] = _serialise(batch.model_dump())
        self._persist()

    def get_detection(self, detection_id: UUID) -> Optional[dict]:
        return self._data["detections"].get(str(detection_id))

    def record_policy(self, policy: PatchPolicy) -> None:
        policy_id = str(policy.policy_id)
        if policy_id in self._data["policies"]:
            raise ValueError("policy_id_exists")
        self._data["policies"][policy_id] = _serialise(policy.model_dump())
        self._persist()

    def get_policy(self, policy_id: UUID) -> Optional[dict]:
        return self._data["policies"].get(str(policy_id))

    def list_policies(self, tenant_id: str) -> list[dict]:
        return [
            policy
            for policy in self._data["policies"].values()
            if policy.get("tenant_id") == tenant_id
        ]

    def record_plan(self, plan: ExecutionPlan) -> None:
        plan_id = str(plan.plan_id)
        if plan_id in self._data["plans"]:
            raise ValueError("plan_id_exists")
        self._data["plans"][plan_id] = _serialise(plan.model_dump())
        self._persist()

    def update_plan(self, plan: ExecutionPlan) -> None:
        plan_id = str(plan.plan_id)
        if plan_id not in self._data["plans"]:
            raise ValueError("plan_not_found")
        self._data["plans"][plan_id] = _serialise(plan.model_dump())
        self._persist()

    def get_plan(self, plan_id: UUID) -> Optional[dict]:
        return self._data["plans"].get(str(plan_id))

    def record_evidence(self, record: EvidenceRecord) -> None:
        plan_id = str(record.plan_id)
        if plan_id in self._data["evidence"]:
            raise ValueError("evidence_exists")
        self._data["evidence"][plan_id] = _serialise(record.model_dump())
        self._persist()

    def get_evidence(self, plan_id: UUID) -> Optional[dict]:
        return self._data["evidence"].get(str(plan_id))

    def list_evidence_by_asset(self, asset_id: str) -> list[dict]:
        return [
            record
            for record in self._data["evidence"].values()
            if record.get("plan_snapshot", {}).get("asset_id") == asset_id
        ]

    def list_detections(self) -> list[dict]:
        return list(self._data["detections"].values())

    def record_asset_state(self, asset_id: str, payload: dict) -> None:
        self._data["assets"][asset_id] = _serialise(payload)
        self._persist()

    def get_asset_state(self, asset_id: str) -> Optional[dict]:
        return self._data["assets"].get(asset_id)


def _serialise(payload: Any) -> Any:
    if isinstance(payload, datetime):
        return payload.isoformat()
    if isinstance(payload, dict):
        return {key: _serialise(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [_serialise(value) for value in payload]
    return payload


def build_store(storage_path: str) -> PatchStore:
    return PatchStore(storage_path=storage_path)
