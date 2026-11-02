"""Persistence for MVP-13 compliance automation."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Any, Dict, Optional

from .models import (
    AssessmentResult,
    AuditBundle,
    ControlDefinition,
    EvidenceRecord,
    ExceptionRecord,
    FrameworkMapping,
)


@dataclass
class ComplianceStore:
    """JSON-backed storage for compliance control data."""

    storage_path: str
    _lock: Lock = field(default_factory=Lock)
    _data: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._data = {
            "controls": {},
            "evidence": {},
            "assessments": {},
            "exceptions": {},
            "mappings": {},
            "bundles": {},
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

    def list_controls(self) -> list[dict]:
        return list(self._data["controls"].values())

    def get_control(self, control_id: str) -> Optional[dict]:
        return self._data["controls"].get(control_id)

    def record_control(self, control: ControlDefinition) -> None:
        self._data["controls"][control.control_id] = _serialise(control.model_dump())
        self._persist()

    def list_evidence(self, control_id: str) -> list[dict]:
        return list(self._data["evidence"].get(control_id, []))

    def record_evidence(self, record: EvidenceRecord) -> None:
        items = self._data["evidence"].setdefault(record.control_id, [])
        items.append(_serialise(record.model_dump()))
        self._persist()

    def trim_evidence(self, control_id: str, limit: int) -> None:
        items = self._data["evidence"].get(control_id, [])
        if len(items) > limit:
            self._data["evidence"][control_id] = items[-limit:]
            self._persist()

    def list_assessments(self, control_id: str) -> list[dict]:
        return list(self._data["assessments"].get(control_id, []))

    def record_assessment(self, assessment: AssessmentResult) -> None:
        items = self._data["assessments"].setdefault(assessment.control_id, [])
        items.append(_serialise(assessment.model_dump()))
        self._persist()

    def trim_assessments(self, control_id: str, limit: int) -> None:
        items = self._data["assessments"].get(control_id, [])
        if len(items) > limit:
            self._data["assessments"][control_id] = items[-limit:]
            self._persist()

    def list_exceptions(self, control_id: str) -> list[dict]:
        return list(self._data["exceptions"].get(control_id, []))

    def record_exception(self, record: ExceptionRecord) -> None:
        items = self._data["exceptions"].setdefault(record.control_id, [])
        items.append(_serialise(record.model_dump()))
        self._persist()

    def trim_exceptions(self, control_id: str, limit: int) -> None:
        items = self._data["exceptions"].get(control_id, [])
        if len(items) > limit:
            self._data["exceptions"][control_id] = items[-limit:]
            self._persist()

    def list_mappings(self, control_id: Optional[str] = None) -> list[dict]:
        if control_id:
            return list(self._data["mappings"].get(control_id, []))
        mappings: list[dict] = []
        for records in self._data["mappings"].values():
            mappings.extend(records)
        return mappings

    def record_mapping(self, mapping: FrameworkMapping) -> None:
        items = self._data["mappings"].setdefault(mapping.control_id, [])
        items.append(_serialise(mapping.model_dump()))
        self._persist()

    def record_bundle(self, bundle: AuditBundle) -> None:
        self._data["bundles"][str(bundle.bundle_id)] = _serialise(bundle.model_dump())
        self._persist()


def _serialise(payload: Any) -> Any:
    if isinstance(payload, datetime):
        return payload.isoformat()
    if isinstance(payload, dict):
        return {key: _serialise(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [_serialise(value) for value in payload]
    return payload


def build_store(storage_path: str) -> ComplianceStore:
    return ComplianceStore(storage_path=storage_path)
