"""Validation and normalisation helpers for MVP-7 event ingestion."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Iterable

from .models import EventBatch, EventEnvelope, EventPayloadValue


ALLOWED_EVENT_CATEGORIES = {
    "system",
    "security",
    "process",
    "file",
    "network",
}


class EventValidationError(ValueError):
    """Raised when event payload validation fails."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _is_json_value(value: EventPayloadValue) -> bool:
    if value is None:
        return True
    if isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, list):
        return all(_is_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _is_json_value(inner)
            for key, inner in value.items()
        )
    return False


def validate_event_payload(event: EventEnvelope) -> None:
    if event.event_category not in ALLOWED_EVENT_CATEGORIES:
        raise EventValidationError("unsupported_event_category")
    if not event.payload:
        raise EventValidationError("payload_required")
    if not _is_json_value(event.payload):
        raise EventValidationError("payload_not_json")


def validate_batch(batch: EventBatch, event_limit: int) -> None:
    if batch.schema_version != "v1":
        raise EventValidationError("schema_version_unsupported")
    if not batch.events:
        raise EventValidationError("events_required")
    if len(batch.events) > event_limit:
        raise EventValidationError("event_batch_too_large")
    for event in batch.events:
        validate_event_payload(event)


def canonical_payload_hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_payload_hash(event: EventEnvelope) -> None:
    computed = canonical_payload_hash(event.payload)
    if computed != event.payload_hash:
        raise EventValidationError("payload_hash_mismatch")


def ensure_timestamp_bounds(
    event: EventEnvelope,
    now: datetime,
    stale_seconds: int,
    future_seconds: int,
) -> None:
    event_time = event.timestamp_local
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    oldest_allowed = now - timedelta(seconds=stale_seconds)
    newest_allowed = now + timedelta(seconds=future_seconds)
    if event_time < oldest_allowed:
        raise EventValidationError("event_stale")
    if event_time > newest_allowed:
        raise EventValidationError("event_in_future")


def detect_clock_drift(
    event: EventEnvelope,
    received_at: datetime,
    drift_threshold: int,
) -> int | None:
    drift = int(abs((received_at - event.timestamp_local).total_seconds()))
    if drift > drift_threshold:
        return drift
    return None


def iter_events(batch: EventBatch) -> Iterable[EventEnvelope]:
    return batch.events
