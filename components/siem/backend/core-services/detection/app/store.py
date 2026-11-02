"""In-memory stores for events, rules, findings, and suppressions."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from .models import (
    DismissalDecision,
    EventIngestRequest,
    Finding,
    FindingState,
    NormalisedEvent,
    RuleDefinition,
    SuppressionDecision,
)


@dataclass
class EventRecord:
    event: NormalisedEvent
    context: Optional[EventIngestRequest] = None


class EventStore:
    """FIFO store for normalised events."""

    def __init__(self, retention: int) -> None:
        self._events: deque[NormalisedEvent] = deque(maxlen=retention)

    def add(self, event: NormalisedEvent) -> None:
        self._events.append(event)

    def list_recent(self) -> list[NormalisedEvent]:
        return list(self._events)


class RuleStore:
    """Registry for detection rules."""

    def __init__(self) -> None:
        self._rules: dict[str, RuleDefinition] = {}

    def add(self, rule: RuleDefinition) -> None:
        self._rules[rule.rule_id] = rule

    def list(self) -> list[RuleDefinition]:
        return list(self._rules.values())

    def get(self, rule_id: str) -> Optional[RuleDefinition]:
        return self._rules.get(rule_id)


class FindingStore:
    """Store for immutable findings with lifecycle state."""

    def __init__(self, retention: int) -> None:
        self._findings: deque[Finding] = deque(maxlen=retention)

    def add(self, finding: Finding) -> None:
        self._findings.appendleft(finding)

    def list(self) -> list[Finding]:
        return list(self._findings)

    def get(self, finding_id: UUID) -> Optional[Finding]:
        for finding in self._findings:
            if finding.finding_id == finding_id:
                return finding
        return None

    def supersede(self, finding_id: UUID, superseded_by: UUID) -> Optional[Finding]:
        for index, finding in enumerate(self._findings):
            if finding.finding_id == finding_id:
                updated = finding.model_copy(update={
                    "state": "superseded",
                    "superseded_by": superseded_by,
                })
                self._findings[index] = updated
                return updated
        return None

    def dismiss(self, finding_id: UUID) -> Optional[Finding]:
        for index, finding in enumerate(self._findings):
            if finding.finding_id == finding_id:
                updated = finding.model_copy(update={"state": "dismissed"})
                self._findings[index] = updated
                return updated
        return None

    def find_open_by_key(self, rule_id: str, asset_id: str, identity_id: str) -> Optional[Finding]:
        for finding in self._findings:
            if (
                finding.state == "open"
                and finding.finding_type == rule_id
                and finding.context_snapshot.asset.asset_id == asset_id
                and finding.context_snapshot.identity.identity_id == identity_id
            ):
                return finding
        return None


class SuppressionStore:
    """Store for suppression decisions and duplicate detection."""

    def __init__(self) -> None:
        self._decisions: list[SuppressionDecision] = []

    def record(self, rule_id: str, event_id: str, asset_id: str, identity_id: str, reason: str) -> SuppressionDecision:
        decision = SuppressionDecision(
            decision_id=uuid4(),
            rule_id=rule_id,
            event_id=event_id,
            asset_id=asset_id,
            identity_id=identity_id,
            reason=reason,
            suppressed_at=datetime.now(timezone.utc),
        )
        self._decisions.append(decision)
        return decision

    def list(self) -> list[SuppressionDecision]:
        return list(self._decisions)


class DismissalStore:
    """Store for dismissal decisions and reasons."""

    def __init__(self) -> None:
        self._decisions: list[DismissalDecision] = []

    def record(self, finding_id: UUID, identity_id: str, reason: str, dismissed_at: datetime) -> DismissalDecision:
        decision = DismissalDecision(
            dismissal_id=uuid4(),
            finding_id=finding_id,
            identity_id=identity_id,
            reason=reason,
            dismissed_at=dismissed_at,
        )
        self._decisions.append(decision)
        return decision

    def list(self) -> list[DismissalDecision]:
        return list(self._decisions)


@dataclass
class Stores:
    events: EventStore
    rules: RuleStore
    findings: FindingStore
    suppressions: SuppressionStore
    dismissals: DismissalStore


store: Stores | None = None


def init_stores(event_retention: int, finding_retention: int) -> Stores:
    """Initialise singleton stores for the service."""
    global store
    store = Stores(
        events=EventStore(retention=event_retention),
        rules=RuleStore(),
        findings=FindingStore(retention=finding_retention),
        suppressions=SuppressionStore(),
        dismissals=DismissalStore(),
    )
    return store
