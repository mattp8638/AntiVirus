"""Rule evaluation engine for MVP-8."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable
from uuid import uuid4

from .config import Settings
from .correlation import build_correlation_graph
from .explain import render_explanation
from .models import ContextSnapshot, Finding, NormalisedEvent, RuleDefinition
from .risk import boost_severity, compute_confidence
from .store import Stores


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _within_window(event_time: datetime, window_seconds: int) -> bool:
    return event_time >= _now() - timedelta(seconds=window_seconds)


def _event_matches(rule: RuleDefinition, event: NormalisedEvent) -> bool:
    if rule.trigger_event_types and event.event_type not in rule.trigger_event_types:
        return False
    return True


def _context_satisfies(rule: RuleDefinition, context: ContextSnapshot | None) -> bool:
    if not rule.required_context:
        return True
    if context is None:
        return False
    required_map = {
        "asset": context.asset,
        "identity": context.identity,
        "baseline": context.baseline,
        "patch_state": context.patch_state,
    }
    for key in rule.required_context:
        if required_map.get(key) is None:
            return False
    return True


def _sequence_matches(
    rule: RuleDefinition,
    event: NormalisedEvent,
    events: Iterable[NormalisedEvent],
    window_seconds: int,
) -> list[NormalisedEvent]:
    if not rule.sequence_event_types:
        return []
    if event.event_type != rule.sequence_event_types[-1]:
        return []
    sequence_events = [event]
    window_start = event.occurred_at - timedelta(seconds=window_seconds)
    prior_events = [
        candidate
        for candidate in events
        if candidate.occurred_at >= window_start
        and candidate.occurred_at <= event.occurred_at
        and candidate.asset_id == event.asset_id
        and candidate.identity_id == event.identity_id
    ]
    for expected_event_type in rule.sequence_event_types[:-1]:
        matching = [candidate for candidate in prior_events if candidate.event_type == expected_event_type]
        if not matching:
            return []
        sequence_events.extend(matching[:1])
    return sequence_events


def _behavioural_deviation_matches(rule: RuleDefinition, event: NormalisedEvent, context: ContextSnapshot) -> bool:
    if context.baseline is None or rule.deviation_multiplier is None:
        return False
    metric_value = event.attributes.get("metric_value")
    if metric_value is None:
        return False
    try:
        metric_value_float = float(metric_value)
    except (TypeError, ValueError):
        return False
    return metric_value_float >= context.baseline.baseline_value * rule.deviation_multiplier


def _cross_domain_matches(rule: RuleDefinition, event: NormalisedEvent, context: ContextSnapshot) -> bool:
    if context.patch_state is None:
        return False
    if not context.patch_state.missing_patches:
        return False
    return True


def _suppression_window_elapsed(
    event: NormalisedEvent,
    existing: Finding | None,
    window_seconds: int,
) -> bool:
    if existing is None:
        return True
    return event.occurred_at >= existing.creation_timestamp + timedelta(seconds=window_seconds)


def evaluate_event(
    event: NormalisedEvent,
    context: ContextSnapshot | None,
    settings: Settings,
    stores: Stores,
) -> list[Finding]:
    """Evaluate an event against all active rules and return findings."""
    findings: list[Finding] = []
    if event.occurred_at.tzinfo is None:
        return findings
    if not _within_window(event.occurred_at, settings.max_event_age_seconds):
        return findings

    for rule in stores.rules.list():
        if not rule.enabled:
            continue
        if not _event_matches(rule, event):
            continue
        if not _context_satisfies(rule, context):
            if not settings.allow_findings_without_context:
                continue

        time_window = rule.time_window_seconds or settings.correlation_time_window_seconds
        supporting_events = [event]

        if rule.rule_type == "sequence":
            supporting_events = _sequence_matches(rule, event, stores.events.list_recent(), time_window)
            if not supporting_events:
                continue
        if rule.rule_type == "behavioural_deviation":
            if context is None or not _behavioural_deviation_matches(rule, event, context):
                continue
        if rule.rule_type == "cross_domain":
            if context is None or not _cross_domain_matches(rule, event, context):
                continue

        if context is None:
            continue

        if context.maintenance_window:
            stores.suppressions.record(
                rule_id=rule.rule_id,
                event_id=event.event_id,
                asset_id=event.asset_id,
                identity_id=event.identity_id,
                reason="maintenance_window",
            )
            continue

        if event.asset_id in rule.suppression.allowlist_assets:
            stores.suppressions.record(
                rule_id=rule.rule_id,
                event_id=event.event_id,
                asset_id=event.asset_id,
                identity_id=event.identity_id,
                reason="asset_allowlist",
            )
            continue
        if event.identity_id in rule.suppression.allowlist_identities:
            stores.suppressions.record(
                rule_id=rule.rule_id,
                event_id=event.event_id,
                asset_id=event.asset_id,
                identity_id=event.identity_id,
                reason="identity_allowlist",
            )
            continue
        if event.event_type in rule.suppression.allowlist_event_types:
            stores.suppressions.record(
                rule_id=rule.rule_id,
                event_id=event.event_id,
                asset_id=event.asset_id,
                identity_id=event.identity_id,
                reason="event_type_allowlist",
            )
            continue

        duplicate = stores.findings.find_open_by_key(rule.rule_id, event.asset_id, event.identity_id)
        if duplicate and not _suppression_window_elapsed(event, duplicate, rule.suppression.dedupe_window_seconds):
            stores.suppressions.record(
                rule_id=rule.rule_id,
                event_id=event.event_id,
                asset_id=event.asset_id,
                identity_id=event.identity_id,
                reason="duplicate_open_finding",
            )
            continue
        new_finding_id = uuid4()
        if duplicate:
            stores.findings.supersede(duplicate.finding_id, new_finding_id)

        explanation = render_explanation(rule, event, context, settings, time_window)
        confidence_score = compute_confidence(rule.output.confidence_base, context)
        severity = boost_severity(rule.output.severity, context)
        correlation_graph = build_correlation_graph(event)
        finding = Finding(
            finding_id=new_finding_id,
            finding_type=rule.rule_id,
            severity=severity,
            confidence_score=confidence_score,
            supporting_events=[event.event_id for event in supporting_events][: settings.max_supporting_events],
            correlation_graph=correlation_graph,
            context_snapshot=context,
            explanation_text=explanation,
            creation_timestamp=_now(),
        )
        stores.findings.add(finding)
        findings.append(finding)
        if len(findings) >= settings.max_findings_per_request:
            break

    return findings
