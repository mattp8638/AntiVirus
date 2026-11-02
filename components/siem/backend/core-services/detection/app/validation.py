"""Validation helpers for rule definitions."""
from __future__ import annotations

import string
from datetime import datetime, timezone

from fastapi import HTTPException, status

from .config import Settings
from .models import EventIngestRequest, RuleDefinition


def _extract_placeholders(template: str) -> set[str]:
    formatter = string.Formatter()
    return {field_name for _, field_name, _, _ in formatter.parse(template) if field_name}


def validate_rule_definition(rule: RuleDefinition, settings: Settings) -> None:
    """Validate rule configuration to ensure deterministic behaviour."""
    if rule.rule_type == "sequence":
        if not rule.sequence_event_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="sequence_requires_event_types",
            )
        if not rule.time_window_seconds:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="sequence_requires_time_window",
            )
    if rule.rule_type == "behavioural_deviation" and rule.deviation_multiplier is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="deviation_requires_multiplier",
        )
    if rule.rule_type == "cross_domain" and "patch_state" not in rule.required_context:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cross_domain_requires_patch_state",
        )

    placeholders = _extract_placeholders(rule.output.explanation_template)
    invalid = placeholders.difference(settings.allowed_explanation_variables)
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid_explanation_variables:{','.join(sorted(invalid))}",
        )


def validate_event_payload(payload: EventIngestRequest, settings: Settings) -> None:
    """Validate event payload integrity and context alignment."""
    event = payload.event
    if event.received_at.tzinfo is None or event.occurred_at.tzinfo is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="event_requires_timezone",
        )
    if event.received_at < event.occurred_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="received_before_occurred",
        )
    max_age = datetime.now(timezone.utc) - event.occurred_at
    if max_age.total_seconds() > settings.max_event_age_seconds:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="event_too_old",
        )
    if payload.context:
        if payload.context.asset.asset_id != event.asset_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="context_asset_mismatch",
            )
        if payload.context.identity.identity_id != event.identity_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="context_identity_mismatch",
            )
