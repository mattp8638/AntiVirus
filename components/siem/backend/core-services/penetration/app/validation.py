"""Validation helpers for MVP-12 test plans and execution."""
from __future__ import annotations

from datetime import datetime
from typing import Iterable


from .models import DetectionResponseSummary, Observation, PenTestPlan, PenTestCreateRequest, ResultIngestRequest, Safeguards


class ValidationError(ValueError):
    """Raised when validation fails."""


def _unique(values: Iterable[str]) -> bool:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            return False
        seen.add(value)
    return True


def validate_plan_request(request: PenTestCreateRequest, settings: Settings) -> None:
    """Validate incoming test plan details."""
    if request.schedule.end_at <= request.schedule.start_at:
        raise ValidationError("invalid_schedule_window")
    if not request.scope.assets and not request.scope.networks:
        raise ValidationError("scope_empty")
    if request.scope.exclusions and not _unique(request.scope.exclusions):
        raise ValidationError("duplicate_exclusions")
    if request.credentials and not _unique([cred.credential_ref for cred in request.credentials]):
        raise ValidationError("duplicate_credentials")
    safeguards = request.safeguards
    if safeguards:
        if not safeguards.target_allow_list:
            raise ValidationError("allow_list_required")
        if safeguards.rate_limit_per_minute <= 0:
            raise ValidationError("rate_limit_invalid")
        allow_list = set(safeguards.target_allow_list)
        scope_targets = set(request.scope.assets + request.scope.networks)
        if scope_targets and not scope_targets.issubset(allow_list):
            raise ValidationError("scope_not_in_allow_list")
    if request.authorisation.authorised_by != request.requested_by:
        raise ValidationError("authorisation_mismatch")


def validate_plan_start(plan: PenTestPlan, now: datetime) -> None:
    """Validate that a plan can be started."""
    if plan.status not in {"planned", "scheduled"}:
        raise ValidationError("invalid_state")
    if now < plan.schedule.start_at or now > plan.schedule.end_at:
        raise ValidationError("outside_execution_window")
    if plan.scope.decommissioned_assets:
        decommissioned = set(plan.scope.decommissioned_assets)
        if any(asset in decommissioned for asset in plan.scope.assets):
            raise ValidationError("decommissioned_assets_in_scope")


def validate_results_request(
    request: ResultIngestRequest,
    settings: Settings,
) -> None:
    """Validate result ingestion payloads."""
    if not request.operator_identity:
        raise ValidationError("operator_identity_required")
    if len(request.observations) > settings.max_observations_per_request:
        raise ValidationError("observation_limit_exceeded")


def should_abort_for_credentials(observations: list[Observation]) -> bool:
    """Return True when revoked credentials are detected mid-test."""
    return any(observation.credential_state == "revoked" for observation in observations)


def should_abort_for_detection(
    detection_summary: DetectionResponseSummary,
    safeguards: Safeguards,
) -> bool:
    """Return True when detection failures require immediate aborts."""
    return detection_summary.detection_system_status == "failed" and safeguards.abort_on_detection_failure
