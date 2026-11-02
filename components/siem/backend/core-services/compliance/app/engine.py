"""Assessment logic for MVP-13 compliance controls."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from .models import (
    AssessmentResult,
    AssessmentStatus,
    ControlDefinition,
    EvidenceRecord,
    ExceptionRecord,
)


def _normalise_numeric(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _apply_operator(left: float, operator: str, right: float) -> bool:
    if operator == ">=":
        return left >= right
    if operator == "<=":
        return left <= right
    if operator == "==":
        return left == right
    if operator == "!=":
        return left != right
    if operator == ">":
        return left > right
    if operator == "<":
        return left < right
    return False


def _active_exceptions(
    exceptions: Iterable[ExceptionRecord],
    now: datetime,
) -> list[ExceptionRecord]:
    return [exception for exception in exceptions if exception.expires_at > now]


def evaluate_control(
    control: ControlDefinition,
    evidence: list[EvidenceRecord],
    exceptions: list[ExceptionRecord],
    now: datetime | None = None,
) -> AssessmentResult:
    """Evaluate a control definition against current evidence."""
    evaluated_at = now or datetime.now(timezone.utc)
    evidence_ids = [record.evidence_id for record in evidence]
    active_exceptions = _active_exceptions(exceptions, evaluated_at)

    if control.assessment_logic.logic_type == "manual":
        status: AssessmentStatus = "manual_evidence_required"
        summary = "Manual evidence required for this control."
        confidence = 0.2
    else:
        status, summary, confidence = _evaluate_logic(control, evidence)

    if active_exceptions and status == "non_compliant":
        status = "partially_compliant"
        summary = "Non-compliance covered by approved exception."
        confidence = min(confidence, 0.7)

    return AssessmentResult(
        control_id=control.control_id,
        status=status,
        confidence=confidence,
        summary=summary,
        evidence_count=len(evidence),
        evaluated_at=evaluated_at,
        evidence_ids=evidence_ids,
        exceptions_applied=[exception.exception_id for exception in active_exceptions],
        drift_detected=status in {"non_compliant", "partially_compliant"},
    )


def _evaluate_logic(
    control: ControlDefinition,
    evidence: list[EvidenceRecord],
) -> tuple[AssessmentStatus, str, float]:
    if not evidence:
        return (
            "manual_evidence_required",
            "Evidence unavailable for this control.",
            0.1,
        )

    logic = control.assessment_logic
    logic_type = logic.logic_type

    if logic_type == "boolean":
        values = [record.attributes.get(logic.evidence_key) for record in evidence]
        if not values:
            return "manual_evidence_required", "Evidence missing expected attribute.", 0.2
        true_count = sum(1 for value in values if value is True)
        false_count = sum(1 for value in values if value is False)
        if false_count and true_count:
            return "partially_compliant", "Conflicting evidence detected.", 0.4
        if true_count:
            return "compliant", "Control behaviour observed consistently.", 0.9
        return "non_compliant", "Control behaviour not observed.", 0.8

    if logic_type == "threshold":
        if not logic.evidence_key or logic.operator is None or logic.threshold is None:
            return "manual_evidence_required", "Control logic missing threshold configuration.", 0.2
        values = [
            _normalise_numeric(record.attributes.get(logic.evidence_key))
            for record in evidence
        ]
        values = [value for value in values if value is not None]
        if not values:
            return "manual_evidence_required", "Evidence missing numeric measurements.", 0.2
        passing = [
            value for value in values if _apply_operator(value, logic.operator or "", logic.threshold or 0.0)
        ]
        if len(passing) == len(values):
            return "compliant", "Evidence meets threshold requirements.", 0.85
        if passing:
            return "partially_compliant", "Evidence partially meets threshold requirements.", 0.6
        return "non_compliant", "Evidence below threshold requirements.", 0.8

    if logic_type == "time_window":
        if logic.time_window_days is None or not logic.evidence_key:
            return "manual_evidence_required", "Control logic missing time window configuration.", 0.2
        latest = max(evidence, key=lambda record: record.observed_at)
        age_days = (latest.observed_at - min(evidence, key=lambda record: record.observed_at).observed_at).days
        if age_days >= logic.time_window_days:
            return "compliant", "Evidence retention meets time window requirements.", 0.8
        return "non_compliant", "Evidence retention below required window.", 0.7

    if logic_type == "behavioural":
        values = [record.attributes.get(logic.evidence_key) for record in evidence]
        if not values:
            return "manual_evidence_required", "Evidence missing behavioural indicators.", 0.2
        positive = sum(1 for value in values if value == "observed")
        negative = sum(1 for value in values if value == "missing")
        if positive and negative:
            return "partially_compliant", "Behavioural evidence is mixed.", 0.5
        if positive:
            return "compliant", "Behavioural control observed.", 0.85
        return "non_compliant", "Behavioural control not observed.", 0.75

    return "manual_evidence_required", "Control logic error detected.", 0.1
