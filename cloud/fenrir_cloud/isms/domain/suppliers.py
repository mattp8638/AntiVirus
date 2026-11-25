"""Supplier risk tiering, questionnaire scoring and incident rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Literal, Mapping

from ._js import iso_instant, js_round, js_trim, parse_instant

DataAccess = Literal["none", "internal", "confidential", "personal"]
Criticality = Literal["low", "medium", "high"]
TIER_REVIEW_MONTHS = {1: 12, 2: 24, 3: 36}


def supplier_tier(access: DataAccess, criticality: Criticality) -> int:
    """Tier 1 needs the closest oversight: confidential or personal data, or a high criticality service. Internal
    data or medium criticality is tier 2."""
    if access in ("confidential", "personal") or criticality == "high":
        return 1
    if access == "internal" or criticality == "medium":
        return 2
    return 3


@dataclass(frozen=True)
class WeightedQuestion:
    ref: str
    weight: float
    critical: bool = False  # a "no" makes the supplier not acceptable whatever the score


@dataclass(frozen=True)
class QuestionnaireScore:
    score: int
    outcome: Literal["acceptable", "acceptable_with_actions", "not_acceptable"]
    unanswered: list[str]


def score_questionnaire(questions: list[WeightedQuestion], answers: Mapping[str, str]) -> QuestionnaireScore:
    got = 0.0
    top = 0.0
    unanswered: list[str] = []
    critical_fail = False
    for q in questions:
        a = answers.get(q.ref)
        if not a:
            unanswered.append(q.ref)
            continue
        if a == "not_applicable":
            continue
        top += q.weight
        got += q.weight if a == "yes" else q.weight / 2 if a == "partly" else 0
        if a == "no" and q.critical:
            critical_fail = True
    score = js_round(got / top * 100) if top else 100
    outcome = ("not_acceptable" if critical_fail or score < 50 else
               "acceptable_with_actions" if score < 80 else "acceptable")
    return QuestionnaireScore(score, outcome, unanswered)


IncidentSeverity = Literal["low", "medium", "high", "critical"]
INCIDENT_FLOW = ("reported", "investigating", "contained", "resolved", "closed")


def can_move_to(current: str, target: str) -> bool:
    """Statuses only move forward."""
    def idx(s: str) -> int:
        return INCIDENT_FLOW.index(s) if s in INCIDENT_FLOW else -1
    return idx(target) > idx(current)


def closure_blockers(severity: IncidentSeverity, root_cause: str, lessons_learned: str, personal_data: bool,
                     reported_to_authority_at: str | None) -> list[str]:
    """Reasons an incident cannot close yet. Medium and above need lessons learned and a root cause."""
    out = []
    if severity != "low":
        if not js_trim(root_cause):
            out.append("Record the root cause.")
        if not js_trim(lessons_learned):
            out.append("Record the lessons learned.")
    if personal_data and not reported_to_authority_at and severity in ("high", "critical"):
        out.append("Record when the breach was reported to the regulator, or lower the severity with a reason.")
    return out


def breach_deadline(detected_at: str) -> str:
    """Personal data breaches likely to risk people's rights must be reported to the regulator within 72 hours of
    becoming aware (UK GDPR article 33)."""
    return iso_instant(parse_instant(detected_at) + timedelta(hours=72))
