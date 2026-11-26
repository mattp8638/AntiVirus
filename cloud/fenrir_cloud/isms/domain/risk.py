"""Risk method maths (ISO 27001 6.1.2): score = likelihood x impact on the tenant's scales, banded into levels and
compared with appetite."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime

from ._js import add_months, js_trim, utc


@dataclass(frozen=True)
class ScalePoint:
    value: int
    label: str
    description: str


@dataclass(frozen=True)
class LevelBand:
    min: int  # lowest score in the band, inclusive
    level: str
    label: str


@dataclass
class RiskMethod:
    likelihood_scale: list[ScalePoint]
    impact_scale: list[ScalePoint]
    levels: list[LevelBand]
    appetite: float
    acceptance_criteria: str
    review_months: float = 12


def default_risk_method() -> RiskMethod:
    """A 5 x 5 starting point; every tenant can change it."""
    return RiskMethod(
        likelihood_scale=[
            ScalePoint(1, "Rare", "Not expected in the next five years."),
            ScalePoint(2, "Unlikely", "Could happen once in three to five years."),
            ScalePoint(3, "Possible", "Could happen once in one to three years."),
            ScalePoint(4, "Likely", "Expected about once a year."),
            ScalePoint(5, "Almost certain", "Expected several times a year."),
        ],
        impact_scale=[
            ScalePoint(1, "Negligible", "No lasting effect on customers, finances or reputation."),
            ScalePoint(2, "Minor", "Short disruption or small cost, handled within the team."),
            ScalePoint(3, "Moderate", "Noticeable disruption, customer complaints or a reportable breach."),
            ScalePoint(4, "Major", "Serious disruption, regulatory action or loss of key customers."),
            ScalePoint(5, "Severe", "Threatens the continuity of the organization."),
        ],
        levels=[LevelBand(1, "low", "Low"), LevelBand(5, "medium", "Medium"), LevelBand(10, "high", "High"),
                LevelBand(16, "critical", "Critical")],
        appetite=8,
        acceptance_criteria=(
            "Risks scoring 8 or less after treatment may be accepted by the risk owner. Higher risks need treatment, "
            "or acceptance by the risk owner with a recorded rationale that top management reviews."),
        review_months=12,
    )


@dataclass(frozen=True)
class MethodIssue:
    field: str
    message: str


def _is_int(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and float(v).is_integer()


def max_score(m: RiskMethod) -> int:
    return len(m.likelihood_scale) * len(m.impact_scale)


def validate_risk_method(m: RiskMethod) -> list[MethodIssue]:
    issues: list[MethodIssue] = []

    def check_scale(name: str, scale: list[ScalePoint]) -> None:
        if not 3 <= len(scale) <= 10:
            issues.append(MethodIssue(name, "Use between 3 and 10 points."))
        for i, p in enumerate(scale, start=1):
            if p.value != i:
                issues.append(MethodIssue(name, f"Point {i} must have the value {i}."))
            if not js_trim(p.label):
                issues.append(MethodIssue(name, f"Point {i} needs a label."))

    check_scale("likelihoodScale", m.likelihood_scale)
    check_scale("impactScale", m.impact_scale)
    top = max_score(m)
    if not m.levels:
        issues.append(MethodIssue("levels", "Add at least one level."))
    else:
        if m.levels[0].min != 1:
            issues.append(MethodIssue("levels", "The first level must start at 1."))
        for prev, cur in zip(m.levels, m.levels[1:]):
            if cur.min <= prev.min:
                issues.append(MethodIssue("levels", "Levels must start at increasing scores."))
        if any(lv.min > top for lv in m.levels):
            issues.append(MethodIssue("levels", f"No level can start above the highest score ({top})."))
    if not _is_int(m.appetite) or m.appetite < 1 or m.appetite > top:
        issues.append(MethodIssue("appetite", f"Appetite must be between 1 and {top}."))
    if not js_trim(m.acceptance_criteria):
        issues.append(MethodIssue("acceptanceCriteria", "Describe the acceptance criteria."))
    if not _is_int(m.review_months) or m.review_months < 1 or m.review_months > 36:
        issues.append(MethodIssue("reviewMonths", "Review every 1 to 36 months."))
    return issues


def risk_score(m: RiskMethod, likelihood: float | None, impact: float | None) -> float | None:
    """None when either rating is missing or outside the scales."""
    if likelihood is None or impact is None:
        return None
    if not 1 <= likelihood <= len(m.likelihood_scale) or not 1 <= impact <= len(m.impact_scale):
        return None
    return likelihood * impact


def risk_level(m: RiskMethod, score: float | None) -> LevelBand | None:
    if score is None:
        return None
    band = None
    for lv in m.levels:
        if score >= lv.min:
            band = lv
    return band


def within_appetite(m: RiskMethod, score: float | None) -> bool:
    return score is not None and score <= m.appetite


def heat_map(m: RiskMethod, risks: list[tuple[int | None, int | None]]) -> tuple[list[list[int]], int]:
    """Counts per cell, grid[impact - 1][likelihood - 1], for (likelihood, impact) pairs; unrated risks separately."""
    grid = [[0 for _ in m.likelihood_scale] for _ in m.impact_scale]
    unrated = 0
    for likelihood, impact in risks:
        if risk_score(m, likelihood, impact) is None:
            unrated += 1
        else:
            grid[int(impact) - 1][int(likelihood) - 1] += 1
    return grid, unrated


def next_review_date(start: date | datetime, months: int) -> str:
    """Next review date as YYYY-MM-DD, clamped to the last day of shorter months."""
    d = utc(start).date() if isinstance(start, datetime) else start
    return add_months(d, months).isoformat()
