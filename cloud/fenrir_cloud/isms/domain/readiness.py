"""Readiness scoring.

A requirement is met when every applicable control that fully satisfies it is implemented and has current evidence.
Readiness = met requirements / applicable requirements that have at least one implementing control. Requirements
with no mapped control (the management clauses 4 to 10) are reported separately: they are evidenced by the ISMS
processes, not by controls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ._js import js_round

ControlState = Literal["not_started", "in_progress", "implemented", "implemented_evidenced", "not_applicable"]
RequirementStatus = Literal["met", "partial", "not_met", "not_applicable", "no_controls"]

READINESS_FORMULA = (
    "Readiness = requirements met / applicable requirements with implementing controls. A requirement is met when "
    "all of its implementing controls are implemented and have current evidence.")


@dataclass(frozen=True)
class ReadinessRequirement:
    ref: str
    applicable: bool
    control_states: tuple[ControlState, ...]


def requirement_status(r: ReadinessRequirement) -> RequirementStatus:
    if not r.applicable:
        return "not_applicable"
    live = [s for s in r.control_states if s != "not_applicable"]
    if not live:
        return "no_controls"
    if all(s == "implemented_evidenced" for s in live):
        return "met"
    if any(s != "not_started" for s in live):
        return "partial"
    return "not_met"


@dataclass(frozen=True)
class Readiness:
    met: int
    partial: int
    not_met: int
    applicable: int
    not_applicable: int
    without_controls: int
    score: float | None  # 0 to 100, one decimal place; None when nothing is applicable yet
    formula: str = READINESS_FORMULA


def _pct1(part: int, whole: int) -> float | None:
    return js_round(part / whole * 1000) / 10 if whole else None


def compute_readiness(requirements: list[ReadinessRequirement]) -> Readiness:
    statuses = [requirement_status(r) for r in requirements]
    met, partial, not_met = statuses.count("met"), statuses.count("partial"), statuses.count("not_met")
    applicable = met + partial + not_met
    return Readiness(met, partial, not_met, applicable, statuses.count("not_applicable"),
                     statuses.count("no_controls"), _pct1(met, applicable))


@dataclass(frozen=True)
class Coverage:
    evidenced: int
    applicable: int
    score: float | None


def control_coverage(states: list[ControlState]) -> Coverage:
    """Share of applicable controls that are implemented with current evidence."""
    live = [s for s in states if s != "not_applicable"]
    evidenced = sum(1 for s in live if s == "implemented_evidenced")
    return Coverage(evidenced, len(live), _pct1(evidenced, len(live)))
