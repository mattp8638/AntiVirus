"""Objective tracking (ISO 27001 6.2, 9.1) over recorded measurements."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ._js import parse_day

Direction = Literal["at_least", "at_most"]
ObjectiveHealth = Literal["met", "not_met", "no_data"]
Trend = Literal["improving", "worsening", "steady", "unknown"]
_FREQ_DAYS = {"monthly": 31, "quarterly": 92, "six-monthly": 183, "annual": 366}


@dataclass(frozen=True)
class Measurement:
    measured_on: str
    value: float


def meets_target(value: float, direction: Direction, target: float) -> bool:
    return value >= target if direction == "at_least" else value <= target


@dataclass(frozen=True)
class ObjectiveSummary:
    latest: Measurement | None
    health: ObjectiveHealth
    trend: Trend
    stale: bool  # the latest value is older than the measurement frequency allows


def _sorted(values: list[Measurement]) -> list[Measurement]:
    return sorted(values, key=lambda m: m.measured_on)  # stable, like Array.prototype.sort


def summarize_objective(values: list[Measurement], direction: Direction, target: float, frequency: str,
                        today: str) -> ObjectiveSummary:
    ordered = _sorted(values)
    if not ordered:
        return ObjectiveSummary(None, "no_data", "unknown", True)
    latest = ordered[-1]
    trend: Trend = "unknown"
    if len(ordered) > 1:
        delta = latest.value - ordered[-2].value
        trend = "steady" if delta == 0 else ("improving" if (delta > 0) == (direction == "at_least") else "worsening")
    age = (parse_day(today) - parse_day(latest.measured_on)).days
    return ObjectiveSummary(latest, "met" if meets_target(latest.value, direction, target) else "not_met", trend,
                            age > _FREQ_DAYS.get(frequency, 31))


@dataclass(frozen=True)
class ChartPoint:
    x: float
    y: float
    value: float
    measured_on: str


@dataclass(frozen=True)
class ChartGeometry:
    points: list[ChartPoint]
    target_y: float
    min: float
    max: float


def chart_geometry(values: list[Measurement], target: float, width: float, height: float,
                   pad: float = 8) -> ChartGeometry:
    """Scales values into a width by height box (y grows downwards), keeping the target visible."""
    ordered = _sorted(values)
    nums = [v.value for v in ordered] + [target]
    lo, hi = min(nums), max(nums)
    if lo == hi:
        lo, hi = lo - 1, hi + 1

    def y(v: float) -> float:
        return pad + (1 - (v - lo) / (hi - lo)) * (height - 2 * pad)

    step = (width - 2 * pad) / (len(ordered) - 1) if len(ordered) > 1 else 0
    points = [ChartPoint(pad + i * step if len(ordered) > 1 else width / 2, y(v.value), v.value, v.measured_on)
              for i, v in enumerate(ordered)]
    return ChartGeometry(points, y(target), lo, hi)
