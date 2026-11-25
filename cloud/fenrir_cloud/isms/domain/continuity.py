"""Business continuity rules (ISO 22301 8.2 and 8.5). Impact is rated per time window after a disruption starts; the
maximum tolerable period of disruption (MTPD) is the first window where impact becomes unacceptable."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from ._js import parse_instant

IMPACT_WINDOWS = (4, 24, 72, 168, 336)  # hours after disruption
WINDOW_LABEL = {4: "4 hours", 24: "1 day", 72: "3 days", 168: "1 week", 336: "2 weeks"}
IMPACT_LABEL = {1: "Minimal", 2: "Minor", 3: "Moderate", 4: "Major", 5: "Severe"}
UNACCEPTABLE = 4  # impact at or above this level is unacceptable


def normalize_impacts(raw: Mapping[int, int]) -> dict[int, int]:
    """Impact never falls as a disruption goes on, so later windows are at least as high as earlier ones."""
    out: dict[int, int] = {}
    floor = 0
    for w in IMPACT_WINDOWS:
        v = raw.get(w)
        if v is None:
            continue
        floor = max(floor, v)
        out[w] = floor
    return out


def suggested_mtpd(impacts: Mapping[int, int]) -> int | None:
    """The first window rated unacceptable, or None if none is."""
    for w in IMPACT_WINDOWS:
        if (impacts.get(w) or 0) >= UNACCEPTABLE:
            return w
    return None


def recovery_priority(rto_hours: float | None) -> int | None:
    """1 within a day, 2 within three days, 3 later."""
    if rto_hours is None:
        return None
    return 1 if rto_hours <= 24 else 2 if rto_hours <= 72 else 3


@dataclass(frozen=True)
class BiaActivity:
    mtpd_hours: float | None
    rto_hours: float | None
    rpo_hours: float | None
    impacts: Mapping[int, int]
    dependencies: int
    plans: int
    last_exercised_on: str | None
    today: str


def bia_issues(a: BiaActivity) -> list[str]:
    """Problems with an activity's business impact analysis and readiness."""
    out = []
    if not a.impacts:
        out.append("Rate the impact of disruption over time.")
    if a.mtpd_hours is None:
        out.append("Set the maximum tolerable period of disruption.")
    if a.rto_hours is None:
        out.append("Set the recovery time objective.")
    if a.rpo_hours is None:
        out.append("Set the recovery point objective.")
    if a.mtpd_hours is not None and a.rto_hours is not None and a.rto_hours > a.mtpd_hours:
        out.append("The recovery time objective must be shorter than the maximum tolerable disruption.")
    if not a.dependencies:
        out.append("Record the assets and suppliers it depends on.")
    if not a.plans:
        out.append("Cover it with a continuity plan.")
    elif not a.last_exercised_on or (
            parse_instant(a.today) - parse_instant(a.last_exercised_on)).total_seconds() > 366 * 86_400:
        out.append("Exercise its plan (at least once a year).")
    return out


def rto_met(achieved_hours: float | None, rto_hours: float | None) -> bool | None:
    """Whether an exercise met the recovery time objective."""
    if achieved_hours is None or rto_hours is None:
        return None
    return achieved_hours <= rto_hours
