"""People: RACI rules (ISO 27001 5.3), competence records (7.2) and policy acknowledgement progress."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal

from ._js import parse_day

RACI_LETTERS = ("R", "A", "C", "I")
RaciProblem = Literal["no_accountable", "several_accountable", "no_responsible"]
RACI_ISSUE_TEXT = {
    "no_accountable": "No role is accountable.",
    "several_accountable": "More than one role is accountable.",
    "no_responsible": "No role is responsible.",
}


@dataclass(frozen=True)
class RaciCell:
    activity_id: str
    role_id: str
    letter: str


@dataclass(frozen=True)
class RaciIssue:
    activity_id: str
    problem: RaciProblem


def raci_issues(activity_ids: list[str], cells: list[RaciCell]) -> list[RaciIssue]:
    """Each activity needs exactly one accountable role and at least one responsible role."""
    issues: list[RaciIssue] = []
    for aid in activity_ids:
        mine = [c for c in cells if c.activity_id == aid]
        accountable = sum(1 for c in mine if c.letter == "A")
        if accountable == 0:
            issues.append(RaciIssue(aid, "no_accountable"))
        if accountable > 1:
            issues.append(RaciIssue(aid, "several_accountable"))
        if not any(c.letter == "R" for c in mine):
            issues.append(RaciIssue(aid, "no_responsible"))
    return issues


CompetenceStatus = Literal["current", "expiring", "expired", "no_expiry"]


def competence_status(expires_on: str | None, today: str, soon_days: int = 30) -> CompetenceStatus:
    if not expires_on:
        return "no_expiry"
    if expires_on < today:
        return "expired"
    return "expiring" if expires_on <= (parse_day(today) + timedelta(days=soon_days)).isoformat() else "current"


@dataclass(frozen=True)
class AckProgress:
    total: int
    done: int
    percent: int  # whole number; 100 when nobody is asked


def ack_progress(target_user_ids: list[str], acknowledged_user_ids: list[str]) -> AckProgress:
    targets = set(target_user_ids)
    done = len({u for u in acknowledged_user_ids if u in targets})
    total = len(targets)
    return AckProgress(total, done, math.floor(done / total * 100) if total else 100)
