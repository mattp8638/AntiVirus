"""Recurring task dates. Dates are YYYY-MM-DD strings."""

from __future__ import annotations

from datetime import timedelta
from typing import Literal

from ._js import add_months, parse_day

RECURRENCES = ("daily", "weekly", "monthly", "quarterly", "six-monthly", "annual")
Recurrence = Literal["daily", "weekly", "monthly", "quarterly", "six-monthly", "annual"]
TaskUrgency = Literal["overdue", "due_soon", "later"]
_MONTHS = {"monthly": 1, "quarterly": 3, "six-monthly": 6}


def recurrence_for(frequency: str | None) -> str | None:
    """A control's default frequency as a task recurrence; continuous and event-driven have none."""
    return frequency if frequency in RECURRENCES else None


def add_interval(day: str, recurrence: str) -> str:
    d = parse_day(day)
    if recurrence == "daily":
        nxt = d + timedelta(days=1)
    elif recurrence == "weekly":
        nxt = d + timedelta(days=7)
    else:
        nxt = add_months(d, _MONTHS.get(recurrence, 12))
    return nxt.isoformat()


def next_due_date(recurrence: str, previous_due: str | None, today: str) -> str:
    """One interval after the previous due date, or after today if there is none; never in the past."""
    nxt = add_interval(previous_due or today, recurrence)
    while nxt < today:
        nxt = add_interval(nxt, recurrence)
    return nxt


def task_urgency(due_on: str, today: str, soon_days: int = 7) -> TaskUrgency:
    if due_on < today:
        return "overdue"
    return "due_soon" if parse_day(due_on) <= parse_day(today) + timedelta(days=soon_days) else "later"


def days_between(start: str, end: str) -> int:
    return (parse_day(end) - parse_day(start)).days
