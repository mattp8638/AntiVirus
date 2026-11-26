"""Scheduled report timing. Times are UTC."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

from ._js import add_months, utc

DIGEST_HOUR_UTC = 7


def next_digest_at(start: datetime, frequency: Literal["weekly", "monthly"]) -> datetime:
    """The next send time strictly after ``start``: Mondays at 07:00 UTC for weekly digests, the first of the month
    at 07:00 UTC for monthly ones."""
    start = utc(start)
    d = datetime(start.year, start.month, start.day, DIGEST_HOUR_UTC, tzinfo=timezone.utc)
    if frequency == "weekly":
        d += timedelta(days=(7 - d.weekday()) % 7)  # days until Monday
        if d <= start:
            d += timedelta(days=7)
        return d
    d = d.replace(day=1)
    if d <= start:
        nxt = add_months(d.date(), 1)
        d = d.replace(year=nxt.year, month=nxt.month)
    return d
