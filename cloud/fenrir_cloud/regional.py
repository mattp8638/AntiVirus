"""Regional settings for an MSP: default currency, time zone and the public holidays that pause SLA clocks.

Stored on the MSP tenant (``Tenant.settings["region"]``). Without settings, behaviour is as before: GBP, Europe/London
and no holidays. Built-in calendars follow the published rules for their region (fixed dates, Easter, nth weekdays and
weekend substitutes). Any other region, and one-off days such as a royal funeral or a state holiday, go in
``extraHolidays`` as YYYY-MM-DD dates.
"""
from __future__ import annotations

import re
from datetime import date, timedelta
from functools import lru_cache

from sqlalchemy.orm import Session

DEFAULTS = {"currency": "GBP", "timeZone": "Europe/London", "holidayCalendar": "none", "extraHolidays": []}

CALENDARS = {
    "none": "No public holidays",
    "GB-ENG": "England and Wales (bank holidays)",
    "GB-SCT": "Scotland (bank holidays)",
    "GB-NIR": "Northern Ireland (bank holidays)",
    "IE": "Ireland (public holidays)",
    "US": "United States (federal holidays, observed)",
}

# ISO 4217 codes offered in the console; any valid three-letter code is accepted by the API.
CURRENCIES = ["GBP", "EUR", "USD", "AUD", "CAD", "NZD", "ZAR", "INR", "CHF", "SEK", "NOK", "DKK", "PLN", "CZK", "HUF", "RON",
              "JPY", "SGD", "HKD", "AED", "SAR", "BRL", "MXN", "ILS", "TRY", "NGN", "KES", "PHP", "MYR"]

_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def easter(year: int) -> date:
    """Western (Gregorian) Easter Sunday: the Anonymous Gregorian algorithm."""
    a, b, c = year % 19, year // 100, year % 100
    d, e = b // 4, b % 4
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = c // 4, c % 4
    l = (32 + 2 * e + 2 * i - h - k) % 7  # noqa: E741 - the algorithm's own name
    m = (a + 11 * h + 22 * l) // 451
    month, day = divmod(h + l - 7 * m + 114, 31)
    return date(year, month, day + 1)


def _nth_weekday(year: int, month: int, weekday: int, n: int) -> date:
    """The n-th given weekday (Monday = 0) of a month; n = -1 for the last one."""
    if n > 0:
        first = date(year, month, 1)
        return first + timedelta(days=(weekday - first.weekday()) % 7 + 7 * (n - 1))
    last = (date(year + (month == 12), month % 12 + 1, 1) - timedelta(days=1))
    return last - timedelta(days=(last.weekday() - weekday) % 7)


def _substitute(days: list[date]) -> set[date]:
    """UK rule: a holiday on a Saturday or Sunday moves to the next weekday that is not already a holiday."""
    out: set[date] = set()
    for day in sorted(days):
        while day.weekday() >= 5 or day in out:
            day += timedelta(days=1)
        out.add(day)
    return out


def _uk(year: int, region: str) -> set[date]:
    e = easter(year)
    fixed_start = [date(year, 1, 1)] + ([date(year, 1, 2)] if region == "GB-SCT" else [])
    days = _substitute(fixed_start)
    days |= {e - timedelta(days=2), _nth_weekday(year, 5, 0, 1), _nth_weekday(year, 5, 0, -1)}
    if region == "GB-SCT":
        days |= {_nth_weekday(year, 8, 0, 1)}
        days |= _substitute([date(year, 11, 30)])  # St Andrew's Day
    else:
        days |= {e + timedelta(days=1), _nth_weekday(year, 8, 0, -1)}
    if region == "GB-NIR":
        days |= _substitute([date(year, 3, 17)]) | _substitute([date(year, 7, 12)])  # St Patrick's Day, Battle of the Boyne
    return days | _substitute([date(year, 12, 25), date(year, 12, 26)])


def _ireland(year: int) -> set[date]:
    feb1 = date(year, 2, 1)
    brigid = feb1 if feb1.weekday() == 4 else _nth_weekday(year, 2, 0, 1)  # since 2023
    days = {date(year, 1, 1), date(year, 3, 17), easter(year) + timedelta(days=1), _nth_weekday(year, 5, 0, 1),
            _nth_weekday(year, 6, 0, 1), _nth_weekday(year, 8, 0, 1), _nth_weekday(year, 10, 0, -1), date(year, 12, 25), date(year, 12, 26)}
    if year >= 2023:
        days.add(brigid)
    return days


def _us_observed(day: date) -> date:
    return day - timedelta(days=1) if day.weekday() == 5 else day + timedelta(days=1) if day.weekday() == 6 else day


def _us(year: int) -> set[date]:
    days: set[date] = set()
    for y in (year, year + 1):  # 1 January on a Saturday is observed on 31 December of the year before
        fixed = [date(y, 1, 1), date(y, 7, 4), date(y, 11, 11), date(y, 12, 25)] + ([date(y, 6, 19)] if y >= 2021 else [])
        days |= {_us_observed(d) for d in fixed}
    days |= {_nth_weekday(year, 1, 0, 3), _nth_weekday(year, 2, 0, 3), _nth_weekday(year, 5, 0, -1), _nth_weekday(year, 9, 0, 1),
             _nth_weekday(year, 10, 0, 2), _nth_weekday(year, 11, 3, 4)}
    return {d for d in days if d.year == year}


@lru_cache(maxsize=256)
def calendar_days(calendar: str, year: int) -> frozenset[date]:
    if calendar in ("GB-ENG", "GB-SCT", "GB-NIR"):
        return frozenset(_uk(year, calendar))
    if calendar == "IE":
        return frozenset(_ireland(year))
    if calendar == "US":
        return frozenset(_us(year))
    return frozenset()


def holiday_dates(region: dict, years: range) -> set[str]:
    """YYYY-MM-DD dates on which the SLA clock stops, for these years."""
    out = {d.isoformat() for y in years for d in calendar_days(region.get("holidayCalendar") or "none", y)}
    return out | {d for d in region.get("extraHolidays") or [] if _DATE.fullmatch(str(d))}


def get(db: Session, tenant_id: str | None) -> dict:
    """The regional settings of the MSP that manages this tenant."""
    from . import services
    from .models import Tenant

    if not tenant_id:
        return dict(DEFAULTS)
    msp = db.get(Tenant, services.msp_tenant_id(db, tenant_id))
    stored = ((msp.settings or {}).get("region") if msp is not None else None) or {}
    return {**DEFAULTS, **{k: v for k, v in stored.items() if k in DEFAULTS}}


def validate(body: dict) -> dict:
    """The settings to store, or ValueError with a message for the user."""
    from zoneinfo import ZoneInfo

    out = dict(DEFAULTS)
    currency = str(body.get("currency") or DEFAULTS["currency"]).upper()
    if not re.fullmatch(r"[A-Z]{3}", currency):
        raise ValueError("Currency must be a three-letter ISO 4217 code such as GBP, EUR or USD")
    zone = str(body.get("timeZone") or DEFAULTS["timeZone"])
    try:
        ZoneInfo(zone)
    except Exception:  # noqa: BLE001 - any lookup failure means an unknown zone
        raise ValueError(f"Unknown time zone: {zone}") from None
    calendar = str(body.get("holidayCalendar") or "none")
    if calendar not in CALENDARS:
        raise ValueError(f"holidayCalendar must be one of: {', '.join(CALENDARS)}")
    extra = sorted({str(d).strip() for d in body.get("extraHolidays") or [] if str(d).strip()})
    bad = [d for d in extra if not _DATE.fullmatch(d)]
    if bad:
        raise ValueError(f"Holiday dates must be YYYY-MM-DD: {', '.join(bad[:5])}")
    try:
        for d in extra:
            date.fromisoformat(d)
    except ValueError as exc:
        raise ValueError(f"Not a real date: {exc}") from None
    out.update(currency=currency, timeZone=zone, holidayCalendar=calendar, extraHolidays=extra[:200])
    return out
