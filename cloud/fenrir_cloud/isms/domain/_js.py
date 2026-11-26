"""Small helpers that reproduce JavaScript behaviour the standalone engine relied on.

* ``js_round``: Math.round rounds halves up (2.5 to 3, -2.5 to -2); Python's round() rounds halves to even.
* ``js_trim`` and ``JS_SPACES``: JavaScript's whitespace includes the byte order mark and other Unicode spaces.
* ``parse_day``: ``new Date("YYYY-MM-DDT00:00:00Z")`` accepts days up to 31 in any month and rolls over
  (30 February is 2 March).

One deliberate difference: the standalone app sorted some keys with localeCompare (case-insensitive, locale
dependent). The port sorts by code point, which gives the same order for the identifiers it sorts (lower-case
references and ISO dates) and the same order on every server.
"""

from __future__ import annotations

import math
import re
from datetime import date, datetime, timedelta, timezone

_JS_SPACE = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a" \
            "\u2028\u2029\u202f\u205f\u3000\ufeff"
JS_SPACES = re.compile("[" + re.escape(_JS_SPACE) + "]+")  # what \\s+ matches in a JavaScript regular expression
_DAY = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")


def js_round(x: float) -> int:
    return math.floor(x + 0.5)


def js_trim(s: str) -> str:
    return s.strip(_JS_SPACE)


def parse_day(s: str) -> date:
    m = _DAY.match(s)
    if not m:
        raise ValueError(f"Invalid date {s}")
    y, mo, d = (int(x) for x in m.groups())
    if not 1 <= mo <= 12 or not 1 <= d <= 31:
        raise ValueError(f"Invalid date {s}")
    return date(y, mo, 1) + timedelta(days=d - 1)


def day(d: date) -> str:
    return d.isoformat()


def add_months(d: date, months: int) -> date:
    """Calendar months, clamped to the last day of a shorter month (31 January plus one month is 28 or 29 February)."""
    total = d.year * 12 + (d.month - 1) + months
    y, m = divmod(total, 12)
    m += 1
    nxt = date(y + (m == 12), 1 if m == 12 else m + 1, 1)
    last = (nxt - timedelta(days=1)).day
    return date(y, m, min(d.day, last))


def utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def iso_instant(dt: datetime) -> str:
    """Date.prototype.toISOString: UTC with milliseconds and a Z."""
    dt = utc(dt)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_instant(s: str) -> datetime:
    """Date.parse for the ISO forms the app stores (date only means UTC midnight)."""
    if _DAY.match(s):
        return datetime.combine(parse_day(s), datetime.min.time(), timezone.utc)
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return utc(dt)


def js_number(x: float) -> str:
    """A number as JavaScript's String(x) writes it for ordinary values: 14.0 is "14", 2.5 stays "2.5"."""
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    return repr(float(x))
