"""Management review inputs (ISO 27001 9.3.2), described in our own words, and the reporting period."""

from __future__ import annotations

from typing import Any, Mapping

from ._js import parse_day

REVIEW_INPUTS = (
    {"key": "previous_actions", "clause": "9.3.2 a", "title": "Actions from earlier management reviews"},
    {"key": "issue_changes", "clause": "9.3.2 b", "title": "Changes in internal and external issues"},
    {"key": "party_changes", "clause": "9.3.2 c", "title": "Changes in what interested parties need and expect"},
    {"key": "nonconformities", "clause": "9.3.2 d", "title": "Nonconformities and corrective actions"},
    {"key": "monitoring", "clause": "9.3.2 d", "title": "Monitoring and measurement results"},
    {"key": "audits", "clause": "9.3.2 d", "title": "Audit results"},
    {"key": "objectives", "clause": "9.3.2 d", "title": "How well objectives are being met"},
    {"key": "party_feedback", "clause": "9.3.2 e", "title": "Feedback from interested parties"},
    {"key": "risk", "clause": "9.3.2 f", "title": "Risk assessment results and treatment progress"},
    {"key": "opportunities", "clause": "9.3.2 g", "title": "Opportunities for continual improvement"},
)


def missing_inputs(inputs: Mapping[str, Any]) -> list[str]:
    """Inputs the review pack has not filled (missing or None)."""
    return [i["key"] for i in REVIEW_INPUTS if inputs.get(i["key"]) is None]


def review_period_start(planned_on: str, last_held_on: str | None) -> str:
    """From the last held review, or a year before the planned date (29 February goes to 1 March)."""
    if last_held_on and last_held_on <= planned_on:
        return last_held_on
    d = parse_day(planned_on)
    try:
        return d.replace(year=d.year - 1).isoformat()
    except ValueError:  # 29 February in a non-leap year rolls over, as in JavaScript
        return d.replace(year=d.year - 1, month=3, day=1).isoformat()
