"""Privacy rules. Wording is original; the legal anchors are UK GDPR articles 6, 9, 12, 35 and 36 and chapter V."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Literal, Mapping

from ._js import add_months, js_trim

LAWFUL_BASIS_LABEL = {
    "consent": "Consent (article 6(1)(a))",
    "contract": "Contract (article 6(1)(b))",
    "legal_obligation": "Legal obligation (article 6(1)(c))",
    "vital_interests": "Vital interests (article 6(1)(d))",
    "public_task": "Public task (article 6(1)(e))",
    "legitimate_interests": "Legitimate interests (article 6(1)(f))",
}
LAWFUL_BASES = tuple(LAWFUL_BASIS_LABEL)

TRANSFER_SAFEGUARD_LABEL = {
    "adequacy": "UK adequacy regulations",
    "idta": "International data transfer agreement (IDTA)",
    "addendum": "UK addendum to the EU standard contractual clauses",
    "bcr": "Binding corporate rules",
    "derogation": "Article 49 exception",
}
TRANSFER_SAFEGUARDS = tuple(TRANSFER_SAFEGUARD_LABEL)

# DPIA screening questions. A "strong" one alone means a DPIA is needed.
DPIA_SCREENING = (
    ("automated_decisions", True, "Decisions with legal or similarly significant effects are made by automated means"),
    ("special_large_scale", True, "Special category or criminal offence data is processed on a large scale"),
    ("public_monitoring", True, "Publicly accessible areas are systematically monitored on a large scale"),
    ("profiling", False, "People are evaluated, scored or profiled"),
    ("new_technology", False, "New or innovative technology is used"),
    ("matching", False, "Data sets are combined or matched"),
    ("vulnerable", False, "People who may be vulnerable are affected (for example children or patients)"),
    ("tracking", False, "Location or behaviour is tracked"),
    ("invisible", False, "Data is collected without people being told directly"),
    ("denial", False, "The processing could stop people using a service or contract"),
    ("large_scale", False, "Large volumes of data or many people are involved"),
)


@dataclass(frozen=True)
class DpiaScreening:
    required: bool
    reasons: list[str]


def dpia_required(answers: Mapping[str, bool]) -> DpiaScreening:
    """Any strong indicator, or two or more of the others (the regulators' approach to "likely high risk")."""
    hits = [(strong, text) for qid, strong, text in DPIA_SCREENING if answers.get(qid)]
    return DpiaScreening(any(s for s, _ in hits) or len(hits) >= 2, [t for _, t in hits])


@dataclass(frozen=True)
class ProcessingRecord:
    lawful_basis: str | None
    special_category: bool
    special_condition: str
    transfers: bool
    transfer_safeguard: str | None
    retention: str
    data_subjects: tuple[str, ...]
    data_categories: tuple[str, ...]
    dpia_required: bool
    has_approved_dpia: bool


def processing_gaps(p: ProcessingRecord) -> list[str]:
    """Problems with a record of processing that need fixing before it is complete."""
    out = []
    if not p.lawful_basis:
        out.append("Choose the lawful basis.")
    if p.special_category and not js_trim(p.special_condition):
        out.append("Record the article 9 condition for special category data.")
    if p.transfers and not p.transfer_safeguard:
        out.append("Record the safeguard for international transfers.")
    if not js_trim(p.retention):
        out.append("Record how long the data is kept.")
    if not p.data_subjects:
        out.append("List the categories of people.")
    if not p.data_categories:
        out.append("List the categories of personal data.")
    if p.dpia_required and not p.has_approved_dpia:
        out.append("Complete and approve a DPIA.")
    return out


Level = Literal["low", "medium", "high"]
_LEVEL = {"low": 1, "medium": 2, "high": 3}


def dpia_risk_level(likelihood: Level, severity: Level) -> Level:
    s = _LEVEL[likelihood] * _LEVEL[severity]
    return "high" if s >= 6 else "medium" if s >= 3 else "low"


def prior_consultation_needed(residuals: list[Level]) -> bool:
    """A high residual risk that cannot be reduced means consulting the regulator first (article 36)."""
    return any(r == "high" for r in residuals)


DSR_TYPE_LABEL = {
    "access": "Access (subject access request)",
    "rectification": "Rectification",
    "erasure": "Erasure",
    "restriction": "Restriction",
    "portability": "Data portability",
    "objection": "Objection",
    "automated_decision": "Automated decision review",
}
DSR_TYPES = tuple(DSR_TYPE_LABEL)


def add_calendar_months(iso_date: str, months: int) -> str:
    """When the target month is shorter, the deadline is its last day (31 January plus one month is 28 or 29
    February)."""
    # Like the standalone app, the day is taken as written (30 February plus two months is 30 April).
    y, m, d = (int(x) for x in iso_date.split("-"))
    first = add_months(date(y, m, 1), months)
    last = (add_months(first, 1) - timedelta(days=1)).day
    return first.replace(day=min(d, last)).isoformat()


def dsr_deadline(clock_starts_on: str, extension_months: int = 0) -> str:
    """One month from receipt (or from identity being confirmed), extendable by up to two further months for complex
    or numerous requests (article 12(3))."""
    whole = (not isinstance(extension_months, bool) and isinstance(extension_months, (int, float))
             and float(extension_months).is_integer())
    if not whole or not 0 <= extension_months <= 2:
        raise ValueError("A deadline can be extended by up to two months.")
    return add_calendar_months(clock_starts_on, 1 + int(extension_months))
