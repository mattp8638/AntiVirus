"""Nonconformity workflow (ISO 27001 10.2): correction, root cause, corrective actions, then an effectiveness check
before closure. Improvement opportunities (10.1) only need a closing note."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ._js import js_trim

NcStage = Literal["needs_root_cause", "needs_actions", "actions_in_progress", "ready_for_check", "open_opportunity",
                  "closed", "cancelled"]
NC_STAGE_TEXT = {
    "needs_root_cause": "Root cause needed",
    "needs_actions": "Corrective action needed",
    "actions_in_progress": "Actions in progress",
    "ready_for_check": "Ready for effectiveness check",
    "open_opportunity": "Open",
    "closed": "Closed",
    "cancelled": "Cancelled",
}


@dataclass(frozen=True)
class NcState:
    kind: Literal["nonconformity", "opportunity"]
    status: Literal["open", "closed", "cancelled"]
    root_cause: str


def nc_stage(nc: NcState, actions_done: list[bool]) -> NcStage:
    if nc.status == "closed":
        return "closed"
    if nc.status == "cancelled":
        return "cancelled"
    if nc.kind == "opportunity":
        return "open_opportunity"
    if not js_trim(nc.root_cause):
        return "needs_root_cause"
    if not actions_done:
        return "needs_actions"
    if not all(actions_done):
        return "actions_in_progress"
    return "ready_for_check"


def effectiveness_blockers(nc: NcState, actions_done: list[bool]) -> list[str]:
    """Reasons the effectiveness check cannot be recorded yet; empty when it can."""
    if nc.kind == "opportunity":
        return ["Improvement opportunities are closed with a note, not an effectiveness check."]
    if nc.status != "open":
        return ["Only an open nonconformity can be checked."]
    out = []
    if not js_trim(nc.root_cause):
        out.append("Record the root cause.")
    if not actions_done:
        out.append("Plan at least one corrective action.")
    elif not all(actions_done):
        out.append("Complete every corrective action.")
    return out
