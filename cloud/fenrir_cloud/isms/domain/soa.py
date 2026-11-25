"""Statement of Applicability status for one requirement, from the states of the controls that implement it."""

from __future__ import annotations

_RANK = {"not_applicable": -1, "not_started": 0, "in_progress": 1, "implemented": 2, "implemented_evidenced": 3}

SOA_STATUSES = ("Not applicable", "Not started", "In progress", "Implemented", "Implemented and evidenced")


def soa_status(applicable: bool, states: list[str]) -> str:
    """The weakest implementing control decides: every control must be implemented for "Implemented", and evidenced
    for "Implemented and evidenced"; any progress at all is "In progress"."""
    if not applicable:
        return "Not applicable"
    live = [_RANK[s] for s in states if s != "not_applicable"]
    if not live:
        return "Not started"
    if min(live) >= 3:
        return "Implemented and evidenced"
    if min(live) >= 2:
        return "Implemented"
    if max(live) >= 1:
        return "In progress"
    return "Not started"
