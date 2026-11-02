"""Helpers to aggregate phase results into a reporting structure."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Sequence


def _normalise_summary(summary: object) -> str:
    """Convert heterogeneous summary payloads into human-readable text."""

    if isinstance(summary, str) and summary.strip():
        return summary

    if isinstance(summary, Mapping):
        for key in ("summary", "status", "message", "description", "notes"):
            value = summary.get(key)
            if isinstance(value, str) and value.strip():
                return value

        exploit_type = summary.get("exploit_type")
        status = summary.get("status")
        if isinstance(exploit_type, str):
            prefix = f"{status.capitalize()}" if isinstance(status, str) else "Exploit plan"
            return f"{prefix}: {exploit_type}"

        key_list = [str(key) for key in list(summary.keys())[:3]]
        if key_list:
            return f"Structured summary with fields: {', '.join(key_list)}"

    if isinstance(summary, Sequence) and not isinstance(summary, (str, bytes, bytearray)):
        rendered_items = [str(item) for item in summary if item]
        if rendered_items:
            preview = rendered_items[:3]
            suffix = "..." if len(rendered_items) > 3 else ""
            return "; ".join(preview) + suffix

    if summary is None:
        return "No summary available"

    return str(summary)


def merge_phase_results(phase_results: Iterable[Dict[str, object]]) -> Dict[str, object]:
    """Combine heterogeneous phase outputs into a single report dictionary."""

    combined: Dict[str, object] = {"phases": []}
    for result in phase_results:
        if not result:
            continue
        phase_name = result.get("phase", "unknown")
        raw_summary: Any = result.get("summary")
        if raw_summary is None:
            raw_summary = result.get("status")
        summary = _normalise_summary(raw_summary)
        combined["phases"].append(
            {"phase": phase_name, "summary": summary, "details": result}
        )

    combined["overall_status"] = _derive_overall_status(combined["phases"])
    return combined


def _derive_overall_status(phases: List[Dict[str, object]]) -> str:
    if not phases:
        return "no-data"
    if any(
        isinstance(phase.get("summary"), str)
        and phase["summary"].lower().startswith("no ")
        for phase in phases
    ):
        return "incomplete"
    if any(phase["details"].get("status") == "failed" for phase in phases):
        return "degraded"
    return "complete"


def render_text_report(report: Dict[str, object]) -> str:
    """Render the combined report as human readable text for the UI."""

    lines = ["Engagement Summary", "==================", ""]
    for phase in report.get("phases", []):
        lines.append(f"- {phase['phase']}: {phase['summary']}")
    lines.append("")
    lines.append(f"Overall status: {report.get('overall_status', 'unknown')}")
    return "\n".join(lines)


__all__ = ["merge_phase_results", "render_text_report"]

