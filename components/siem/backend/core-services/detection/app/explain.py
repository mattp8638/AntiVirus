"""Explanation rendering for findings."""
from __future__ import annotations

from .config import Settings
from .models import ContextSnapshot, NormalisedEvent, RuleDefinition


def render_explanation(
    rule: RuleDefinition,
    event: NormalisedEvent,
    context: ContextSnapshot,
    settings: Settings,
    time_window: int | None,
) -> str:
    """Render a human-readable explanation using the rule template."""
    metric_value = event.attributes.get("metric_value")
    metric_name = event.attributes.get("metric_name")
    baseline_value = context.baseline.baseline_value if context.baseline else None
    missing_patches = (
        ", ".join(context.patch_state.missing_patches)
        if context.patch_state and context.patch_state.missing_patches
        else "none"
    )
    network_destination = event.network_flow.destination if event.network_flow else None
    process_name = event.process_lineage.process_name if event.process_lineage else None

    variables = {
        "event_type": event.event_type,
        "asset_id": event.asset_id,
        "identity_id": event.identity_id,
        "metric_name": metric_name or "metric",
        "metric_value": metric_value or "unknown",
        "baseline_value": baseline_value or "unknown",
        "time_window": time_window or 0,
        "multiplier": rule.deviation_multiplier or 0,
        "missing_patches": missing_patches,
        "network_destination": network_destination or "unknown",
        "process_name": process_name or "unknown",
    }

    for key in list(variables.keys()):
        if key not in settings.allowed_explanation_variables:
            variables.pop(key, None)

    return rule.output.explanation_template.format(**variables)
