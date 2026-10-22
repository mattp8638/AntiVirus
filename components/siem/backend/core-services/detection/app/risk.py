"""Risk scoring utilities for MVP-8."""
from __future__ import annotations

from .models import ContextSnapshot, Severity


def compute_confidence(base_score: float, context: ContextSnapshot) -> float:
    """Adjust confidence based on asset criticality and privileges."""
    adjustment = 0.0
    if context.asset.criticality == "high":
        adjustment += 0.1
    if context.identity.privileges:
        adjustment += 0.05
    if context.patch_state and context.patch_state.missing_patches:
        adjustment += 0.05
    return min(1.0, max(0.0, base_score + adjustment))


def boost_severity(severity: Severity, context: ContextSnapshot) -> Severity:
    """Amplify severity when asset criticality is high or exposure is internet-facing."""
    if context.asset.criticality == "high":
        if severity == "low":
            return "medium"
        if severity == "medium":
            return "high"
    if context.patch_state and context.patch_state.exposure == "internet":
        if severity == "low":
            return "medium"
        if severity == "medium":
            return "high"
    return severity
