"""Priority and SLA computation for PSA tickets."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .models import AssetCriticality, ExposureLevel, PriorityLevel, TimeSensitivity


def compute_priority(
    risk_score: float,
    asset_criticality: AssetCriticality,
    exposure_level: ExposureLevel,
    time_sensitivity: TimeSensitivity,
) -> PriorityLevel:
    """Compute a priority level using deterministic weighting."""
    adjusted_score = float(risk_score)

    if asset_criticality == "high":
        adjusted_score += 10.0
    elif asset_criticality == "mission_critical":
        adjusted_score += 20.0

    if exposure_level == "external":
        adjusted_score += 10.0

    if time_sensitivity == "exploit_observed":
        adjusted_score += 10.0
    elif time_sensitivity == "active_attack":
        adjusted_score += 15.0

    if adjusted_score >= 85:
        return "p1"
    if adjusted_score >= 70:
        return "p2"
    if adjusted_score >= 50:
        return "p3"
    return "p4"


def compute_sla_deadline(priority: PriorityLevel, now: datetime | None = None) -> datetime:
    """Compute SLA deadline based on priority level."""
    if now is None:
        now = datetime.now(timezone.utc)

    sla_hours = {
        "p1": 4,
        "p2": 24,
        "p3": 72,
        "p4": 168,
    }[priority]

    return now + timedelta(hours=sla_hours)
