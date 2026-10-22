"""Policy evaluation logic for patch eligibility."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from .models import EligibilityDecision, MaintenanceWindow, PatchMetadata, PatchPolicy


@dataclass(frozen=True)
class EligibilityResult:
    allowed: list[PatchMetadata]
    decisions: list[EligibilityDecision]


def evaluate_patches(policy: PatchPolicy, patches: list[PatchMetadata]) -> EligibilityResult:
    """Determine which patches are eligible under the policy."""
    allowed: list[PatchMetadata] = []
    decisions: list[EligibilityDecision] = []
    allowed_severities = set(policy.allowed_severities)
    deferred_categories = set(policy.deferred_categories)
    exclusions = set(policy.exclusions)
    superseded = _collect_superseded_ids(patches)

    for patch in patches:
        if patch.patch_id in superseded:
            decisions.append(
                EligibilityDecision(
                    patch_id=patch.patch_id,
                    status="deferred",
                    reason="superseded",
                )
            )
            continue
        if patch.patch_id in exclusions:
            decisions.append(
                EligibilityDecision(
                    patch_id=patch.patch_id,
                    status="excluded",
                    reason="explicit_exclusion",
                )
            )
            continue
        if deferred_categories and patch.category in deferred_categories:
            decisions.append(
                EligibilityDecision(
                    patch_id=patch.patch_id,
                    status="deferred",
                    reason="category_deferred",
                )
            )
            continue
        if allowed_severities and patch.severity not in allowed_severities:
            decisions.append(
                EligibilityDecision(
                    patch_id=patch.patch_id,
                    status="deferred",
                    reason="severity_not_allowed",
                )
            )
            continue
        allowed.append(patch)
        decisions.append(
            EligibilityDecision(
                patch_id=patch.patch_id,
                status="allowed",
                reason="policy_allowed",
            )
        )

    return EligibilityResult(allowed=allowed, decisions=decisions)


def _collect_superseded_ids(patches: list[PatchMetadata]) -> set[str]:
    superseded: set[str] = set()
    for patch in patches:
        superseded.update(patch.supersedes)
    return superseded


def next_maintenance_window(
    now: datetime, windows: list[MaintenanceWindow]
) -> datetime | None:
    """Calculate the next maintenance window start, if any."""
    if not windows:
        return None

    candidates: list[datetime] = []
    for window in windows:
        zone = ZoneInfo(window.timezone)
        local_now = now.astimezone(zone)
        start_hour, start_minute = [int(value) for value in window.start_time.split(":")]
        for offset in range(0, 14):
            candidate = local_now + timedelta(days=offset)
            if candidate.weekday() not in window.days_of_week:
                continue
            start = candidate.replace(
                hour=start_hour,
                minute=start_minute,
                second=0,
                microsecond=0,
            )
            if start >= local_now:
                candidates.append(start)
                break

    if not candidates:
        return None

    return min(candidates).astimezone(now.tzinfo)
