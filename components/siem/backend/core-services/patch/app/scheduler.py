"""Execution plan scheduling helpers."""
from __future__ import annotations

from datetime import datetime, timezone

from .models import ExecutionPlan, PatchMetadata, PatchPolicy
from .policy import EligibilityResult, next_maintenance_window


def build_execution_plan(
    *,
    plan_id,
    tenant_id: str,
    asset_id: str,
    policy: PatchPolicy,
    detection_id,
    eligibility: EligibilityResult,
) -> ExecutionPlan:
    """Create an execution plan based on policy and eligibility results."""
    now = datetime.now(timezone.utc)
    scheduled_for = None
    if policy.reboot_rule == "maintenance_window":
        scheduled_for = next_maintenance_window(now, policy.maintenance_windows)

    ordered_patches = _order_patches(eligibility.allowed)
    execution_order = [patch.patch_id for patch in ordered_patches]

    return ExecutionPlan(
        plan_id=plan_id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        policy_id=policy.policy_id,
        detection_id=detection_id,
        created_at=now,
        scheduled_for=scheduled_for,
        reboot_rule=policy.reboot_rule,
        status="planned",
        execution_order=execution_order,
        pre_checks=["disk_space", "service_health"],
        post_checks=["reboot_state", "service_health", "patch_rescan"],
        rollback_plan=["package_rollback", "restore_point"],
        eligibility=eligibility.decisions,
        pre_check_results=[],
        post_check_results=[],
        rollback_actions=[],
        reboot_events=[],
    )


def _order_patches(patches: list[PatchMetadata]) -> list[PatchMetadata]:
    """Sort patches by severity and release date for deterministic execution."""
    severity_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "unknown": 4,
    }
    return sorted(
        patches,
        key=lambda patch: (
            severity_rank.get(patch.severity, 5),
            patch.release_date,
        ),
    )
