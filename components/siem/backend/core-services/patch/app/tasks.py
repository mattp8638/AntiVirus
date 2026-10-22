"""Task generation helpers for MVP-5 execution."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from .models import ExecutionPlan, TaskDefinition, TaskManifest


def build_task_manifest(plan: ExecutionPlan, *, issued_by: str) -> TaskManifest:
    """Create a task manifest from an execution plan.

    The task payloads are placeholders for MVP-5 execution and are
    intentionally deterministic for audit traceability.
    """
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=30)
    tasks: list[TaskDefinition] = []

    for index, patch_id in enumerate(plan.execution_order, start=1):
        task_id = _task_id(plan.plan_id, index)
        tasks.append(
            TaskDefinition(
                task_id=task_id,
                issued_by=issued_by,
                policy_reference=str(plan.policy_id),
                execution_context="system",
                interpreter="bash",
                command_payload=f"apply-patch --id {patch_id}",
                expires_at=expires_at,
            )
        )

    return TaskManifest(
        plan_id=plan.plan_id,
        tenant_id=plan.tenant_id,
        asset_id=plan.asset_id,
        issued_at=now,
        tasks=tasks,
    )


def _task_id(plan_id: UUID, sequence: int) -> UUID:
    """Deterministic task UUID derived from plan_id and sequence."""
    return UUID(int=(plan_id.int + sequence) % (1 << 128))
