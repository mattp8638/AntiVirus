"""In-memory task queue for MVP-5 command execution."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


VALID_TASK_STATES = {
    "pending",
    "delivered",
    "executing",
    "completed",
    "failed",
    "expired",
    "rejected",
}


@dataclass
class Task:
    task_id: str
    tenant_id: str
    asset_id: str
    issued_by: str
    policy_reference: str
    execution_context: str
    interpreter: str
    command_payload: str
    expires_at: datetime
    signature: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    state: str = "pending"
    delivered_at: Optional[datetime] = None
    delivered_to_agent: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    last_error: Optional[str] = None


@dataclass
class TaskResult:
    task_id: str
    status: str
    stdout: Optional[str]
    stderr: Optional[str]
    exit_code: Optional[int]
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    truncated: bool
    recorded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class TaskStore:
    """Store tasks and results for MVP-5 execution."""

    def __init__(self) -> None:
        self._tasks: Dict[str, Task] = {}
        self._results: Dict[str, TaskResult] = {}

    def create(self, task: Task) -> Task:
        if task.task_id in self._tasks:
            raise ValueError("task_exists")
        self._tasks[task.task_id] = task
        return task

    def list_pending(
        self,
        tenant_id: str,
        asset_id: str,
        now: Optional[datetime] = None,
    ) -> List[Task]:
        timestamp = now or datetime.now(timezone.utc)
        self._expire_tasks(timestamp)
        return [
            task
            for task in self._tasks.values()
            if task.asset_id == asset_id
            and task.tenant_id == tenant_id
            and task.state == "pending"
        ]

    def mark_delivered(self, task_id: str, agent_id: str) -> Optional[Task]:
        task = self._tasks.get(task_id)
        if not task:
            return None
        if task.state != "pending":
            return task
        task.state = "delivered"
        task.delivered_at = datetime.now(timezone.utc)
        task.delivered_to_agent = agent_id
        return task

    def mark_executing(self, task_id: str, started_at: datetime) -> Optional[Task]:
        task = self._tasks.get(task_id)
        if not task:
            return None
        if task.state not in {"pending", "delivered"}:
            return task
        task.state = "executing"
        task.started_at = started_at
        return task

    def record_result(self, result: TaskResult) -> Optional[Task]:
        task = self._tasks.get(result.task_id)
        if not task:
            return None
        if task.state in {"completed", "failed"}:
            raise ValueError("task_already_recorded")
        if task.state == "expired":
            raise ValueError("task_expired")
        task.finished_at = result.finished_at
        task.state = "completed" if result.status == "completed" else "failed"
        self._results[result.task_id] = result
        return task

    def get(self, task_id: str) -> Optional[Task]:
        return self._tasks.get(task_id)

    def expire_overdue(self, now: Optional[datetime] = None) -> None:
        timestamp = now or datetime.now(timezone.utc)
        self._expire_tasks(timestamp)

    def _expire_tasks(self, now: datetime) -> None:
        for task in self._tasks.values():
            if task.state in {"pending", "delivered", "executing"} and task.expires_at <= now:
                task.state = "expired"
                task.last_error = "expired"


store = TaskStore()
