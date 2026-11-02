"""API models for the Patch Management service."""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field


PatchSeverity = Literal["critical", "high", "medium", "low", "unknown"]
PatchCategory = Literal["security", "critical", "optional", "feature", "unknown"]
RebootRule = Literal["immediate", "deferred", "maintenance_window"]
PlanStatus = Literal["planned", "executing", "completed", "failed"]
VerificationStatus = Literal["pending", "passed", "failed"]
FailureType = Literal[
    "install_failure",
    "timeout",
    "reboot_failure",
    "post_check_failure",
    "unknown",
]


class PatchMetadata(BaseModel):
    """Normalised patch metadata captured by the agent."""

    patch_id: str = Field(..., min_length=3, max_length=200)
    vendor: str = Field(..., min_length=2, max_length=120)
    severity: PatchSeverity = "unknown"
    category: PatchCategory = "unknown"
    affected_component: str = Field(..., min_length=2, max_length=200)
    requires_reboot: bool
    release_date: datetime
    detection_timestamp: datetime
    supersedes: list[str] = Field(default_factory=list)


class DetectionBatch(BaseModel):
    """Batch of patch detections for a specific asset."""

    detection_id: UUID
    tenant_id: str = Field(..., min_length=3, max_length=64)
    asset_id: str = Field(..., min_length=3, max_length=64)
    identity_id: str = Field(..., min_length=3, max_length=64)
    detected_at: datetime
    patches: list[PatchMetadata]


class DetectionResponse(BaseModel):
    status: Literal["recorded"]
    detection_id: UUID


class MaintenanceWindow(BaseModel):
    """Maintenance window definition (local time)."""

    window_id: UUID
    timezone: str = Field(..., min_length=2, max_length=64)
    start_time: str = Field(..., pattern=r"^\d{2}:\d{2}$")
    end_time: str = Field(..., pattern=r"^\d{2}:\d{2}$")
    days_of_week: list[int] = Field(..., min_length=1, max_length=7)


class PatchPolicy(BaseModel):
    """Signed policy that governs patch eligibility and scheduling."""

    policy_id: UUID
    name: str = Field(..., min_length=3, max_length=120)
    version: str = Field(..., min_length=1, max_length=40)
    tenant_id: str = Field(..., min_length=3, max_length=64)
    asset_ids: list[str] = Field(default_factory=list)
    allowed_severities: list[PatchSeverity] = Field(default_factory=list)
    deferred_categories: list[PatchCategory] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    reboot_rule: RebootRule
    retry_limit: int = Field(ge=0, le=10)
    maintenance_windows: list[MaintenanceWindow] = Field(default_factory=list)
    signed_by: str = Field(..., min_length=3, max_length=120)
    signature: str = Field(..., min_length=10, max_length=500)
    created_at: datetime


class PolicyResponse(BaseModel):
    status: Literal["recorded"]
    policy_id: UUID


class EligibilityDecision(BaseModel):
    patch_id: str
    status: Literal["allowed", "deferred", "excluded"]
    reason: str


class ExecutionPlanRequest(BaseModel):
    plan_id: UUID
    tenant_id: str = Field(..., min_length=3, max_length=64)
    asset_id: str = Field(..., min_length=3, max_length=64)
    detection_id: UUID
    policy_id: UUID
    requested_by: str = Field(..., min_length=3, max_length=120)


class ExecutionPlan(BaseModel):
    plan_id: UUID
    tenant_id: str
    asset_id: str
    policy_id: UUID
    detection_id: UUID
    created_at: datetime
    scheduled_for: Optional[datetime]
    reboot_rule: RebootRule
    status: PlanStatus
    execution_order: list[str]
    pre_checks: list[str]
    post_checks: list[str]
    rollback_plan: list[str]
    eligibility: list[EligibilityDecision]
    pre_check_results: list[str] = Field(default_factory=list)
    post_check_results: list[str] = Field(default_factory=list)
    rollback_actions: list[str] = Field(default_factory=list)
    reboot_events: list["RebootEvent"] = Field(default_factory=list)


class ExecutionPlanResponse(BaseModel):
    status: Literal["planned"]
    plan: ExecutionPlan


class PlanStartRequest(BaseModel):
    tenant_id: str = Field(..., min_length=3, max_length=64)
    asset_id: str = Field(..., min_length=3, max_length=64)
    started_at: datetime


class PlanStartResponse(BaseModel):
    status: Literal["executing"]
    plan_id: UUID
    started_at: datetime


class PlanCheckRequest(BaseModel):
    tenant_id: str = Field(..., min_length=3, max_length=64)
    asset_id: str = Field(..., min_length=3, max_length=64)
    checks: list[str] = Field(..., min_length=1)
    phase: Literal["pre", "post"]
    recorded_at: datetime


class PlanCheckResponse(BaseModel):
    status: Literal["recorded"]
    plan_id: UUID


class PlanRollbackRequest(BaseModel):
    tenant_id: str = Field(..., min_length=3, max_length=64)
    asset_id: str = Field(..., min_length=3, max_length=64)
    actions: list[str] = Field(..., min_length=1)
    recorded_at: datetime


class PlanRollbackResponse(BaseModel):
    status: Literal["recorded"]
    plan_id: UUID


class RebootEvent(BaseModel):
    """Reboot event recorded during patch execution."""

    stage: Literal["requested", "started", "completed"]
    recorded_at: datetime


class PlanRebootRequest(BaseModel):
    tenant_id: str = Field(..., min_length=3, max_length=64)
    asset_id: str = Field(..., min_length=3, max_length=64)
    event: RebootEvent


class PlanRebootResponse(BaseModel):
    status: Literal["recorded"]
    plan_id: UUID


class ExecutionResult(BaseModel):
    patch_id: str
    status: Literal["completed", "failed", "skipped"]
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    exit_code: Optional[int] = None
    failure_type: Optional[FailureType] = None


class ExecutionResultRequest(BaseModel):
    tenant_id: str = Field(..., min_length=3, max_length=64)
    asset_id: str = Field(..., min_length=3, max_length=64)
    plan_id: UUID
    started_at: datetime
    finished_at: datetime
    results: list[ExecutionResult]
    reboot_confirmed: bool
    verification_status: VerificationStatus
    verification_notes: Optional[str] = Field(default=None, max_length=500)


class ExecutionResultResponse(BaseModel):
    status: Literal["recorded"]
    plan_status: PlanStatus


class TaskDefinition(BaseModel):
    """A task to be executed by the MVP-5 execution engine."""

    task_id: UUID
    issued_by: str = Field(..., min_length=3, max_length=120)
    policy_reference: str = Field(..., min_length=3, max_length=120)
    execution_context: Literal["system", "root"]
    interpreter: Literal["bash", "powershell"]
    command_payload: str = Field(..., min_length=3, max_length=500)
    expires_at: datetime


class TaskManifest(BaseModel):
    """Collection of tasks for a single execution plan."""

    plan_id: UUID
    tenant_id: str = Field(..., min_length=3, max_length=64)
    asset_id: str = Field(..., min_length=3, max_length=64)
    issued_at: datetime
    tasks: list[TaskDefinition]


class AssetPatchState(BaseModel):
    """Current patch state for an asset."""

    tenant_id: str = Field(..., min_length=3, max_length=64)
    asset_id: str = Field(..., min_length=3, max_length=64)
    status: Literal["normal", "patch_blocked"]
    reason: Optional[str] = Field(default=None, max_length=200)
    recorded_at: datetime


class AssetBlockRequest(BaseModel):
    tenant_id: str = Field(..., min_length=3, max_length=64)
    asset_id: str = Field(..., min_length=3, max_length=64)
    reason: str = Field(..., min_length=5, max_length=200)
    recorded_at: datetime


class AssetBlockResponse(BaseModel):
    status: Literal["blocked"]
    asset_state: AssetPatchState


class AssetUnblockRequest(BaseModel):
    tenant_id: str = Field(..., min_length=3, max_length=64)
    asset_id: str = Field(..., min_length=3, max_length=64)
    reason: str = Field(..., min_length=5, max_length=200)
    recorded_at: datetime


class AssetUnblockResponse(BaseModel):
    status: Literal["unblocked"]
    asset_state: AssetPatchState


class ComplianceSummary(BaseModel):
    tenant_id: str = Field(..., min_length=3, max_length=64)
    compliant: int
    pending: int
    failed: int


class AssetHistoryRecord(BaseModel):
    plan_id: UUID
    status: PlanStatus
    recorded_at: datetime
    verification_status: VerificationStatus
    reboot_confirmed: bool


class NextWindowResponse(BaseModel):
    policy_id: UUID
    next_window_start: Optional[datetime] = None


class EvidenceRecord(BaseModel):
    plan_id: UUID
    detection_snapshot: DetectionBatch
    policy_snapshot: PatchPolicy
    plan_snapshot: ExecutionPlan
    results: list[ExecutionResult]
    reboot_confirmed: bool
    verification_status: VerificationStatus
    recorded_at: datetime
    started_at: datetime
    finished_at: datetime
    verification_notes: Optional[str] = None
    evidence_hash: Optional[str] = None


class EvidenceResponse(BaseModel):
    status: Literal["ok"]
    evidence: EvidenceRecord


class EvidenceHashResponse(BaseModel):
    status: Literal["ok"]
    plan_id: UUID
    evidence_hash: str
