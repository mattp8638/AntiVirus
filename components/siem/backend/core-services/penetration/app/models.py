"""API models for the Penetration Testing Orchestrator (MVP-12)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


TestType = Literal["network", "host", "auth", "config"]
TestMethod = Literal["scan", "simulate", "validate"]
TestStatus = Literal[
    "planned",
    "scheduled",
    "running",
    "completed",
    "aborted",
    "blocked",
    "failed",
]
DetectionStatus = Literal["ok", "degraded", "failed"]
RiskRating = Literal["critical", "high", "medium", "low", "info"]
CredentialState = Literal["valid", "revoked", "unknown"]


class ScopeDefinition(BaseModel):
    """Explicit scope definition with allow-list and exclusions."""

    assets: list[str] = Field(default_factory=list)
    networks: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    decommissioned_assets: list[str] = Field(default_factory=list)


class ScheduleWindow(BaseModel):
    """Execution window for a controlled test."""

    start_at: datetime
    end_at: datetime


class CredentialReference(BaseModel):
    """Reference to credentials used for authenticated testing."""

    credential_ref: str = Field(..., min_length=3, max_length=120)
    description: Optional[str] = Field(default=None, max_length=200)
    expires_at: Optional[datetime] = None


class Safeguards(BaseModel):
    """Mandatory safety controls for test execution."""

    target_allow_list: list[str] = Field(default_factory=list, min_length=1)
    payload_restrictions: list[str] = Field(default_factory=list)
    max_duration_minutes: int = Field(default=180, ge=5, le=1440)
    rate_limit_per_minute: int = Field(default=120, ge=10, le=2000)
    safe_mode: bool = True
    abort_on_detection_failure: bool = True


class AuthorisationRecord(BaseModel):
    """Authorisation metadata for auditability."""

    authorised_by: str = Field(..., min_length=3, max_length=120)
    authorised_at: datetime
    policy_reference: str = Field(..., min_length=3, max_length=120)
    justification: Optional[str] = Field(default=None, max_length=300)


class PenTestPlan(BaseModel):
    """First-class penetration test plan."""

    test_id: UUID
    tenant_id: str = Field(..., min_length=3, max_length=64)
    scope: ScopeDefinition
    test_type: TestType
    method: TestMethod
    credentials: list[CredentialReference] = Field(default_factory=list)
    schedule: ScheduleWindow
    safeguards: Safeguards
    authorisation: AuthorisationRecord
    status: TestStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    last_updated_at: datetime


class Observation(BaseModel):
    """Raw observation captured during a test execution."""

    observation_id: UUID = Field(default_factory=uuid4)
    asset_id: str = Field(..., min_length=3, max_length=64)
    weakness_id: str = Field(..., min_length=3, max_length=120)
    summary: str = Field(..., min_length=5, max_length=300)
    evidence: str = Field(..., min_length=5, max_length=2000)
    confidence: float = Field(..., ge=0.0, le=1.0)
    observed_at: datetime
    external_severity: Optional[str] = Field(default=None, max_length=40)
    credential_state: CredentialState = "valid"
    attack_stage: Optional[str] = Field(default=None, max_length=80)


class DetectionResponseSummary(BaseModel):
    """Detection and defence response summary."""

    detection_system_status: DetectionStatus
    detections_fired: list[str] = Field(default_factory=list)
    defences_acted: list[str] = Field(default_factory=list)
    defences_failed: list[str] = Field(default_factory=list)
    detection_notes: Optional[str] = Field(default=None, max_length=400)


class NormalisedResult(BaseModel):
    """Normalised result for vulnerability and detection ingestion."""

    result_id: UUID = Field(default_factory=uuid4)
    test_id: UUID
    weakness_id: str
    asset_id: str
    summary: str
    evidence: str
    confidence: float
    risk_rating: RiskRating
    context: dict
    detection_summary: DetectionResponseSummary
    created_at: datetime


class EvidenceRecord(BaseModel):
    """Immutable evidence record for auditing."""

    evidence_id: UUID = Field(default_factory=uuid4)
    test_id: UUID
    payload_hash: str
    payload: dict
    captured_at: datetime


class IntegrationDispatch(BaseModel):
    """Dispatch record for downstream engines."""

    dispatch_id: UUID = Field(default_factory=uuid4)
    test_id: UUID
    target: Literal["vulnerability", "detection", "psa"]
    status: Literal["queued", "delivered", "degraded"]
    recorded_at: datetime
    payload_preview: dict


class PenTestCreateRequest(BaseModel):
    tenant_id: str = Field(..., min_length=3, max_length=64)
    scope: ScopeDefinition
    test_type: TestType
    method: TestMethod
    credentials: list[CredentialReference] = Field(default_factory=list)
    schedule: ScheduleWindow
    safeguards: Optional[Safeguards] = None
    authorisation: AuthorisationRecord
    requested_by: str = Field(..., min_length=3, max_length=120)


class PenTestResponse(BaseModel):
    status: Literal["recorded", "blocked"]
    test: PenTestPlan
    message: Optional[str] = None


class PenTestListResponse(BaseModel):
    tests: list[PenTestPlan]


class StartTestRequest(BaseModel):
    requested_by: str = Field(..., min_length=3, max_length=120)


class AbortTestRequest(BaseModel):
    requested_by: str = Field(..., min_length=3, max_length=120)
    reason: str = Field(..., min_length=3, max_length=300)


class ResultIngestRequest(BaseModel):
    operator_identity: str = Field(..., min_length=3, max_length=120)
    observations: list[Observation] = Field(default_factory=list)
    detection_summary: DetectionResponseSummary
    finalise: bool = False


class ResultIngestResponse(BaseModel):
    status: Literal["recorded", "aborted", "blocked", "truncated"]
    test_id: UUID
    result_count: int
    message: Optional[str] = None


class ResultListResponse(BaseModel):
    results: list[NormalisedResult]


class EvidenceListResponse(BaseModel):
    evidence: list[EvidenceRecord]


class DispatchListResponse(BaseModel):
    dispatches: list[IntegrationDispatch]
