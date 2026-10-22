"""API models for the Compliance & Audit Automation service (MVP-13)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


AssessmentStatus = Literal[
    "compliant",
    "non_compliant",
    "partially_compliant",
    "not_applicable",
    "manual_evidence_required",
]

LogicType = Literal["boolean", "threshold", "time_window", "behavioural", "manual"]


class ControlLogic(BaseModel):
    """Machine-readable control assessment logic."""

    logic_type: LogicType
    evidence_key: Optional[str] = Field(default=None, max_length=120)
    operator: Optional[Literal[">=", "<=", "==", "!=", ">", "<"]] = None
    threshold: Optional[float] = None
    time_window_days: Optional[int] = Field(default=None, ge=1, le=3650)
    notes: Optional[str] = Field(default=None, max_length=400)


class ControlDefinition(BaseModel):
    """Immutable control definition."""

    control_id: str = Field(..., min_length=3, max_length=120)
    framework: str = Field(..., min_length=2, max_length=120)
    control_statement: str = Field(..., min_length=10, max_length=800)
    expected_system_behaviour: str = Field(..., min_length=10, max_length=800)
    evidence_sources: list[str] = Field(default_factory=list)
    assessment_logic: ControlLogic
    evaluation_frequency_days: int = Field(default=30, ge=1, le=365)
    version: int = Field(default=1, ge=1, le=1000)
    published_at: datetime


class FrameworkMapping(BaseModel):
    """Map controls to multiple frameworks."""

    control_id: str = Field(..., min_length=3, max_length=120)
    framework: str = Field(..., min_length=2, max_length=120)
    mapped_control: str = Field(..., min_length=2, max_length=120)
    mapped_at: datetime


class EvidenceRecord(BaseModel):
    """Evidence extracted from system activity."""

    evidence_id: UUID = Field(default_factory=uuid4)
    control_id: str = Field(..., min_length=3, max_length=120)
    source: str = Field(..., min_length=2, max_length=120)
    observed_at: datetime
    actor: str = Field(..., min_length=2, max_length=120)
    attributes: dict
    immutable_reference: Optional[str] = Field(default=None, max_length=400)


class AssessmentResult(BaseModel):
    """Assessment output for a control."""

    assessment_id: UUID = Field(default_factory=uuid4)
    control_id: str
    status: AssessmentStatus
    confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str = Field(..., min_length=5, max_length=600)
    evidence_count: int
    evaluated_at: datetime
    evidence_ids: list[UUID] = Field(default_factory=list)
    exceptions_applied: list[UUID] = Field(default_factory=list)
    drift_detected: bool = False


class ExceptionRecord(BaseModel):
    """Risk acceptance or exception record."""

    exception_id: UUID = Field(default_factory=uuid4)
    control_id: str
    approved_by: str = Field(..., min_length=3, max_length=120)
    justification: str = Field(..., min_length=5, max_length=600)
    expires_at: datetime
    recorded_at: datetime


class AuditBundle(BaseModel):
    """Immutable audit bundle snapshot."""

    bundle_id: UUID = Field(default_factory=uuid4)
    scope: dict
    controls: list[ControlDefinition]
    assessments: list[AssessmentResult]
    evidence: list[EvidenceRecord]
    exceptions: list[ExceptionRecord]
    generated_at: datetime


class ControlCreateRequest(BaseModel):
    framework: str = Field(..., min_length=2, max_length=120)
    control_statement: str = Field(..., min_length=10, max_length=800)
    expected_system_behaviour: str = Field(..., min_length=10, max_length=800)
    evidence_sources: list[str] = Field(default_factory=list)
    assessment_logic: ControlLogic
    evaluation_frequency_days: Optional[int] = Field(default=None, ge=1, le=365)
    requested_by: str = Field(..., min_length=3, max_length=120)


class ControlResponse(BaseModel):
    status: Literal["recorded", "exists"]
    control: ControlDefinition
    message: Optional[str] = None


class ControlListResponse(BaseModel):
    controls: list[ControlDefinition]


class EvidenceIngestRequest(BaseModel):
    control_id: str = Field(..., min_length=3, max_length=120)
    source: str = Field(..., min_length=2, max_length=120)
    observed_at: datetime
    actor: str = Field(..., min_length=2, max_length=120)
    attributes: dict
    immutable_reference: Optional[str] = Field(default=None, max_length=400)


class EvidenceListResponse(BaseModel):
    evidence: list[EvidenceRecord]


class AssessmentRequest(BaseModel):
    requested_by: str = Field(..., min_length=3, max_length=120)


class AssessmentResponse(BaseModel):
    status: Literal["recorded"]
    assessment: AssessmentResult


class AssessmentListResponse(BaseModel):
    assessments: list[AssessmentResult]


class ExceptionRequest(BaseModel):
    approved_by: str = Field(..., min_length=3, max_length=120)
    justification: str = Field(..., min_length=5, max_length=600)
    expires_at: datetime


class ExceptionListResponse(BaseModel):
    exceptions: list[ExceptionRecord]


class FrameworkMappingRequest(BaseModel):
    control_id: str = Field(..., min_length=3, max_length=120)
    framework: str = Field(..., min_length=2, max_length=120)
    mapped_control: str = Field(..., min_length=2, max_length=120)
    requested_by: str = Field(..., min_length=3, max_length=120)


class FrameworkMappingListResponse(BaseModel):
    mappings: list[FrameworkMapping]


class AuditBundleRequest(BaseModel):
    scope: dict
    requested_by: str = Field(..., min_length=3, max_length=120)


class AuditBundleResponse(BaseModel):
    status: Literal["recorded"]
    bundle: AuditBundle
