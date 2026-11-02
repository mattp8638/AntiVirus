from __future__ import annotations

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from .db import Base

def gen_uuid():
    return str(uuid.uuid4())

class Organisation(Base):
    __tablename__ = "organisations"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    name = Column(Text, nullable=False)
    type = Column(Text)
    status = Column(Text, default="active")
    created_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    organisation_id = Column(String(36), ForeignKey("organisations.id"))
    email = Column(Text, nullable=False)
    display_name = Column(Text)
    status = Column(Text, default="active")
    created_at = Column(DateTime, default=datetime.utcnow)

class Asset(Base):
    __tablename__ = "assets"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    organisation_id = Column(String(36), ForeignKey("organisations.id"))
    asset_type = Column(Text)
    external_ref = Column(Text)
    name = Column(Text)
    status = Column(Text, default="active")

class Case(Base):
    __tablename__ = "cases"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    organisation_id = Column(String(36), ForeignKey("organisations.id"))
    case_type = Column(Text)
    source_system = Column(Text)
    severity = Column(Integer, default=1)
    status = Column(Text, default="open")
    opened_at = Column(DateTime, default=datetime.utcnow)
    closed_at = Column(DateTime, nullable=True)
    assets = relationship("CaseAsset", back_populates="case")
    tasks = relationship("Task", back_populates="case")

class CaseAsset(Base):
    __tablename__ = "case_assets"
    case_id = Column(String(36), ForeignKey("cases.id"), primary_key=True)
    asset_id = Column(String(36), ForeignKey("assets.id"), primary_key=True)
    case = relationship("Case", back_populates="assets")

class Task(Base):
    __tablename__ = "tasks"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    case_id = Column(String(36), ForeignKey("cases.id"))
    assigned_to = Column(String(36), ForeignKey("users.id"), nullable=True)
    task_type = Column(Text)
    status = Column(Text, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    case = relationship("Case", back_populates="tasks")
    actions = relationship("TaskAction", back_populates="task")

class TaskAction(Base):
    __tablename__ = "task_actions"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    task_id = Column(String(36), ForeignKey("tasks.id"))
    action_type = Column(Text)
    description = Column(Text)
    performed_by = Column(String(36), ForeignKey("users.id"))
    performed_at = Column(DateTime, default=datetime.utcnow)
    task = relationship("Task", back_populates="actions")

class EvidenceItem(Base):
    __tablename__ = "evidence_items"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    case_id = Column(String(36), ForeignKey("cases.id"))
    evidence_type = Column(Text)
    source_system = Column(Text)
    hash = Column(Text)
    stored_uri = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    actor_id = Column(String(36))
    action = Column(Text)
    entity_type = Column(Text)
    entity_id = Column(String(36))
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_metadata = Column(Text)
"""Pydantic models for the PSA workflow engine."""

from datetime import datetime
from typing import Literal, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator

SourceType = Literal["finding", "patch_failure", "defence_action", "vulnerability"]
PriorityLevel = Literal["p1", "p2", "p3", "p4"]
TicketStatus = Literal[
    "open",
    "acknowledged",
    "remediation_in_progress",
    "deferred",
    "accepted_risk",
    "escalated",
    "resolved",
]
ActionType = Literal["acknowledge", "remediate", "defer", "accept_risk", "escalate"]
AssetCriticality = Literal["low", "medium", "high", "mission_critical"]
ExposureLevel = Literal["internal", "external"]
TimeSensitivity = Literal["none", "exploit_observed", "active_attack"]
LinkedObjectType = Literal["event", "finding", "vulnerability", "patch", "defence_action"]


class EvidenceInput(BaseModel):
    """Evidence payload supplied by upstream intelligence services."""

    linked_object_type: LinkedObjectType
    linked_object_id: str = Field(min_length=3)
    immutable_reference: str = Field(min_length=3)
    payload: Optional[dict] = None


class TicketIntakeRequest(BaseModel):
    """Request body for ticket intake from system intelligence."""

    tenant_id: str = Field(min_length=3)
    asset_id: str = Field(min_length=3)
    source_type: SourceType
    source_reference_id: str = Field(min_length=3)
    risk_score: float = Field(ge=0.0, le=100.0)
    asset_criticality: AssetCriticality
    exposure_level: ExposureLevel
    time_sensitivity: TimeSensitivity = "none"
    system_recommendation: Optional[str] = Field(default=None, max_length=120)
    evidence: list[EvidenceInput] = Field(default_factory=list)

    @field_validator("evidence")
    @classmethod
    def validate_evidence(cls, value: list[EvidenceInput]) -> list[EvidenceInput]:
        if len(value) > 200:
            raise ValueError("evidence_too_large")
        return value


class TicketRecord(BaseModel):
    """Stored ticket representation."""

    ticket_id: UUID = Field(default_factory=uuid4)
    tenant_id: str
    source_type: SourceType
    source_reference_id: str
    asset_id: str
    risk_score: float
    priority: PriorityLevel
    status: TicketStatus
    assigned_to: Optional[str] = None
    sla_deadline: datetime
    creation_timestamp: datetime
    last_updated_at: datetime
    system_recommendation: Optional[str] = None


class TicketResponse(BaseModel):
    """Ticket response payload."""

    status: str
    ticket: TicketRecord


class TicketListResponse(BaseModel):
    """List response for ticket queue."""

    tickets: list[TicketRecord]


class ActionRequest(BaseModel):
    """Request body for recording a human action."""

    action_type: ActionType
    actor_identity: str = Field(min_length=3)
    approver_identity: Optional[str] = Field(default=None, max_length=120)
    justification: Optional[str] = Field(default=None, max_length=200)
    automation_request_id: Optional[str] = Field(default=None, max_length=120)

    @field_validator("justification")
    @classmethod
    def validate_justification(cls, value: Optional[str], info) -> Optional[str]:
        action_type = info.data.get("action_type")
        if action_type in {"defer", "accept_risk", "escalate"} and not value:
            raise ValueError("justification_required")
        return value

    @field_validator("approver_identity")
    @classmethod
    def validate_approver(cls, value: Optional[str], info) -> Optional[str]:
        action_type = info.data.get("action_type")
        if action_type == "accept_risk" and not value:
            raise ValueError("approver_identity_required")
        return value

    @field_validator("automation_request_id")
    @classmethod
    def validate_automation_request(cls, value: Optional[str], info) -> Optional[str]:
        action_type = info.data.get("action_type")
        if action_type == "remediate" and not value:
            raise ValueError("automation_request_required")
        return value


class ActionRecord(BaseModel):
    """Stored action entry for a ticket."""

    action_id: UUID = Field(default_factory=uuid4)
    ticket_id: UUID
    action_type: ActionType
    actor_identity: str
    approver_identity: Optional[str] = None
    timestamp: datetime
    justification: Optional[str] = None
    automation_request_id: Optional[str] = None


class ActionListResponse(BaseModel):
    """List response for ticket actions."""

    actions: list[ActionRecord]


class EvidenceRecord(BaseModel):
    """Stored immutable evidence record."""

    evidence_id: UUID = Field(default_factory=uuid4)
    ticket_id: UUID
    linked_object_type: LinkedObjectType
    linked_object_id: str
    immutable_reference: str
    hash_sha256: str
    captured_at: datetime
    payload: Optional[dict] = None


class EvidenceListResponse(BaseModel):
    """List response for ticket evidence."""

    evidence: list[EvidenceRecord]


class IntakeResponse(BaseModel):
    """Response to ticket intake requests."""

    status: str
    ticket_id: Optional[UUID] = None
    message: Optional[str] = None


class ResolveRequest(BaseModel):
    """Request body to resolve a ticket upstream."""

    tenant_id: str = Field(min_length=3)
    source_type: SourceType
    source_reference_id: str = Field(min_length=3)
    asset_id: str = Field(min_length=3)
    resolved_at: datetime
    resolution_note: Optional[str] = Field(default=None, max_length=120)
