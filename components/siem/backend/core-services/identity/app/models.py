"""Pydantic models for request and response schemas."""
from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field


class HelloRequest(BaseModel):
    """Signed hello payload emitted by agents via the transport layer."""

    tenant_id: str = Field(..., min_length=8, max_length=64)
    asset_id: str = Field(..., min_length=8, max_length=64)
    identity_id: str = Field(..., min_length=8, max_length=64)
    event_id: str = Field(..., min_length=8, max_length=64)
    agent_version: str = Field(..., min_length=1, max_length=32)
    hostname: str = Field(..., min_length=1, max_length=255)
    os: str = Field(..., min_length=1, max_length=64)
    uptime_seconds: int = Field(..., ge=0)
    trust_state: str = Field(..., min_length=1, max_length=32)
    sent_at: datetime


class HelloResponse(BaseModel):
    """Response returned after verification."""

    status: str
    received_at: datetime
    service: str


class HeartbeatEventResponse(BaseModel):
    """Heartbeat event representation for diagnostics."""

    event_id: str
    agent_id: str
    hostname: str
    os: str
    uptime_seconds: int
    trust_state: str
    received_at: datetime


class AgentStateResponse(BaseModel):
    """Agent state representation for MVP-2 visibility."""

    identity_id: str
    hostname: str
    os: str
    last_seen_at: datetime
    trust_state: str


class AgentPresenceResponse(BaseModel):
    """Agent presence state for online/offline visibility."""

    identity_id: str
    hostname: str
    os: str
    trust_state: str
    last_seen_at: datetime
    status: str


class RiskScoreResponse(BaseModel):
    """Risk score representation for MVP-2 visibility."""

    identity_id: str
    score: float
    rationale: str


class CertificateIssueRequest(BaseModel):
    """Request to register a new client certificate fingerprint."""

    identity_id: str = Field(..., min_length=8, max_length=64)
    fingerprint_sha256: str = Field(..., min_length=8, max_length=128)
    expires_at: datetime


class CertificateIssueResponse(BaseModel):
    """Response after certificate issuance registration."""

    status: str
    issued_at: datetime
    expires_at: datetime


class CertificateRevokeRequest(BaseModel):
    """Request to revoke a certificate fingerprint."""

    fingerprint_sha256: str = Field(..., min_length=8, max_length=128)
    reason: str = Field(..., min_length=3, max_length=255)


class CertificateRevokeResponse(BaseModel):
    """Response after certificate revocation."""

    status: str
    revoked_at: datetime


class TaskCreateRequest(BaseModel):
    """Request to create a signed remote execution task."""

    tenant_id: str = Field(..., min_length=8, max_length=64)
    asset_id: str = Field(..., min_length=8, max_length=64)
    task_id: str = Field(..., min_length=8, max_length=64)
    issued_by: str = Field(..., min_length=8, max_length=64)
    policy_reference: str = Field(..., min_length=3, max_length=128)
    execution_context: str = Field(..., min_length=3, max_length=32)
    interpreter: str = Field(..., min_length=3, max_length=32)
    command_payload: str = Field(..., min_length=1, max_length=8192)
    expires_at: datetime


class TaskCreateResponse(BaseModel):
    """Response after creating a remote execution task."""

    status: str
    task_id: str
    created_at: datetime


class TaskPollRequest(BaseModel):
    """Agent polling request for pending tasks."""

    tenant_id: str = Field(..., min_length=8, max_length=64)
    asset_id: str = Field(..., min_length=8, max_length=64)
    agent_id: str = Field(..., min_length=8, max_length=64)


class TaskRecordResponse(BaseModel):
    """Task record returned to agents."""

    task_id: str
    tenant_id: str
    asset_id: str
    issued_by: str
    policy_reference: str
    execution_context: str
    interpreter: str
    command_payload: str
    expires_at: datetime


class TaskPollResponse(BaseModel):
    """Response for polling tasks."""

    status: str
    tasks: list[TaskRecordResponse]


class TaskStartRequest(BaseModel):
    """Execution start event reported by the agent."""

    tenant_id: str = Field(..., min_length=8, max_length=64)
    asset_id: str = Field(..., min_length=8, max_length=64)
    agent_id: str = Field(..., min_length=8, max_length=64)
    task_id: str = Field(..., min_length=8, max_length=64)
    started_at: datetime


class TaskStartResponse(BaseModel):
    """Response after recording task execution start."""

    status: str
    recorded_at: datetime


class TaskResultRequest(BaseModel):
    """Execution result reported by the agent."""

    tenant_id: str = Field(..., min_length=8, max_length=64)
    asset_id: str = Field(..., min_length=8, max_length=64)
    agent_id: str = Field(..., min_length=8, max_length=64)
    task_id: str = Field(..., min_length=8, max_length=64)
    status: str = Field(..., min_length=3, max_length=32)
    stdout: str | None = None
    stderr: str | None = None
    exit_code: int | None = None
    started_at: datetime
    finished_at: datetime
    duration_ms: int = Field(..., ge=0)
    truncated: bool = False


class TaskResultResponse(BaseModel):
    """Response after recording a task execution result."""

    status: str
    recorded_at: datetime
