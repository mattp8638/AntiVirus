"""Identity service entry point.

This service validates signed agent "hello" messages delivered via the
transport layer. It enforces strict request validation and HTTPS-only access.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
import os
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session


from .config import Settings, load_settings
from .certificates import CertificateRecord, registry
from .agents import AgentState, store as agent_store
from .events import HeartbeatEvent, store
from .online import evaluate_presence
from .risk import store as risk_store
from .db import get_db, init_db
from .db_models import AgentRecord, HeartbeatRecord, RiskScoreRecord
from .models import (
    CertificateIssueRequest,
    CertificateIssueResponse,
    CertificateRevokeRequest,
    CertificateRevokeResponse,
    HelloRequest,
    HelloResponse,
    HeartbeatEventResponse,
    AgentStateResponse,
    RiskScoreResponse,
    AgentPresenceResponse,
    TaskCreateRequest,
    TaskCreateResponse,
    TaskPollRequest,
    TaskPollResponse,
    TaskRecordResponse,
    TaskStartRequest,
    TaskStartResponse,
    TaskResultRequest,
    TaskResultResponse,
)
from .security import verify_signature
from .tasks import Task, TaskResult, store as task_store

app = FastAPI(title="Identity Service", version="0.1.0")
cors_origins = tuple(
    origin.strip()
    for origin in os.environ.get(
        "IDENTITY_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


def get_settings() -> Settings:
    """Dependency to load settings once per request."""
    return load_settings()


@app.on_event("startup")
async def startup_db() -> None:
    """Initialise identity database tables on startup."""
    init_db()


async def enforce_https(request: Request) -> None:
    """Reject non-HTTPS requests.

    In production, transport terminates TLS and forwards HTTPS headers.
    """
    # Allow CORS preflight requests to pass through without HTTPS enforcement
    if request.method == "OPTIONS":
        return None
    forwarded_proto = request.headers.get("x-forwarded-proto", "http")
    if forwarded_proto.lower() != "https":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="https_required",
        )


def _require_execution_enabled(settings: Settings) -> None:
    if not settings.tasks_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="execution_disabled",
        )


def _validate_allowlist(settings: Settings, command_payload: str) -> None:
    payload_bytes = command_payload.encode("utf-8")
    if len(payload_bytes) > settings.task_max_payload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="payload_too_large",
        )

    if not settings.task_allowlist_patterns:
        return

    for pattern in settings.task_allowlist_patterns:
        if re.fullmatch(pattern, command_payload):
            return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="command_not_allowlisted",
    )


def _validate_output_limit(settings: Settings, value: Optional[str], field_name: str) -> None:
    if value is None:
        return
    if len(value.encode("utf-8")) > settings.task_max_output_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"{field_name}_too_large",
        )


def _validate_expiry(settings: Settings, expires_at: datetime) -> None:
    if expires_at.tzinfo is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="expiry_requires_timezone",
        )
    now = datetime.now(timezone.utc)
    if expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="expiry_in_past",
        )
    max_expiry = now + timedelta(seconds=settings.task_max_ttl_seconds)
    if expires_at > max_expiry:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="expiry_exceeds_max_ttl",
        )


def _validate_result_timing(settings: Settings, started_at: datetime, finished_at: datetime, duration_ms: int) -> None:
    if started_at.tzinfo is None or finished_at.tzinfo is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="result_requires_timezone",
        )
    if finished_at < started_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_result_timing",
        )
    elapsed_ms = int((finished_at - started_at).total_seconds() * 1000)
    max_duration_ms = settings.task_max_ttl_seconds * 1000
    if duration_ms < 0 or duration_ms > max_duration_ms:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_result_duration",
        )
    if abs(duration_ms - elapsed_ms) > 1000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="duration_mismatch",
        )


def _validate_start_time(started_at: datetime, task: Task) -> None:
    if started_at.tzinfo is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_requires_timezone",
        )
    if started_at < task.created_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_before_created",
        )
    if started_at > task.expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_after_expiry",
        )


def _validate_scope_enabled(settings: Settings, tenant_id: str, asset_id: str) -> None:
    if tenant_id in settings.tasks_disabled_tenants:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="tenant_execution_disabled",
        )
    if asset_id in settings.tasks_disabled_assets:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="asset_execution_disabled",
        )


def _upsert_agent(db: Session, identity_id: str, hostname: str, os_name: str, trust_state: str, last_seen_at: datetime) -> None:
    record = db.get(AgentRecord, identity_id)
    if record:
        record.hostname = hostname
        record.os = os_name
        record.last_seen_at = last_seen_at
        record.trust_state = trust_state
    else:
        db.add(
            AgentRecord(
                identity_id=identity_id,
                hostname=hostname,
                os=os_name,
                last_seen_at=last_seen_at,
                trust_state=trust_state,
            )
        )


def _upsert_risk_score(db: Session, identity_id: str, score: float, rationale: str) -> None:
    record = db.get(RiskScoreRecord, identity_id)
    if record:
        record.score = score
        record.rationale = rationale
    else:
        db.add(
            RiskScoreRecord(
                identity_id=identity_id,
                score=score,
                rationale=rationale,
            )
        )


@app.get("/health", response_class=JSONResponse)
async def health_check(settings: Settings = Depends(get_settings)) -> dict:
    """Simple health endpoint for load balancers."""
    return {
        "status": "ok",
        "service": settings.service_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/status", response_class=JSONResponse)
async def status_check(
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> dict:
    """Expose in-memory store counts for diagnostics."""
    heartbeats = (
        db.query(HeartbeatRecord)
        .order_by(HeartbeatRecord.received_at.desc())
        .limit(100)
        .all()
    )
    agents = db.query(AgentRecord).all()
    scores = db.query(RiskScoreRecord).all()
    last_heartbeat_at = max(
        (event.received_at for event in heartbeats),
        default=None,
    )
    last_agent_seen_at = max(
        (agent.last_seen_at for agent in agents),
        default=None,
    )

    return {
        "service": settings.service_name,
        "storage": "postgres",
        "counts": {
            "heartbeats": len(heartbeats),
            "agents": len(agents),
            "risk_scores": len(scores),
        },
        "last_heartbeat_at": last_heartbeat_at.isoformat() if last_heartbeat_at else None,
        "last_agent_seen_at": last_agent_seen_at.isoformat() if last_agent_seen_at else None,
    }


@app.post("/hello", response_model=HelloResponse)
async def hello(
    request: Request,
    payload: HelloRequest,
    settings: Settings = Depends(get_settings),
    signature: Optional[str] = Header(None, alias="X-Request-Signature"),
    timestamp: Optional[str] = Header(None, alias="X-Request-Timestamp"),
    client_identity: Optional[str] = Header(None, alias="X-Client-Identity"),
    client_cert_fingerprint: Optional[str] = Header(
        None, alias="X-Client-Cert-Sha256"
    ),
    _: None = Depends(enforce_https),
    db: Session = Depends(get_db),
) -> HelloResponse:
    """Accept a signed hello payload and verify its authenticity.

    Transport supplies the client identity and certificate fingerprint.
    """
    if not signature or not timestamp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_signature_headers",
        )

    if not client_identity or not client_cert_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_transport_identity",
        )

    if not registry.is_known(client_cert_fingerprint):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unknown_certificate",
        )

    if registry.is_revoked(client_cert_fingerprint):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="revoked_certificate",
        )

    try:
        timestamp_int = int(timestamp)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_timestamp",
        ) from exc

    raw_body = json.dumps(payload.model_dump(), separators=(",", ":")).encode(
        "utf-8"
    )
    valid, reason = verify_signature(settings, raw_body, signature, timestamp_int)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=reason,
        )

    received_at = datetime.now(timezone.utc)
    store.record(
        HeartbeatEvent(
            event_id=payload.event_id,
            agent_id=payload.identity_id,
            hostname=payload.hostname,
            os=payload.os,
            uptime_seconds=payload.uptime_seconds,
            trust_state=payload.trust_state,
            received_at=received_at,
        )
    )
    agent_store.upsert(
        identity_id=payload.identity_id,
        hostname=payload.hostname,
        os_name=payload.os,
        trust_state=payload.trust_state,
    )
    risk_store.upsert(
        identity_id=payload.identity_id,
        score=0.0,
        rationale="baseline",
    )
    db.add(
        HeartbeatRecord(
            event_id=payload.event_id,
            agent_id=payload.identity_id,
            hostname=payload.hostname,
            os=payload.os,
            uptime_seconds=payload.uptime_seconds,
            trust_state=payload.trust_state,
            received_at=received_at,
        )
    )
    _upsert_agent(
        db,
        identity_id=payload.identity_id,
        hostname=payload.hostname,
        os_name=payload.os,
        trust_state=payload.trust_state,
        last_seen_at=received_at,
    )
    _upsert_risk_score(
        db,
        identity_id=payload.identity_id,
        score=0.0,
        rationale="baseline",
    )
    db.commit()

    return HelloResponse(
        status="verified",
        received_at=datetime.now(timezone.utc),
        service=settings.service_name,
    )


@app.post("/tasks", response_model=TaskCreateResponse)
async def create_task(
    request: Request,
    payload: TaskCreateRequest,
    settings: Settings = Depends(get_settings),
    signature: Optional[str] = Header(None, alias="X-Request-Signature"),
    timestamp: Optional[str] = Header(None, alias="X-Request-Timestamp"),
    _: None = Depends(enforce_https),
) -> TaskCreateResponse:
    """Create a signed, immutable task for remote execution."""
    _require_execution_enabled(settings)
    _validate_scope_enabled(settings, payload.tenant_id, payload.asset_id)

    if not signature or not timestamp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_signature_headers",
        )

    try:
        timestamp_int = int(timestamp)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_timestamp",
        ) from exc

    raw_body = json.dumps(payload.model_dump(), separators=(",", ":")).encode(
        "utf-8"
    )
    valid, reason = verify_signature(settings, raw_body, signature, timestamp_int)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=reason,
        )

    if payload.execution_context.lower() not in {"system", "root"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_execution_context",
        )

    if payload.interpreter.lower() not in {"bash", "powershell"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_interpreter",
        )

    _validate_allowlist(settings, payload.command_payload)

    _validate_expiry(settings, payload.expires_at)

    task = Task(
        task_id=payload.task_id,
        tenant_id=payload.tenant_id,
        asset_id=payload.asset_id,
        issued_by=payload.issued_by,
        policy_reference=payload.policy_reference,
        execution_context=payload.execution_context,
        interpreter=payload.interpreter,
        command_payload=payload.command_payload,
        expires_at=payload.expires_at,
        signature=signature,
    )
    try:
        task_store.create(task)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    return TaskCreateResponse(
        status="created",
        task_id=task.task_id,
        created_at=task.created_at,
    )


@app.post("/tasks/poll", response_model=TaskPollResponse)
async def poll_tasks(
    request: Request,
    payload: TaskPollRequest,
    settings: Settings = Depends(get_settings),
    signature: Optional[str] = Header(None, alias="X-Request-Signature"),
    timestamp: Optional[str] = Header(None, alias="X-Request-Timestamp"),
    _: None = Depends(enforce_https),
) -> TaskPollResponse:
    """Poll for pending tasks for an asset."""
    _require_execution_enabled(settings)
    _validate_scope_enabled(settings, payload.tenant_id, payload.asset_id)

    if not signature or not timestamp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_signature_headers",
        )

    try:
        timestamp_int = int(timestamp)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_timestamp",
        ) from exc

    raw_body = json.dumps(payload.model_dump(), separators=(",", ":")).encode(
        "utf-8"
    )
    valid, reason = verify_signature(settings, raw_body, signature, timestamp_int)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=reason,
        )

    tasks = task_store.list_pending(payload.tenant_id, payload.asset_id)
    for task in tasks:
        task_store.mark_delivered(task.task_id, payload.agent_id)

    return TaskPollResponse(
        status="ok",
        tasks=[
            TaskRecordResponse(
                task_id=task.task_id,
                tenant_id=task.tenant_id,
                asset_id=task.asset_id,
                issued_by=task.issued_by,
                policy_reference=task.policy_reference,
                execution_context=task.execution_context,
                interpreter=task.interpreter,
                command_payload=task.command_payload,
                expires_at=task.expires_at,
            )
            for task in tasks
        ],
    )


@app.post("/tasks/{task_id}/start", response_model=TaskStartResponse)
async def start_task(
    task_id: str,
    request: Request,
    payload: TaskStartRequest,
    settings: Settings = Depends(get_settings),
    signature: Optional[str] = Header(None, alias="X-Request-Signature"),
    timestamp: Optional[str] = Header(None, alias="X-Request-Timestamp"),
    _: None = Depends(enforce_https),
) -> TaskStartResponse:
    """Record the start of a task execution."""
    _require_execution_enabled(settings)
    _validate_scope_enabled(settings, payload.tenant_id, payload.asset_id)

    if not signature or not timestamp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_signature_headers",
        )

    try:
        timestamp_int = int(timestamp)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_timestamp",
        ) from exc

    raw_body = json.dumps(payload.model_dump(), separators=(",", ":")).encode(
        "utf-8"
    )
    valid, reason = verify_signature(settings, raw_body, signature, timestamp_int)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=reason,
        )

    if payload.task_id != task_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="task_id_mismatch",
        )

    task_store.expire_overdue()
    task = task_store.get(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="task_not_found",
        )

    if task.delivered_to_agent and task.delivered_to_agent != payload.agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="task_agent_mismatch",
        )

    if task.tenant_id != payload.tenant_id or task.asset_id != payload.asset_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="task_scope_mismatch",
        )

    _validate_start_time(payload.started_at, task)
    task_store.mark_executing(task_id, payload.started_at)

    return TaskStartResponse(
        status="recorded",
        recorded_at=datetime.now(timezone.utc),
    )


@app.post("/tasks/{task_id}/results", response_model=TaskResultResponse)
async def record_task_result(
    task_id: str,
    request: Request,
    payload: TaskResultRequest,
    settings: Settings = Depends(get_settings),
    signature: Optional[str] = Header(None, alias="X-Request-Signature"),
    timestamp: Optional[str] = Header(None, alias="X-Request-Timestamp"),
    _: None = Depends(enforce_https),
) -> TaskResultResponse:
    """Record the outcome of a task execution."""
    _require_execution_enabled(settings)
    _validate_scope_enabled(settings, payload.tenant_id, payload.asset_id)

    if not signature or not timestamp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_signature_headers",
        )

    try:
        timestamp_int = int(timestamp)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_timestamp",
        ) from exc

    raw_body = json.dumps(payload.model_dump(), separators=(",", ":")).encode(
        "utf-8"
    )
    valid, reason = verify_signature(settings, raw_body, signature, timestamp_int)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=reason,
        )

    if payload.status not in {"completed", "failed"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_result_status",
        )

    if payload.task_id != task_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="task_id_mismatch",
        )

    _validate_result_timing(
        settings,
        payload.started_at,
        payload.finished_at,
        payload.duration_ms,
    )

    _validate_output_limit(settings, payload.stdout, "stdout")
    _validate_output_limit(settings, payload.stderr, "stderr")

    result = TaskResult(
        task_id=task_id,
        status=payload.status,
        stdout=payload.stdout,
        stderr=payload.stderr,
        exit_code=payload.exit_code,
        started_at=payload.started_at,
        finished_at=payload.finished_at,
        duration_ms=payload.duration_ms,
        truncated=payload.truncated,
    )
    task_store.expire_overdue()
    task = task_store.get(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="task_not_found",
        )

    if task.delivered_to_agent and task.delivered_to_agent != payload.agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="task_agent_mismatch",
        )

    if task.tenant_id != payload.tenant_id or task.asset_id != payload.asset_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="task_scope_mismatch",
        )

    try:
        task = task_store.record_result(result)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="task_not_found",
        )

    return TaskResultResponse(
        status="recorded",
        recorded_at=result.recorded_at,
    )


@app.get("/heartbeats", response_model=list[HeartbeatEventResponse])
async def list_heartbeats(db: Session = Depends(get_db)) -> list[HeartbeatEventResponse]:
    """Return recent heartbeat events (in-memory)."""
    events = (
        db.query(HeartbeatRecord)
        .order_by(HeartbeatRecord.received_at.desc())
        .limit(100)
        .all()
    )
    return [
        HeartbeatEventResponse(
            event_id=event.event_id,
            agent_id=event.agent_id,
            hostname=event.hostname,
            os=event.os,
            uptime_seconds=event.uptime_seconds,
            trust_state=event.trust_state,
            received_at=event.received_at,
        )
        for event in events
    ]


@app.get("/agents", response_model=list[AgentStateResponse])
async def list_agents(db: Session = Depends(get_db)) -> list[AgentStateResponse]:
    """Return current agent states (in-memory)."""
    agents = db.query(AgentRecord).all()
    return [
        AgentStateResponse(
            identity_id=agent.identity_id,
            hostname=agent.hostname,
            os=agent.os,
            last_seen_at=agent.last_seen_at,
            trust_state=agent.trust_state,
        )
        for agent in agents
    ]


@app.get("/agents/presence", response_model=list[AgentPresenceResponse])
async def list_agent_presence(
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> list[AgentPresenceResponse]:
    """Return agent online/offline presence based on last seen timestamp."""
    agents = [
        AgentState(
            identity_id=agent.identity_id,
            hostname=agent.hostname,
            os=agent.os,
            last_seen_at=agent.last_seen_at,
            trust_state=agent.trust_state,
        )
        for agent in db.query(AgentRecord).all()
    ]
    presence = evaluate_presence(
        agents,
        settings.heartbeat_offline_threshold_seconds,
    )
    return [
        AgentPresenceResponse(
            identity_id=agent.identity_id,
            hostname=agent.hostname,
            os=agent.os,
            trust_state=agent.trust_state,
            last_seen_at=agent.last_seen_at,
            status=agent.status,
        )
        for agent in presence
    ]


@app.get("/risk-scores", response_model=list[RiskScoreResponse])
async def list_risk_scores(db: Session = Depends(get_db)) -> list[RiskScoreResponse]:
    """Return current risk scores (in-memory)."""
    scores = db.query(RiskScoreRecord).all()
    return [
        RiskScoreResponse(
            identity_id=score.identity_id,
            score=score.score,
            rationale=score.rationale,
        )
        for score in scores
    ]


@app.post("/certificates/issue", response_model=CertificateIssueResponse)
async def issue_certificate(
    payload: CertificateIssueRequest,
    settings: Settings = Depends(get_settings),
    _: None = Depends(enforce_https),
) -> CertificateIssueResponse:
    """Register a new client certificate fingerprint for an identity."""
    issued_at = datetime.now(timezone.utc)
    record = CertificateRecord(
        identity_id=payload.identity_id,
        fingerprint_sha256=payload.fingerprint_sha256,
        issued_at=issued_at,
        expires_at=payload.expires_at,
    )
    registry.issue(record)
    return CertificateIssueResponse(
        status="issued",
        issued_at=issued_at,
        expires_at=payload.expires_at,
    )


@app.post("/certificates/revoke", response_model=CertificateRevokeResponse)
async def revoke_certificate(
    payload: CertificateRevokeRequest,
    settings: Settings = Depends(get_settings),
    _: None = Depends(enforce_https),
) -> CertificateRevokeResponse:
    """Revoke a client certificate fingerprint."""
    record = registry.revoke(payload.fingerprint_sha256, payload.reason)
    if not record or not record.revoked_at:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="certificate_not_found",
        )
    return CertificateRevokeResponse(
        status="revoked",
        revoked_at=record.revoked_at,
    )
