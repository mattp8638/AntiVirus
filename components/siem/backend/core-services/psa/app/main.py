"""PSA workflow engine entry point (MVP-11)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from .config import Settings, load_settings
from .engine import compute_priority, compute_sla_deadline
from .evidence import build_hash
from .models import (
    ActionListResponse,
    ActionRecord,
    ActionRequest,
    EvidenceListResponse,
    EvidenceRecord,
    IntakeResponse,
    ResolveRequest,
    TicketIntakeRequest,
    TicketListResponse,
    TicketRecord,
    TicketResponse,
)
from .store import PsaStore, build_store

app = FastAPI(title="PSA Workflow Engine", version="0.1.0")


def get_settings() -> Settings:
    """Dependency to load settings once per request."""
    return load_settings()


def get_store(settings: Settings = Depends(get_settings)) -> PsaStore:
    """Dependency to access the storage backend."""
    if not hasattr(get_store, "_store"):
        get_store._store = build_store(settings.storage_path)  # type: ignore[attr-defined]
    return get_store._store  # type: ignore[attr-defined]


async def enforce_https(request: Request, settings: Settings) -> None:
    """Reject non-HTTPS requests when configured."""
    # Allow CORS preflight requests to pass through without HTTPS enforcement
    if request.method == "OPTIONS":
        return None
    if not settings.https_enforced:
        return
    forwarded_proto = request.headers.get("x-forwarded-proto", "http")
    if forwarded_proto.lower() != "https":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="https_required",
        )


async def enforce_api_key(
    settings: Settings = Depends(get_settings),
    api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> None:
    """Optional API key enforcement."""
    if settings.api_key and api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_api_key",
        )


def _parse_ticket(payload: dict) -> TicketRecord:
    return TicketRecord.model_validate(payload)


def _parse_action(payload: dict) -> ActionRecord:
    return ActionRecord.model_validate(payload)


def _parse_evidence(payload: dict) -> EvidenceRecord:
    return EvidenceRecord.model_validate(payload)


def _priority_rank(priority: str) -> int:
    return {"p1": 1, "p2": 2, "p3": 3, "p4": 4}.get(priority, 5)


@app.get("/health", response_class=JSONResponse)
async def health_check(settings: Settings = Depends(get_settings)) -> dict:
    """Simple health endpoint for load balancers."""
    return {
        "status": "ok",
        "service": settings.service_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/intake", response_model=IntakeResponse)
async def intake_ticket(
    request: Request,
    payload: TicketIntakeRequest,
    settings: Settings = Depends(get_settings),
    store: PsaStore = Depends(get_store),
    _: None = Depends(enforce_api_key),
) -> IntakeResponse:
    """Create or update a ticket from system intelligence."""
    await enforce_https(request, settings)

    if payload.risk_score < settings.risk_threshold:
        return IntakeResponse(status="suppressed", message="risk_below_threshold")

    existing = store.find_ticket_by_source(
        tenant_id=payload.tenant_id,
        asset_id=payload.asset_id,
        source_type=payload.source_type,
        source_reference_id=payload.source_reference_id,
    )

    now = datetime.now(timezone.utc)
    priority = compute_priority(
        payload.risk_score,
        payload.asset_criticality,
        payload.exposure_level,
        payload.time_sensitivity,
    )
    sla_deadline = compute_sla_deadline(priority, now=now)

    if existing:
        ticket = _parse_ticket(existing)
        reopened = ticket.status == "resolved"
        ticket = ticket.model_copy(
            update={
                "risk_score": payload.risk_score,
                "priority": priority,
                "sla_deadline": sla_deadline,
                "last_updated_at": now,
                "status": "open" if reopened else ticket.status,
                "system_recommendation": payload.system_recommendation or ticket.system_recommendation,
            }
        )
        store.update_ticket(ticket)
        if reopened:
            store.record_action(
                ActionRecord(
                    ticket_id=ticket.ticket_id,
                    action_type="acknowledge",
                    actor_identity="system",
                    timestamp=now,
                    justification="reopened_by_new_evidence",
                )
            )
    else:
        ticket = TicketRecord(
            tenant_id=payload.tenant_id,
            source_type=payload.source_type,
            source_reference_id=payload.source_reference_id,
            asset_id=payload.asset_id,
            risk_score=payload.risk_score,
            priority=priority,
            status="open",
            sla_deadline=sla_deadline,
            creation_timestamp=now,
            last_updated_at=now,
            system_recommendation=payload.system_recommendation,
        )
        store.record_ticket(ticket)

    existing_hashes = store.list_evidence_hashes(ticket.ticket_id)
    for evidence in payload.evidence:
        evidence_payload = {
            "linked_object_type": evidence.linked_object_type,
            "linked_object_id": evidence.linked_object_id,
            "immutable_reference": evidence.immutable_reference,
            "payload": evidence.payload or {},
        }
        evidence_hash = build_hash(evidence_payload)
        if evidence_hash in existing_hashes:
            continue
        store.record_evidence(
            EvidenceRecord(
                ticket_id=ticket.ticket_id,
                linked_object_type=evidence.linked_object_type,
                linked_object_id=evidence.linked_object_id,
                immutable_reference=evidence.immutable_reference,
                hash_sha256=evidence_hash,
                captured_at=now,
                payload=evidence.payload,
            )
        )
        existing_hashes.add(evidence_hash)
    store.trim_evidence(ticket.ticket_id, settings.max_evidence_per_ticket)

    return IntakeResponse(status="recorded", ticket_id=ticket.ticket_id)


@app.post("/intake/resolve", response_model=IntakeResponse)
async def resolve_ticket(
    request: Request,
    payload: ResolveRequest,
    settings: Settings = Depends(get_settings),
    store: PsaStore = Depends(get_store),
    _: None = Depends(enforce_api_key),
) -> IntakeResponse:
    """Resolve a ticket from upstream system intelligence."""
    await enforce_https(request, settings)

    existing = store.find_ticket_by_source(
        tenant_id=payload.tenant_id,
        asset_id=payload.asset_id,
        source_type=payload.source_type,
        source_reference_id=payload.source_reference_id,
    )
    if not existing:
        return IntakeResponse(status="ignored", message="ticket_not_found")

    ticket = _parse_ticket(existing)
    if ticket.status == "resolved":
        return IntakeResponse(status="ignored", ticket_id=ticket.ticket_id, message="already_resolved")

    now = payload.resolved_at
    ticket = ticket.model_copy(update={"status": "resolved", "last_updated_at": now})
    store.update_ticket(ticket)
    store.record_action(
        ActionRecord(
            ticket_id=ticket.ticket_id,
            action_type="acknowledge",
            actor_identity="system",
            timestamp=now,
            justification=payload.resolution_note or "resolved_upstream",
        )
    )
    store.trim_actions(ticket.ticket_id, settings.max_actions_per_ticket)

    return IntakeResponse(status="resolved", ticket_id=ticket.ticket_id)


@app.get("/tickets", response_model=TicketListResponse)
async def list_tickets(
    settings: Settings = Depends(get_settings),
    store: PsaStore = Depends(get_store),
    tenant_id: Optional[str] = None,
    status_filter: Optional[str] = None,
) -> TicketListResponse:
    """Return the ticket queue sorted by priority and SLA deadline."""
    tickets = [_parse_ticket(ticket) for ticket in store.list_tickets()]
    if tenant_id:
        tickets = [ticket for ticket in tickets if ticket.tenant_id == tenant_id]
    if status_filter:
        tickets = [ticket for ticket in tickets if ticket.status == status_filter]

    tickets.sort(key=lambda ticket: (_priority_rank(ticket.priority), ticket.sla_deadline))
    return TicketListResponse(tickets=tickets)


@app.get("/tickets/{ticket_id}", response_model=TicketResponse)
async def get_ticket(
    ticket_id: UUID,
    store: PsaStore = Depends(get_store),
) -> TicketResponse:
    """Return a ticket by ID."""
    ticket_payload = store.get_ticket(ticket_id)
    if not ticket_payload:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ticket_not_found")
    return TicketResponse(status="ok", ticket=_parse_ticket(ticket_payload))


@app.post("/tickets/{ticket_id}/actions", response_model=ActionListResponse)
async def record_action(
    request: Request,
    ticket_id: UUID,
    payload: ActionRequest,
    settings: Settings = Depends(get_settings),
    store: PsaStore = Depends(get_store),
    _: None = Depends(enforce_api_key),
) -> ActionListResponse:
    """Record a human action for a ticket."""
    await enforce_https(request, settings)

    ticket_payload = store.get_ticket(ticket_id)
    if not ticket_payload:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ticket_not_found")
    ticket = _parse_ticket(ticket_payload)

    if ticket.status == "resolved":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="ticket_resolved")

    status_map = {
        "acknowledge": "acknowledged",
        "remediate": "remediation_in_progress",
        "defer": "deferred",
        "accept_risk": "accepted_risk",
        "escalate": "escalated",
    }
    new_status = status_map[payload.action_type]
    now = datetime.now(timezone.utc)

    action = ActionRecord(
        ticket_id=ticket.ticket_id,
        action_type=payload.action_type,
        actor_identity=payload.actor_identity,
        approver_identity=payload.approver_identity,
        timestamp=now,
        justification=payload.justification,
        automation_request_id=payload.automation_request_id,
    )
    store.record_action(action)

    ticket = ticket.model_copy(update={"status": new_status, "last_updated_at": now})
    store.update_ticket(ticket)
    store.trim_actions(ticket.ticket_id, settings.max_actions_per_ticket)

    actions = [_parse_action(record) for record in store.list_actions(ticket_id)]
    return ActionListResponse(actions=actions)


@app.get("/tickets/{ticket_id}/actions", response_model=ActionListResponse)
async def list_actions(
    ticket_id: UUID,
    store: PsaStore = Depends(get_store),
) -> ActionListResponse:
    """List recorded actions for a ticket."""
    actions = [_parse_action(record) for record in store.list_actions(ticket_id)]
    return ActionListResponse(actions=actions)


@app.get("/tickets/{ticket_id}/evidence", response_model=EvidenceListResponse)
async def list_evidence(
    ticket_id: UUID,
    store: PsaStore = Depends(get_store),
) -> EvidenceListResponse:
    """List evidence records for a ticket."""
    evidence = [_parse_evidence(record) for record in store.list_evidence(ticket_id)]
    return EvidenceListResponse(evidence=evidence)
