"""Detection & Correlation service entry point (MVP-8)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from .config import Settings, load_settings
from .engine import evaluate_event
from .models import (
    DismissFindingRequest,
    DismissFindingResponse,
    DismissalListResponse,
    EventIngestRequest,
    EventIngestResponse,
    FindingListResponse,
    FindingResponse,
    RuleDefinition,
    RuleListResponse,
    RuleResponse,
    SuppressionListResponse,
)
from .rules import default_rules
from .store import init_stores, store
from .validation import validate_event_payload, validate_rule_definition

app = FastAPI(title="Detection & Correlation Service", version="0.1.0")


@app.on_event("startup")
async def startup() -> None:
    settings = load_settings()
    init_stores(settings.retention_events, settings.retention_findings)
    for rule in default_rules():
        validate_rule_definition(rule, settings)
        store.rules.add(rule)


def get_settings() -> Settings:
    """Dependency to load settings once per request."""
    return load_settings()


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


@app.get("/health", response_class=JSONResponse)
async def health_check(settings: Settings = Depends(get_settings)) -> dict:
    """Simple health endpoint for load balancers."""
    return {
        "status": "ok",
        "service": settings.service_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/rules", response_model=RuleListResponse)
async def list_rules(settings: Settings = Depends(get_settings)) -> RuleListResponse:
    """Return all configured rules."""
    if store is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="store_unavailable")
    return RuleListResponse(rules=store.rules.list())


@app.post("/rules", response_model=RuleResponse)
async def add_rule(
    request: Request,
    payload: RuleDefinition,
    settings: Settings = Depends(get_settings),
    client_identity: Optional[str] = Header(None, alias="X-Client-Identity"),
) -> RuleResponse:
    """Register a new rule definition."""
    await enforce_https(request, settings)
    if not client_identity:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="client_identity_required")
    if store is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="store_unavailable")
    if store.rules.get(payload.rule_id):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="rule_already_exists")
    validate_rule_definition(payload, settings)
    store.rules.add(payload)
    return RuleResponse(status="recorded", rule=payload)


@app.post("/events", response_model=EventIngestResponse)
async def ingest_event(
    request: Request,
    payload: EventIngestRequest,
    settings: Settings = Depends(get_settings),
    client_identity: Optional[str] = Header(None, alias="X-Client-Identity"),
) -> EventIngestResponse:
    """Ingest a normalised event and evaluate against rules."""
    await enforce_https(request, settings)
    if not client_identity:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="client_identity_required")
    if store is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="store_unavailable")

    validate_event_payload(payload, settings)
    store.events.add(payload.event)
    findings = evaluate_event(payload.event, payload.context, settings, store)
    return EventIngestResponse(status="processed", findings=findings)


@app.get("/findings", response_model=FindingListResponse)
async def list_findings(
    settings: Settings = Depends(get_settings),
    state: Optional[str] = None,
    severity: Optional[str] = None,
    asset_id: Optional[str] = None,
    identity_id: Optional[str] = None,
    limit: int = 50,
) -> FindingListResponse:
    """List findings with optional filters."""
    if store is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="store_unavailable")
    findings = store.findings.list()
    if state:
        findings = [finding for finding in findings if finding.state == state]
    if severity:
        findings = [finding for finding in findings if finding.severity == severity]
    if asset_id:
        findings = [finding for finding in findings if finding.context_snapshot.asset.asset_id == asset_id]
    if identity_id:
        findings = [finding for finding in findings if finding.context_snapshot.identity.identity_id == identity_id]
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="limit_out_of_range")
    findings = findings[:limit]
    return FindingListResponse(findings=findings)


@app.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: UUID,
    settings: Settings = Depends(get_settings),
) -> FindingResponse:
    """Return a single finding by ID."""
    if store is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="store_unavailable")
    finding = store.findings.get(finding_id)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding_not_found")
    return FindingResponse(status="created", finding=finding)


@app.post("/findings/{finding_id}/dismiss", response_model=DismissFindingResponse)
async def dismiss_finding(
    request: Request,
    finding_id: UUID,
    payload: DismissFindingRequest,
    settings: Settings = Depends(get_settings),
    client_identity: Optional[str] = Header(None, alias="X-Client-Identity"),
) -> DismissFindingResponse:
    """Dismiss a finding with justification and identity."""
    await enforce_https(request, settings)
    if not client_identity:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="client_identity_required")
    if store is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="store_unavailable")
    finding = store.findings.get(finding_id)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding_not_found")
    updated = store.findings.dismiss(finding_id)
    if not updated:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="dismiss_failed")
    store.dismissals.record(
        finding_id=finding_id,
        identity_id=payload.identity_id,
        reason=payload.reason,
        dismissed_at=payload.dismissed_at,
    )
    return DismissFindingResponse(status="dismissed", finding_id=finding_id, dismissed_at=payload.dismissed_at)


@app.get("/suppressions", response_model=SuppressionListResponse)
async def list_suppressions(
    settings: Settings = Depends(get_settings),
    rule_id: Optional[str] = None,
    limit: int = 50,
) -> SuppressionListResponse:
    """List suppression decisions for auditing."""
    if store is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="store_unavailable")
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="limit_out_of_range")
    decisions = store.suppressions.list()
    if rule_id:
        decisions = [decision for decision in decisions if decision.rule_id == rule_id]
    decisions = decisions[:limit]
    return SuppressionListResponse(decisions=decisions)


@app.get("/dismissals", response_model=DismissalListResponse)
async def list_dismissals(
    settings: Settings = Depends(get_settings),
    identity_id: Optional[str] = None,
    limit: int = 50,
) -> DismissalListResponse:
    """List dismissal decisions for auditing."""
    if store is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="store_unavailable")
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="limit_out_of_range")
    decisions = store.dismissals.list()
    if identity_id:
        decisions = [decision for decision in decisions if decision.identity_id == identity_id]
    decisions = decisions[:limit]
    return DismissalListResponse(dismissals=decisions)
