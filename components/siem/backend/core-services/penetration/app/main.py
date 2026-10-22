"""Penetration testing orchestration service entry point (MVP-12)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse


from .engine import build_dispatch_records, build_evidence_payload, hash_payload, normalise_observations
from .models import (
    AbortTestRequest,
    DispatchListResponse,
    EvidenceListResponse,
    EvidenceRecord,
    IntegrationDispatch,
    NormalisedResult,
    PenTestCreateRequest,
    PenTestListResponse,
    PenTestPlan,
    PenTestResponse,
    ResultIngestRequest,
    ResultIngestResponse,
    ResultListResponse,
    Safeguards,
    StartTestRequest,
)
from .store import PenTestStore, build_store
from .validation import (
    ValidationError,
    should_abort_for_credentials,
    should_abort_for_detection,
    validate_plan_request,
    validate_plan_start,
    validate_results_request,
)

app = FastAPI(title="Penetration Test Orchestrator", version="0.1.0")


def get_settings() -> Settings:
    """Dependency to load settings once per request."""
    return load_settings()


def get_store(settings: Settings = Depends(get_settings)) -> PenTestStore:
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
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="https_required")


async def enforce_api_key(
    settings: Settings = Depends(get_settings),
    api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> None:
    """Optional API key enforcement."""
    if settings.api_key and api_key != settings.api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_api_key")


def _parse_plan(payload: dict) -> PenTestPlan:
    return PenTestPlan.model_validate(payload)


def _default_safeguards(request: PenTestCreateRequest, settings: Settings) -> Safeguards:
    allow_list = list({*request.scope.assets, *request.scope.networks})
    return Safeguards(
        target_allow_list=allow_list,
        payload_restrictions=["non_destructive", "detection_only"],
        max_duration_minutes=settings.default_max_duration_minutes,
        rate_limit_per_minute=settings.default_rate_limit_per_minute,
        safe_mode=True,
        abort_on_detection_failure=True,
    )


@app.get("/health", response_class=JSONResponse)
async def health_check(settings: Settings = Depends(get_settings)) -> dict:
    """Simple health endpoint for load balancers."""
    return {
        "status": "ok",
        "service": settings.service_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/tests", response_model=PenTestResponse)
async def create_test_plan(
    request: Request,
    payload: PenTestCreateRequest,
    settings: Settings = Depends(get_settings),
    store: PenTestStore = Depends(get_store),
    _: None = Depends(enforce_api_key),
) -> PenTestResponse:
    """Create a new penetration test plan."""
    await enforce_https(request, settings)

    try:
        validate_plan_request(payload, settings)
    except ValidationError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error

    now = datetime.now(timezone.utc)
    safeguards = payload.safeguards or _default_safeguards(payload, settings)

    plan = PenTestPlan(
        test_id=uuid4(),
        tenant_id=payload.tenant_id,
        scope=payload.scope,
        test_type=payload.test_type,
        method=payload.method,
        credentials=payload.credentials,
        schedule=payload.schedule,
        safeguards=safeguards,
        authorisation=payload.authorisation,
        status="planned",
        created_at=now,
        last_updated_at=now,
    )
    store.record_test(plan)

    return PenTestResponse(status="recorded", test=plan)


@app.get("/tests", response_model=PenTestListResponse)
async def list_tests(
    store: PenTestStore = Depends(get_store),
    tenant_id: Optional[str] = None,
    status_filter: Optional[str] = None,
) -> PenTestListResponse:
    """List recorded test plans."""
    tests = [_parse_plan(plan) for plan in store.list_tests()]
    if tenant_id:
        tests = [plan for plan in tests if plan.tenant_id == tenant_id]
    if status_filter:
        tests = [plan for plan in tests if plan.status == status_filter]
    return PenTestListResponse(tests=tests)


@app.get("/tests/{test_id}", response_model=PenTestResponse)
async def get_test(
    test_id: UUID,
    store: PenTestStore = Depends(get_store),
) -> PenTestResponse:
    """Retrieve a test plan by ID."""
    payload = store.get_test(test_id)
    if not payload:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="test_not_found")
    return PenTestResponse(status="recorded", test=_parse_plan(payload))


@app.post("/tests/{test_id}/start", response_model=PenTestResponse)
async def start_test(
    request: Request,
    test_id: UUID,
    payload: StartTestRequest,
    settings: Settings = Depends(get_settings),
    store: PenTestStore = Depends(get_store),
    _: None = Depends(enforce_api_key),
) -> PenTestResponse:
    """Start a penetration test within its authorised window."""
    await enforce_https(request, settings)

    plan_payload = store.get_test(test_id)
    if not plan_payload:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="test_not_found")
    plan = _parse_plan(plan_payload)

    now = datetime.now(timezone.utc)
    try:
        validate_plan_start(plan, now)
    except ValidationError as error:
        if str(error) == "decommissioned_assets_in_scope":
            plan = plan.model_copy(update={"status": "blocked", "last_updated_at": now})
            store.update_test(plan)
            return PenTestResponse(status="blocked", test=plan, message="decommissioned_assets_in_scope")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error

    plan = plan.model_copy(update={"status": "running", "started_at": now, "last_updated_at": now})
    store.update_test(plan)

    return PenTestResponse(status="recorded", test=plan)


@app.post("/tests/{test_id}/abort", response_model=PenTestResponse)
async def abort_test(
    request: Request,
    test_id: UUID,
    payload: AbortTestRequest,
    settings: Settings = Depends(get_settings),
    store: PenTestStore = Depends(get_store),
    _: None = Depends(enforce_api_key),
) -> PenTestResponse:
    """Abort an in-flight penetration test."""
    await enforce_https(request, settings)

    plan_payload = store.get_test(test_id)
    if not plan_payload:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="test_not_found")
    plan = _parse_plan(plan_payload)

    now = datetime.now(timezone.utc)
    plan = plan.model_copy(update={"status": "aborted", "completed_at": now, "last_updated_at": now})
    store.update_test(plan)

    return PenTestResponse(status="recorded", test=plan, message=payload.reason)


@app.post("/tests/{test_id}/results", response_model=ResultIngestResponse)
async def ingest_results(
    request: Request,
    test_id: UUID,
    payload: ResultIngestRequest,
    settings: Settings = Depends(get_settings),
    store: PenTestStore = Depends(get_store),
    _: None = Depends(enforce_api_key),
) -> ResultIngestResponse:
    """Ingest raw observations and normalise them into results."""
    await enforce_https(request, settings)

    plan_payload = store.get_test(test_id)
    if not plan_payload:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="test_not_found")
    plan = _parse_plan(plan_payload)

    if plan.status != "running":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="test_not_running")

    try:
        validate_results_request(payload, settings)
    except ValidationError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error

    now = datetime.now(timezone.utc)
    if now > plan.schedule.end_at:
        plan = plan.model_copy(update={"status": "aborted", "completed_at": now, "last_updated_at": now})
        store.update_test(plan)
        return ResultIngestResponse(status="aborted", test_id=test_id, result_count=0, message="window_expired")

    if should_abort_for_credentials(payload.observations):
        plan = plan.model_copy(update={"status": "aborted", "completed_at": now, "last_updated_at": now})
        store.update_test(plan)
        return ResultIngestResponse(
            status="aborted",
            test_id=test_id,
            result_count=0,
            message="credential_revoked",
        )

    if should_abort_for_detection(payload.detection_summary, plan.safeguards):
        plan = plan.model_copy(update={"status": "aborted", "completed_at": now, "last_updated_at": now})
        store.update_test(plan)
        return ResultIngestResponse(
            status="aborted",
            test_id=test_id,
            result_count=0,
            message="detection_system_failed",
        )

    existing_results = store.list_results(test_id)
    remaining = settings.max_results_per_test - len(existing_results)
    if remaining <= 0:
        return ResultIngestResponse(
            status="truncated",
            test_id=test_id,
            result_count=0,
            message="result_limit_reached",
        )

    observations = payload.observations[:remaining]
    results = normalise_observations(plan, observations, payload.detection_summary)

    for observation in observations:
        evidence_payload = build_evidence_payload(plan, observation)
        evidence = EvidenceRecord(
            test_id=test_id,
            payload_hash=hash_payload(evidence_payload),
            payload=evidence_payload,
            captured_at=now,
        )
        store.record_evidence(evidence)

    store.trim_evidence(test_id, settings.max_evidence_per_test)
    store.record_results(results)

    dispatches = build_dispatch_records(plan, results, settings)
    store.record_dispatches(dispatches)

    if payload.finalise:
        plan = plan.model_copy(update={"status": "completed", "completed_at": now, "last_updated_at": now})
        store.update_test(plan)

    status_label = "recorded"
    message = None
    if len(payload.observations) > len(observations):
        status_label = "truncated"
        message = "result_limit_reached"

    return ResultIngestResponse(
        status=status_label,
        test_id=test_id,
        result_count=len(results),
        message=message,
    )


@app.get("/tests/{test_id}/results", response_model=ResultListResponse)
async def list_results(
    test_id: UUID,
    store: PenTestStore = Depends(get_store),
) -> ResultListResponse:
    """List normalised results for a test."""
    results = [NormalisedResult.model_validate(payload) for payload in store.list_results(test_id)]
    return ResultListResponse(results=results)


@app.get("/tests/{test_id}/evidence", response_model=EvidenceListResponse)
async def list_evidence(
    test_id: UUID,
    store: PenTestStore = Depends(get_store),
) -> EvidenceListResponse:
    """List immutable evidence records for a test."""
    evidence = [EvidenceRecord.model_validate(payload) for payload in store.list_evidence(test_id)]
    return EvidenceListResponse(evidence=evidence)


@app.get("/tests/{test_id}/dispatches", response_model=DispatchListResponse)
async def list_dispatches(
    test_id: UUID,
    store: PenTestStore = Depends(get_store),
) -> DispatchListResponse:
    """List dispatch records for downstream systems."""
    dispatches = [IntegrationDispatch.model_validate(payload) for payload in store.list_dispatches(test_id)]
    return DispatchListResponse(dispatches=dispatches)
