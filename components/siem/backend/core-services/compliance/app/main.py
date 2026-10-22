"""Compliance & audit automation service entry point (MVP-13)."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from .config import Settings, load_settings
from .engine import evaluate_control
from .models import (
    AssessmentResult,
    AssessmentListResponse,
    AssessmentRequest,
    AssessmentResponse,
    AuditBundle,
    AuditBundleRequest,
    AuditBundleResponse,
    ControlCreateRequest,
    ControlDefinition,
    ControlListResponse,
    ControlResponse,
    EvidenceIngestRequest,
    EvidenceListResponse,
    EvidenceRecord,
    ExceptionListResponse,
    ExceptionRecord,
    ExceptionRequest,
    FrameworkMapping,
    FrameworkMappingListResponse,
    FrameworkMappingRequest,
)
from .store import ComplianceStore, build_store
from .validation import (
    ValidationError,
    validate_control_request,
    validate_evidence_request,
    validate_exception_request,
    validate_mapping_request,
)

app = FastAPI(title="Compliance & Audit Automation", version="0.1.0")


def get_settings() -> Settings:
    """Dependency to load settings once per request."""
    return load_settings()


def get_store(settings: Settings = Depends(get_settings)) -> ComplianceStore:
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


def _parse_control(payload: dict) -> ControlDefinition:
    return ControlDefinition.model_validate(payload)


def _parse_evidence(payload: dict) -> EvidenceRecord:
    return EvidenceRecord.model_validate(payload)


def _parse_exception(payload: dict) -> ExceptionRecord:
    return ExceptionRecord.model_validate(payload)


def _parse_mapping(payload: dict) -> FrameworkMapping:
    return FrameworkMapping.model_validate(payload)


@app.get("/health", response_class=JSONResponse)
async def health_check(settings: Settings = Depends(get_settings)) -> dict:
    """Simple health endpoint for load balancers."""
    return {
        "status": "ok",
        "service": settings.service_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/controls", response_model=ControlResponse)
async def create_control(
    request: Request,
    payload: ControlCreateRequest,
    settings: Settings = Depends(get_settings),
    store: ComplianceStore = Depends(get_store),
    _: None = Depends(enforce_api_key),
) -> ControlResponse:
    """Create an immutable control definition."""
    await enforce_https(request, settings)

    try:
        validate_control_request(payload)
    except ValidationError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error

    digest = sha256(payload.control_statement.encode("utf-8")).hexdigest()[:10]
    control_id = f"{payload.framework}-{digest}"
    existing = store.get_control(control_id)
    if existing:
        return ControlResponse(status="exists", control=_parse_control(existing), message="control_exists")

    now = datetime.now(timezone.utc)
    control = ControlDefinition(
        control_id=control_id,
        framework=payload.framework,
        control_statement=payload.control_statement,
        expected_system_behaviour=payload.expected_system_behaviour,
        evidence_sources=payload.evidence_sources,
        assessment_logic=payload.assessment_logic,
        evaluation_frequency_days=payload.evaluation_frequency_days or settings.default_evaluation_frequency_days,
        version=1,
        published_at=now,
    )
    store.record_control(control)

    return ControlResponse(status="recorded", control=control)


@app.get("/controls", response_model=ControlListResponse)
async def list_controls(
    store: ComplianceStore = Depends(get_store),
) -> ControlListResponse:
    """List controls in the system."""
    controls = [_parse_control(control) for control in store.list_controls()]
    return ControlListResponse(controls=controls)


@app.post("/evidence", response_model=EvidenceListResponse)
async def ingest_evidence(
    request: Request,
    payload: EvidenceIngestRequest,
    settings: Settings = Depends(get_settings),
    store: ComplianceStore = Depends(get_store),
    _: None = Depends(enforce_api_key),
) -> EvidenceListResponse:
    """Ingest evidence extracted from upstream system activity."""
    await enforce_https(request, settings)

    try:
        validate_evidence_request(payload)
    except ValidationError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error

    control = store.get_control(payload.control_id)
    if not control:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="control_not_found")

    record = EvidenceRecord(
        control_id=payload.control_id,
        source=payload.source,
        observed_at=payload.observed_at,
        actor=payload.actor,
        attributes=payload.attributes,
        immutable_reference=payload.immutable_reference,
    )
    store.record_evidence(record)
    store.trim_evidence(payload.control_id, settings.max_evidence_records)

    evidence = [_parse_evidence(item) for item in store.list_evidence(payload.control_id)]
    return EvidenceListResponse(evidence=evidence)


@app.get("/controls/{control_id}/evidence", response_model=EvidenceListResponse)
async def list_evidence(
    control_id: str,
    store: ComplianceStore = Depends(get_store),
) -> EvidenceListResponse:
    """List evidence records for a control."""
    evidence = [_parse_evidence(item) for item in store.list_evidence(control_id)]
    return EvidenceListResponse(evidence=evidence)


@app.post("/controls/{control_id}/assess", response_model=AssessmentResponse)
async def assess_control(
    request: Request,
    control_id: str,
    payload: AssessmentRequest,
    settings: Settings = Depends(get_settings),
    store: ComplianceStore = Depends(get_store),
    _: None = Depends(enforce_api_key),
) -> AssessmentResponse:
    """Evaluate a control using current evidence and exceptions."""
    await enforce_https(request, settings)

    control_payload = store.get_control(control_id)
    if not control_payload:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="control_not_found")

    control = _parse_control(control_payload)
    evidence = [_parse_evidence(item) for item in store.list_evidence(control_id)]
    exceptions = [_parse_exception(item) for item in store.list_exceptions(control_id)]
    assessment = evaluate_control(control, evidence, exceptions)

    store.record_assessment(assessment)
    store.trim_assessments(control_id, settings.max_assessments_per_control)

    return AssessmentResponse(status="recorded", assessment=assessment)


@app.get("/controls/{control_id}/assessments", response_model=AssessmentListResponse)
async def list_assessments(
    control_id: str,
    store: ComplianceStore = Depends(get_store),
) -> AssessmentListResponse:
    """List assessment history for a control."""
    assessments = [AssessmentResult.model_validate(item) for item in store.list_assessments(control_id)]
    return AssessmentListResponse(assessments=assessments)


@app.post("/controls/{control_id}/exceptions", response_model=ExceptionListResponse)
async def record_exception(
    request: Request,
    control_id: str,
    payload: ExceptionRequest,
    settings: Settings = Depends(get_settings),
    store: ComplianceStore = Depends(get_store),
    _: None = Depends(enforce_api_key),
) -> ExceptionListResponse:
    """Record a time-bound exception for a control."""
    await enforce_https(request, settings)

    now = datetime.now(timezone.utc)
    try:
        validate_exception_request(payload, now)
    except ValidationError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error

    control_payload = store.get_control(control_id)
    if not control_payload:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="control_not_found")

    record = ExceptionRecord(
        control_id=control_id,
        approved_by=payload.approved_by,
        justification=payload.justification,
        expires_at=payload.expires_at,
        recorded_at=now,
    )
    store.record_exception(record)
    store.trim_exceptions(control_id, settings.max_exceptions_per_control)

    exceptions = [_parse_exception(item) for item in store.list_exceptions(control_id)]
    return ExceptionListResponse(exceptions=exceptions)


@app.get("/controls/{control_id}/exceptions", response_model=ExceptionListResponse)
async def list_exceptions(
    control_id: str,
    store: ComplianceStore = Depends(get_store),
) -> ExceptionListResponse:
    """List exceptions for a control."""
    exceptions = [_parse_exception(item) for item in store.list_exceptions(control_id)]
    return ExceptionListResponse(exceptions=exceptions)


@app.post("/frameworks/mappings", response_model=FrameworkMappingListResponse)
async def map_control(
    request: Request,
    payload: FrameworkMappingRequest,
    settings: Settings = Depends(get_settings),
    store: ComplianceStore = Depends(get_store),
    _: None = Depends(enforce_api_key),
) -> FrameworkMappingListResponse:
    """Map a control to an external framework."""
    await enforce_https(request, settings)

    try:
        validate_mapping_request(payload)
    except ValidationError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error

    if not store.get_control(payload.control_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="control_not_found")

    record = FrameworkMapping(
        control_id=payload.control_id,
        framework=payload.framework,
        mapped_control=payload.mapped_control,
        mapped_at=datetime.now(timezone.utc),
    )
    store.record_mapping(record)

    mappings = [_parse_mapping(item) for item in store.list_mappings(payload.control_id)]
    return FrameworkMappingListResponse(mappings=mappings)


@app.get("/frameworks/mappings", response_model=FrameworkMappingListResponse)
async def list_mappings(
    store: ComplianceStore = Depends(get_store),
    control_id: Optional[str] = None,
) -> FrameworkMappingListResponse:
    """List framework mappings."""
    mappings = [_parse_mapping(item) for item in store.list_mappings(control_id)]
    return FrameworkMappingListResponse(mappings=mappings)


@app.post("/audit/bundles", response_model=AuditBundleResponse)
async def generate_bundle(
    request: Request,
    payload: AuditBundleRequest,
    settings: Settings = Depends(get_settings),
    store: ComplianceStore = Depends(get_store),
    _: None = Depends(enforce_api_key),
) -> AuditBundleResponse:
    """Generate an immutable audit bundle snapshot."""
    await enforce_https(request, settings)

    controls = [_parse_control(control) for control in store.list_controls()]
    assessments = []
    evidence: list[EvidenceRecord] = []
    exceptions: list[ExceptionRecord] = []

    for control in controls:
        assessments.extend(
            AssessmentResult.model_validate(item) for item in store.list_assessments(control.control_id)
        )
        evidence.extend(_parse_evidence(item) for item in store.list_evidence(control.control_id))
        exceptions.extend(_parse_exception(item) for item in store.list_exceptions(control.control_id))

    bundle = AuditBundle(
        scope=payload.scope,
        controls=controls,
        assessments=assessments,
        evidence=evidence,
        exceptions=exceptions,
        generated_at=datetime.now(timezone.utc),
    )
    store.record_bundle(bundle)

    return AuditBundleResponse(status="recorded", bundle=bundle)
