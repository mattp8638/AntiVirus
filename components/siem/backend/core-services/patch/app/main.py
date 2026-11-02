"""Patch management service entry point."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from .config import Settings, load_settings
from .evidence import build_evidence
from .models import (
    AssetBlockRequest,
    AssetBlockResponse,
    AssetPatchState,
    AssetHistoryRecord,
    AssetUnblockRequest,
    AssetUnblockResponse,
    ComplianceSummary,
    DetectionBatch,
    DetectionResponse,
    EvidenceResponse,
    EvidenceRecord,
    EvidenceHashResponse,
    ExecutionPlan,
    ExecutionPlanRequest,
    ExecutionPlanResponse,
    ExecutionResultRequest,
    ExecutionResultResponse,
    PlanCheckRequest,
    PlanCheckResponse,
    PlanRebootRequest,
    PlanRebootResponse,
    PlanRollbackRequest,
    PlanRollbackResponse,
    PlanStartRequest,
    PlanStartResponse,
    PatchPolicy,
    PolicyResponse,
    TaskManifest,
    NextWindowResponse,
)
from .policy import evaluate_patches, next_maintenance_window
from .evidence import _hash_evidence
from .scheduler import build_execution_plan
from .store import PatchStore, build_store
from .tasks import build_task_manifest

app = FastAPI(title="Patch Management Service", version="0.1.0")


def get_settings() -> Settings:
    """Dependency to load settings once per request."""
    return load_settings()


def get_store(settings: Settings = Depends(get_settings)) -> PatchStore:
    """Dependency to access the storage backend."""
    if not hasattr(get_store, "_store"):
        get_store._store = build_store(settings.storage_path)  # type: ignore[attr-defined]
    return get_store._store  # type: ignore[attr-defined]


async def enforce_https(request: Request) -> None:
    """Reject non-HTTPS requests."""
    forwarded_proto = request.headers.get("x-forwarded-proto", "http")
    # Allow CORS preflight requests to pass through without HTTPS enforcement
    if request.method == "OPTIONS":
        return None
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


def _validate_log_limit(settings: Settings, value: Optional[str], field_name: str) -> None:
    if value is None:
        return
    if len(value.encode("utf-8")) > settings.max_log_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"{field_name}_too_large",
        )


def _map_detection_reboot_requirements(detection: DetectionBatch) -> dict[str, bool]:
    return {patch.patch_id: patch.requires_reboot for patch in detection.patches}


def _validate_results(
    plan: ExecutionPlan,
    results: list,
    detection: DetectionBatch,
    reboot_confirmed: bool,
) -> None:
    patch_ids = [result.patch_id for result in results]
    if len(set(patch_ids)) != len(patch_ids):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="duplicate_result_patch_ids",
        )
    missing = set(plan.execution_order) - set(patch_ids)
    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_result_patches",
        )
    reboot_required = _map_detection_reboot_requirements(detection)
    requires_reboot = any(reboot_required.get(patch_id) for patch_id in plan.execution_order)
    if requires_reboot and not reboot_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="reboot_required_not_confirmed",
        )


def _latest_detection_by_asset(detections: list[dict]) -> dict[str, dict]:
    latest: dict[str, dict] = {}
    for detection in detections:
        asset_id = detection.get("asset_id")
        if not asset_id:
            continue
        detected_at = detection.get("detected_at")
        if asset_id not in latest or detected_at > latest[asset_id].get("detected_at"):
            latest[asset_id] = detection
    return latest


def _compute_compliance_summary(tenant_id: str, store: PatchStore) -> ComplianceSummary:
    detections = store.list_detections()
    latest = _latest_detection_by_asset(detections)
    compliant = 0
    pending = 0
    failed = 0
    for asset_id, detection in latest.items():
        if detection.get("tenant_id") != tenant_id:
            continue
        asset_state = store.get_asset_state(asset_id)
        if asset_state and asset_state.get("status") == "patch_blocked":
            failed += 1
            continue
        patches = detection.get("patches", [])
        if not patches:
            compliant += 1
        else:
            pending += 1
    return ComplianceSummary(
        tenant_id=tenant_id,
        compliant=compliant,
        pending=pending,
        failed=failed,
    )


@app.get("/health", response_class=JSONResponse)
async def health_check(settings: Settings = Depends(get_settings)) -> dict:
    """Simple health endpoint for load balancers."""
    return {
        "status": "ok",
        "service": settings.service_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/detections", response_model=DetectionResponse)
async def record_detection(
    payload: DetectionBatch,
    settings: Settings = Depends(get_settings),
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> DetectionResponse:
    """Record an agent patch detection payload (read-only)."""
    if len(payload.patches) > settings.max_patches_per_batch:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="patch_batch_too_large",
        )
    try:
        store.record_detection(payload)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return DetectionResponse(status="recorded", detection_id=payload.detection_id)


@app.get("/detections/{detection_id}", response_model=DetectionBatch)
async def get_detection(
    detection_id: UUID,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> DetectionBatch:
    """Retrieve a stored detection batch."""
    stored = store.get_detection(detection_id)
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="detection_not_found",
        )
    return DetectionBatch.model_validate(stored)


@app.post("/policies", response_model=PolicyResponse)
async def record_policy(
    payload: PatchPolicy,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> PolicyResponse:
    """Record a signed patch policy definition."""
    try:
        store.record_policy(payload)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return PolicyResponse(status="recorded", policy_id=payload.policy_id)


@app.get("/policies/{policy_id}", response_model=PatchPolicy)
async def get_policy(
    policy_id: UUID,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> PatchPolicy:
    stored = store.get_policy(policy_id)
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="policy_not_found",
        )
    return PatchPolicy.model_validate(stored)


@app.post("/plans", response_model=ExecutionPlanResponse)
async def create_plan(
    payload: ExecutionPlanRequest,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> ExecutionPlanResponse:
    """Generate a policy-driven execution plan."""
    detection_data = store.get_detection(payload.detection_id)
    if not detection_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="detection_not_found",
        )
    policy_data = store.get_policy(payload.policy_id)
    if not policy_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="policy_not_found",
        )
    detection = DetectionBatch.model_validate(detection_data)
    policy = PatchPolicy.model_validate(policy_data)

    if detection.tenant_id != payload.tenant_id or detection.asset_id != payload.asset_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="detection_scope_mismatch",
        )
    if policy.tenant_id != payload.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="policy_scope_mismatch",
        )
    if policy.asset_ids and payload.asset_id not in policy.asset_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="policy_asset_not_allowed",
        )

    eligibility = evaluate_patches(policy, detection.patches)
    plan = build_execution_plan(
        plan_id=payload.plan_id,
        tenant_id=payload.tenant_id,
        asset_id=payload.asset_id,
        policy=policy,
        detection_id=payload.detection_id,
        eligibility=eligibility,
    )
    try:
        store.record_plan(plan)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return ExecutionPlanResponse(status="planned", plan=plan)


@app.post("/plans/{plan_id}/start", response_model=PlanStartResponse)
async def start_plan(
    plan_id: UUID,
    payload: PlanStartRequest,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> PlanStartResponse:
    """Mark an execution plan as executing."""
    plan_data = store.get_plan(plan_id)
    if not plan_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="plan_not_found",
        )
    plan = ExecutionPlan.model_validate(plan_data)
    if plan.tenant_id != payload.tenant_id or plan.asset_id != payload.asset_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="plan_scope_mismatch",
        )
    plan.status = "executing"
    store.update_plan(plan)
    return PlanStartResponse(status="executing", plan_id=plan_id, started_at=payload.started_at)


@app.post("/plans/{plan_id}/checks", response_model=PlanCheckResponse)
async def record_plan_checks(
    plan_id: UUID,
    payload: PlanCheckRequest,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> PlanCheckResponse:
    """Record pre/post-check results for a plan."""
    plan_data = store.get_plan(plan_id)
    if not plan_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="plan_not_found",
        )
    plan = ExecutionPlan.model_validate(plan_data)
    if plan.tenant_id != payload.tenant_id or plan.asset_id != payload.asset_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="plan_scope_mismatch",
        )
    if payload.phase == "pre":
        plan.pre_check_results.extend(payload.checks)
    else:
        plan.post_check_results.extend(payload.checks)
    store.update_plan(plan)
    return PlanCheckResponse(status="recorded", plan_id=plan_id)


@app.post("/plans/{plan_id}/rollback", response_model=PlanRollbackResponse)
async def record_plan_rollback(
    plan_id: UUID,
    payload: PlanRollbackRequest,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> PlanRollbackResponse:
    """Record rollback actions executed for a plan."""
    plan_data = store.get_plan(plan_id)
    if not plan_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="plan_not_found",
        )
    plan = ExecutionPlan.model_validate(plan_data)
    if plan.tenant_id != payload.tenant_id or plan.asset_id != payload.asset_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="plan_scope_mismatch",
        )
    plan.rollback_actions.extend(payload.actions)
    store.update_plan(plan)
    return PlanRollbackResponse(status="recorded", plan_id=plan_id)


@app.post("/plans/{plan_id}/reboot", response_model=PlanRebootResponse)
async def record_plan_reboot(
    plan_id: UUID,
    payload: PlanRebootRequest,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> PlanRebootResponse:
    """Record reboot lifecycle events for a plan."""
    plan_data = store.get_plan(plan_id)
    if not plan_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="plan_not_found",
        )
    plan = ExecutionPlan.model_validate(plan_data)
    if plan.tenant_id != payload.tenant_id or plan.asset_id != payload.asset_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="plan_scope_mismatch",
        )
    plan.reboot_events.append(payload.event)
    store.update_plan(plan)
    return PlanRebootResponse(status="recorded", plan_id=plan_id)


@app.get("/plans/{plan_id}", response_model=ExecutionPlan)
async def get_plan(
    plan_id: UUID,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> ExecutionPlan:
    stored = store.get_plan(plan_id)
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="plan_not_found",
        )
    return ExecutionPlan.model_validate(stored)


@app.post("/plans/{plan_id}/results", response_model=ExecutionResultResponse)
async def record_results(
    plan_id: UUID,
    payload: ExecutionResultRequest,
    settings: Settings = Depends(get_settings),
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> ExecutionResultResponse:
    """Record execution results and verification outcomes."""
    if payload.plan_id != plan_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="plan_id_mismatch",
        )

    plan_data = store.get_plan(plan_id)
    if not plan_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="plan_not_found",
        )
    detection_data = store.get_detection(UUID(plan_data["detection_id"]))
    policy_data = store.get_policy(UUID(plan_data["policy_id"]))
    if not detection_data or not policy_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="plan_dependencies_missing",
        )

    plan = ExecutionPlan.model_validate(plan_data)
    detection = DetectionBatch.model_validate(detection_data)
    policy = PatchPolicy.model_validate(policy_data)

    if plan.tenant_id != payload.tenant_id or plan.asset_id != payload.asset_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="plan_scope_mismatch",
        )

    for result in payload.results:
        _validate_log_limit(settings, result.stdout, "stdout")
        _validate_log_limit(settings, result.stderr, "stderr")
        if result.patch_id not in plan.execution_order:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="result_patch_not_in_plan",
            )
        if result.status == "failed" and not result.failure_type:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="failure_type_required",
            )

    _validate_results(plan, payload.results, detection, payload.reboot_confirmed)

    failed = any(result.status == "failed" for result in payload.results)
    if payload.verification_status == "passed" and not failed:
        plan.status = "completed"
    else:
        plan.status = "failed"

    store.update_plan(plan)

    evidence = build_evidence(
        plan=plan,
        detection=detection,
        policy=policy,
        results=payload.results,
        reboot_confirmed=payload.reboot_confirmed,
        verification_status=payload.verification_status,
        verification_notes=payload.verification_notes,
        started_at=payload.started_at,
        finished_at=payload.finished_at,
    )
    try:
        store.record_evidence(evidence)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    if failed or payload.verification_status == "failed":
        asset_state = AssetPatchState(
            tenant_id=payload.tenant_id,
            asset_id=payload.asset_id,
            status="patch_blocked",
            reason="execution_or_verification_failed",
            recorded_at=datetime.now(timezone.utc),
        )
        store.record_asset_state(payload.asset_id, asset_state.model_dump())

    return ExecutionResultResponse(status="recorded", plan_status=plan.status)


@app.post("/assets/block", response_model=AssetBlockResponse)
async def block_asset(
    payload: AssetBlockRequest,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> AssetBlockResponse:
    """Block patching for an asset after a failure event."""
    asset_state = AssetPatchState(
        tenant_id=payload.tenant_id,
        asset_id=payload.asset_id,
        status="patch_blocked",
        reason=payload.reason,
        recorded_at=payload.recorded_at,
    )
    store.record_asset_state(payload.asset_id, asset_state.model_dump())
    return AssetBlockResponse(status="blocked", asset_state=asset_state)


@app.post("/assets/unblock", response_model=AssetUnblockResponse)
async def unblock_asset(
    payload: AssetUnblockRequest,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> AssetUnblockResponse:
    """Restore an asset to a normal patching state."""
    asset_state = AssetPatchState(
        tenant_id=payload.tenant_id,
        asset_id=payload.asset_id,
        status="normal",
        reason=payload.reason,
        recorded_at=payload.recorded_at,
    )
    store.record_asset_state(payload.asset_id, asset_state.model_dump())
    return AssetUnblockResponse(status="unblocked", asset_state=asset_state)


@app.get("/assets/{asset_id}/state", response_model=AssetPatchState)
async def get_asset_state(
    asset_id: str,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> AssetPatchState:
    """Retrieve the current patch state for an asset."""
    stored = store.get_asset_state(asset_id)
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="asset_state_not_found",
        )
    return AssetPatchState.model_validate(stored)


@app.get("/assets/{asset_id}/history", response_model=list[AssetHistoryRecord])
async def get_asset_history(
    asset_id: str,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> list[AssetHistoryRecord]:
    """Return patch execution history for an asset."""
    records = []
    for record in store.list_evidence_by_asset(asset_id):
        records.append(
            AssetHistoryRecord(
                plan_id=UUID(record["plan_id"]),
                status=record["plan_snapshot"]["status"],
                recorded_at=datetime.fromisoformat(record["recorded_at"]),
                verification_status=record["verification_status"],
                reboot_confirmed=record["reboot_confirmed"],
            )
        )
    return records


@app.get("/compliance/{tenant_id}", response_model=ComplianceSummary)
async def get_compliance_summary(
    tenant_id: str,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> ComplianceSummary:
    """Return a compliance summary for a tenant."""
    return _compute_compliance_summary(tenant_id, store)


@app.get("/policies/{policy_id}/next-window", response_model=NextWindowResponse)
async def get_next_window(
    policy_id: UUID,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> NextWindowResponse:
    """Return the next maintenance window for a policy."""
    stored = store.get_policy(policy_id)
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="policy_not_found",
        )
    policy = PatchPolicy.model_validate(stored)
    now = datetime.now(timezone.utc)
    return NextWindowResponse(
        policy_id=policy_id,
        next_window_start=next_maintenance_window(now, policy.maintenance_windows),
    )


@app.get("/plans/{plan_id}/tasks", response_model=TaskManifest)
async def get_task_manifest(
    plan_id: UUID,
    issued_by: str,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> TaskManifest:
    """Return a deterministic task manifest for MVP-5 execution."""
    plan_data = store.get_plan(plan_id)
    if not plan_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="plan_not_found",
        )
    plan = ExecutionPlan.model_validate(plan_data)
    return build_task_manifest(plan, issued_by=issued_by)


@app.get("/evidence/{plan_id}", response_model=EvidenceResponse)
async def get_evidence(
    plan_id: UUID,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> EvidenceResponse:
    """Retrieve immutable evidence for a plan."""
    stored = store.get_evidence(plan_id)
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="evidence_not_found",
        )
    return EvidenceResponse(
        status="ok",
        evidence=EvidenceRecord.model_validate(stored),
    )


@app.get("/evidence/{plan_id}/hash", response_model=EvidenceHashResponse)
async def get_evidence_hash(
    plan_id: UUID,
    store: PatchStore = Depends(get_store),
    _: None = Depends(enforce_https),
    __: None = Depends(enforce_api_key),
) -> EvidenceHashResponse:
    """Return the evidence hash for a plan."""
    stored = store.get_evidence(plan_id)
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="evidence_not_found",
        )
    record = EvidenceRecord.model_validate(stored)
    evidence_hash = record.evidence_hash or _hash_evidence(record)
    return EvidenceHashResponse(status="ok", plan_id=plan_id, evidence_hash=evidence_hash)
