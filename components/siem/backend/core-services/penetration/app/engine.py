"""Normalisation and integration helpers for MVP-12."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256

from .models import (
    DetectionResponseSummary,
    IntegrationDispatch,
    NormalisedResult,
    Observation,
    PenTestPlan,
)


def compute_risk_rating(
    confidence: float,
    *,
    test_type: str,
    method: str,
    detection_summary: DetectionResponseSummary,
) -> str:
    """Compute risk rating without trusting external tool scores."""
    score = confidence
    if method == "simulate":
        score += 0.1
    if test_type == "auth":
        score += 0.05
    if detection_summary.defences_failed:
        score += 0.1
    if detection_summary.detection_system_status == "failed":
        score -= 0.2

    score = max(0.0, min(score, 1.0))
    if score >= 0.9:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.55:
        return "medium"
    if score >= 0.35:
        return "low"
    return "info"


def normalise_observations(
    plan: PenTestPlan,
    observations: list[Observation],
    detection_summary: DetectionResponseSummary,
) -> list[NormalisedResult]:
    """Normalise raw observations into deterministic results."""
    results: list[NormalisedResult] = []
    now = datetime.now(timezone.utc)
    for observation in observations:
        risk_rating = compute_risk_rating(
            observation.confidence,
            test_type=plan.test_type,
            method=plan.method,
            detection_summary=detection_summary,
        )
        context = {
            "test_type": plan.test_type,
            "method": plan.method,
            "scope_assets": plan.scope.assets,
            "scope_networks": plan.scope.networks,
            "external_severity_ignored": bool(observation.external_severity),
            "attack_stage": observation.attack_stage,
        }
        results.append(
            NormalisedResult(
                test_id=plan.test_id,
                weakness_id=observation.weakness_id,
                asset_id=observation.asset_id,
                summary=observation.summary,
                evidence=observation.evidence,
                confidence=observation.confidence,
                risk_rating=risk_rating,
                context=context,
                detection_summary=detection_summary,
                created_at=now,
            )
        )
    return results


def build_evidence_payload(plan: PenTestPlan, observation: Observation) -> dict:
    """Create evidence payload for hashing and immutable storage."""
    return {
        "test_id": str(plan.test_id),
        "asset_id": observation.asset_id,
        "weakness_id": observation.weakness_id,
        "summary": observation.summary,
        "evidence": observation.evidence,
        "confidence": observation.confidence,
        "observed_at": observation.observed_at.isoformat(),
        "external_severity": observation.external_severity,
        "credential_state": observation.credential_state,
    }


def hash_payload(payload: dict) -> str:
    """Hash evidence payload for tamper detection."""
    encoded = sha256()
    encoded.update(str(payload).encode("utf-8"))
    return encoded.hexdigest()


def build_dispatch_records(
    plan: PenTestPlan,
    results: list[NormalisedResult],
    settings: Settings,
) -> list[IntegrationDispatch]:
    """Build dispatch records for downstream services."""
    status = "queued"
    if settings.integration_mode == "simulate_outage":
        status = "degraded"
    if settings.integration_mode == "disabled":
        return []

    now = datetime.now(timezone.utc)
    preview = {
        "test_id": str(plan.test_id),
        "result_count": len(results),
        "risk_ratings": [result.risk_rating for result in results],
    }
    return [
        IntegrationDispatch(
            test_id=plan.test_id,
            target=target,
            status=status,
            recorded_at=now,
            payload_preview=preview,
        )
        for target in ("vulnerability", "detection", "psa")
    ]
