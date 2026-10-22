"""Evidence capture helpers."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .models import (
    DetectionBatch,
    EvidenceRecord,
    ExecutionPlan,
    ExecutionResult,
    PatchPolicy,
    VerificationStatus,
)


def build_evidence(
    *,
    plan: ExecutionPlan,
    detection: DetectionBatch,
    policy: PatchPolicy,
    results: list[ExecutionResult],
    reboot_confirmed: bool,
    verification_status: VerificationStatus,
    verification_notes: str | None,
    started_at: datetime,
    finished_at: datetime,
) -> EvidenceRecord:
    """Assemble immutable evidence of a patch execution cycle."""
    record = EvidenceRecord(
        plan_id=plan.plan_id,
        detection_snapshot=detection,
        policy_snapshot=policy,
        plan_snapshot=plan,
        results=results,
        reboot_confirmed=reboot_confirmed,
        verification_status=verification_status,
        verification_notes=verification_notes,
        recorded_at=datetime.now(timezone.utc),
        started_at=started_at,
        finished_at=finished_at,
    )
    record.evidence_hash = _hash_evidence(record)
    return record


def _hash_evidence(record: EvidenceRecord) -> str:
    payload = record.model_dump(exclude={"evidence_hash"})
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
