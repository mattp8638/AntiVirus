"""Restore evidence (BDR-03), built the same way as the standalone backup server (backup/crates/server/src/evidence.rs):
the backup's recovery point, when the restore was asked for, started and finished, its duration, RTO (request to finish)
and RPO (recovery point to request), and what the agent wrote with its SHA-256 read back and the read-back check of
restored disks. Stored as canonical JSON (keys sorted) with its SHA-256, so a copy can be checked later."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .models import BackupAgent, BackupImage, BackupJob, RestoreEvidence

RESTORES = {"restore", "restore_files", "restore_application", "restore_kubernetes", "restore_saas"}


def _unix(t: datetime | None) -> int | None:
    return int(t.replace(tzinfo=timezone.utc).timestamp()) if t else None


def _iso(secs: int | None) -> str | None:
    return datetime.fromtimestamp(secs, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if secs is not None else None


def digest(record: dict) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def is_restore(kind: dict | None) -> bool:
    return (kind or {}).get("type") in RESTORES and bool((kind or {}).get("image_id"))


def record(db: Session, job: BackupJob) -> RestoreEvidence | None:
    kind = job.kind or {}
    if not is_restore(kind):
        return None
    image = db.get(BackupImage, str(kind["image_id"]))
    agent = db.get(BackupAgent, job.agent_id)
    ev = (job.result or {}).get("evidence") if isinstance(job.result, dict) else None
    created, started, finished = _unix(job.created_at), _unix(job.started_at), _unix(job.finished_at)
    point = image.created_unix if image else None
    rec = {
        "format": "fenrir-restore-evidence-v1", "jobId": job.id, "kind": kind.get("type"), "state": job.state,
        "agentId": job.agent_id, "agent": (agent.display_name or agent.hostname) if agent else None, "requestedBy": job.requested_by,
        "imageId": str(kind["image_id"]), "imageKind": image.kind if image else None, "sourceMachine": image.hostname if image else None,
        "recoveryPoint": _iso(point), "requestedAt": _iso(created), "startedAt": _iso(started), "finishedAt": _iso(finished),
        "durationSeconds": finished - started if started is not None and finished is not None else None,
        "rtoSeconds": finished - created if finished is not None and created is not None else None,
        "rpoSeconds": created - point if point is not None and created is not None else None,
        "outputs": (ev or {}).get("outputs") or [], "verification": (ev or {}).get("verification") or [],
        "checks": (ev or {}).get("checks") or [], "verified": bool((ev or {}).get("verified")), "agentReportedEvidence": ev is not None,
        "warnings": job.warnings or [],
    }
    row = db.get(RestoreEvidence, job.id) or RestoreEvidence(job_id=job.id, tenant_id=job.tenant_id, image_id=str(kind["image_id"]))
    row.record, row.sha256 = rec, digest(rec)
    db.add(row)
    return row


def load(row: RestoreEvidence) -> dict:
    return {"evidence": row.record, "sha256": row.sha256, "intact": digest(row.record) == row.sha256}
