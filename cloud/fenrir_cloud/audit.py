"""Tamper-evident audit trail.

Every row stores SHA-256(prev_hash + canonical row). Editing or deleting any
row breaks the chain from that point on, which ``verify_chain`` reports.
"""

from __future__ import annotations

import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditLog, utcnow


def _row_digest(prev_hash: str, row: AuditLog) -> str:
    canonical = json.dumps(
        {
            "tenant": row.tenant_id,
            "actor": row.actor,
            "action": row.action,
            "target": row.target,
            "details": row.details,
            "at": row.at.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def record(db: Session, actor: str, action: str, target: str = "", tenant_id: str | None = None, **details) -> AuditLog:
    last = db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).scalar_one_or_none()
    prev_hash = last.hash if last else ""
    row = AuditLog(tenant_id=tenant_id, actor=actor, action=action, target=target, details=details, at=utcnow())
    row.prev_hash = prev_hash
    row.hash = _row_digest(prev_hash, row)
    db.add(row)
    return row


def verify_chain(db: Session) -> dict:
    prev_hash = ""
    checked = 0
    for row in db.execute(select(AuditLog).order_by(AuditLog.id)).scalars():
        if row.prev_hash != prev_hash or row.hash != _row_digest(prev_hash, row):
            return {"valid": False, "brokenAt": row.id, "checked": checked}
        prev_hash = row.hash
        checked += 1
    return {"valid": True, "checked": checked}
