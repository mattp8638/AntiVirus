"""Tamper-evident audit trail.

Every row stores SHA-256(prev_hash + canonical row). Editing or deleting any
row breaks the chain from that point on, which ``verify_chain`` reports.
"""

from __future__ import annotations

import hashlib
import json

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import AuditChainHead, AuditLog, utcnow


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


def _head(db: Session) -> AuditChainHead:
    head = db.execute(select(AuditChainHead).where(AuditChainHead.id == 1)
                      .execution_options(populate_existing=True)).scalar_one_or_none()
    if head is not None:
        return head
    # First append on a fresh database (or one created without migrations): start the head at the newest row.
    last = db.execute(select(AuditLog).order_by(AuditLog.seq.desc().nulls_last(), AuditLog.id.desc()).limit(1)).scalar_one_or_none()
    try:
        with db.begin_nested():
            db.add(AuditChainHead(id=1, seq=(last.seq or last.id) if last else 0, last_hash=last.hash if last else ""))
    except IntegrityError:
        pass  # another writer created it first
    return db.execute(select(AuditChainHead).where(AuditChainHead.id == 1).execution_options(populate_existing=True)).scalar_one()


def record(db: Session, actor: str, action: str, target: str = "", tenant_id: str | None = None, **details) -> AuditLog:
    """Append one event. The chain head is advanced with a compare-and-swap: on PostgreSQL the update waits for any
    other writer's transaction, then sees its new head and retries, so every committed row chains onto the row
    committed before it. A rollback undoes both the row and the head move."""
    row = AuditLog(tenant_id=tenant_id, actor=actor, action=action, target=target, details=details, at=utcnow())
    for _ in range(1000):
        head = _head(db)
        row.prev_hash, row.seq = head.last_hash, head.seq + 1
        row.hash = _row_digest(row.prev_hash, row)
        moved = db.execute(update(AuditChainHead).where(AuditChainHead.id == 1, AuditChainHead.seq == head.seq)
                           .values(seq=row.seq, last_hash=row.hash).execution_options(synchronize_session=False))
        if moved.rowcount == 1:
            break
    else:
        raise RuntimeError("Could not append to the audit chain")
    db.add(row)
    return row


def verify_chain(db: Session) -> dict:
    prev_hash = ""
    checked = 0
    for row in db.execute(select(AuditLog).order_by(AuditLog.seq.asc().nulls_first(), AuditLog.id)).scalars():
        if row.prev_hash != prev_hash or row.hash != _row_digest(prev_hash, row):
            return {"valid": False, "brokenAt": row.id, "checked": checked}
        prev_hash = row.hash
        checked += 1
    return {"valid": True, "checked": checked}
