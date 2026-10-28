"""Tamper-evident audit trail.

Every row stores SHA-256(prev_hash + canonical row). Editing or deleting any
row breaks the chain from that point on, which ``verify_chain`` reports.
"""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta

from sqlalchemy import delete, select, update
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


def _legacy_boundary(db: Session):
    """Rows written before the serialised append (migration 22) may carry chain breaks from the old race."""
    from sqlalchemy import text

    try:
        value = db.execute(text("SELECT applied_at FROM schema_migrations WHERE version = 22")).scalar()
    except Exception:  # noqa: BLE001 - databases created without migrations
        db.rollback()
        return None
    if isinstance(value, str):  # SQLite returns the timestamp as text
        from datetime import datetime

        value = datetime.fromisoformat(value.replace(" ", "T"))
    return value.replace(tzinfo=None) if value is not None and value.tzinfo else value


def _anchor(db: Session):
    from .models import AuditCheckpoint

    return db.execute(select(AuditCheckpoint).where(AuditCheckpoint.kind == "anchor").order_by(AuditCheckpoint.seq.desc()).limit(1)).scalar_one_or_none()


def verify_chain(db: Session, limit_breaks: int = 50) -> dict:
    """Walk the chain from the retention anchor (or the start) and classify every break:

    - modified: a row's stored hash no longer matches its own content (edited after it was written);
    - deleted: positions are missing between two rows;
    - legacy-race: before serialised appends (migration 22), two concurrent writers chained onto the same row - the row
      is intact and links to a sibling; this is a software race, not tampering;
    - relinked: the row is intact but points somewhere unexpected (inserted or reordered rows);
    - checkpoint: the chain no longer has the hash a checkpoint recorded (rows up to it were rewritten).
    """
    from .models import AuditCheckpoint

    anchor = _anchor(db)
    boundary = _legacy_boundary(db)
    prev_hash, prev_seq = (anchor.hash, anchor.seq) if anchor else ("", 0)
    known = {}
    breaks: list[dict] = []
    checked = first_break_checked = 0
    first_break_id = None
    query = select(AuditLog).order_by(AuditLog.seq.asc().nulls_first(), AuditLog.id)
    if anchor:
        query = query.where(AuditLog.seq > anchor.seq)
    rows = db.execute(query).scalars().all()
    hashes = {r.hash for r in rows}
    for row in rows:
        intact = row.hash == _row_digest(row.prev_hash, row)
        kind = None
        if not intact:
            kind = "modified"
        elif row.prev_hash != prev_hash:
            if row.seq is not None and prev_seq is not None and row.seq > prev_seq + 1:
                kind = "deleted"
            elif boundary is not None and row.at < boundary and (row.prev_hash in hashes or row.prev_hash == ""):
                kind = "legacy-race"
            else:
                kind = "relinked"
        if kind:
            if first_break_id is None:
                first_break_id, first_break_checked = row.id, checked
            if len(breaks) < limit_breaks:
                breaks.append({"id": row.id, "seq": row.seq, "kind": kind, "at": row.at.isoformat() + "Z"})
        known[row.seq] = row.hash
        prev_hash, prev_seq = row.hash, row.seq
        checked += 1
    head = db.get(AuditChainHead, 1)
    if head is not None and head.seq > (prev_seq or 0):  # rows removed from the end of the chain
        breaks.append({"id": None, "seq": head.seq, "kind": "deleted", "at": None})
    mismatched = []
    checkpoints = db.execute(select(AuditCheckpoint).where(AuditCheckpoint.kind == "checkpoint")).scalars().all()
    for cp in checkpoints:
        if (anchor is None or cp.seq > anchor.seq) and cp.seq in known and known[cp.seq] != cp.hash:
            mismatched.append({"checkpoint": cp.id, "seq": cp.seq, "createdAt": cp.created_at.isoformat() + "Z"})
            breaks.append({"id": None, "seq": cp.seq, "kind": "checkpoint", "at": cp.created_at.isoformat() + "Z"})
        elif (anchor is None or cp.seq > anchor.seq) and cp.seq not in known and cp.seq <= (prev_seq or 0):
            mismatched.append({"checkpoint": cp.id, "seq": cp.seq, "createdAt": cp.created_at.isoformat() + "Z", "missing": True})
            breaks.append({"id": None, "seq": cp.seq, "kind": "deleted", "at": cp.created_at.isoformat() + "Z"})
    if not breaks:
        out = {"valid": True, "checked": checked}
    else:
        out = {"valid": False, "brokenAt": first_break_id, "checked": first_break_checked if first_break_id else checked,
               "breaks": breaks, "tampered": any(b["kind"] != "legacy-race" for b in breaks),
               "legacyBreaks": sum(1 for b in breaks if b["kind"] == "legacy-race")}
    if anchor:
        out["anchor"] = {"seq": anchor.seq, "hash": anchor.hash, "createdAt": anchor.created_at.isoformat() + "Z"}
    if checkpoints:
        out["checkpoints"] = {"checked": len(checkpoints), "mismatched": mismatched}
    return out


def checkpoint(db: Session, actor: str, reason: str = "") -> "AuditCheckpoint":
    """Record the current chain head and publish it, so a copy exists outside this database (webhooks / SIEM)."""
    from . import events
    from .models import AuditCheckpoint

    head = _head(db)
    rows = db.execute(select(AuditLog.id)).all()
    cp = AuditCheckpoint(kind="checkpoint", seq=head.seq, hash=head.last_hash, rows=len(rows), reason=reason, created_by=actor)
    db.add(cp)
    db.flush()
    events.publish(db, "audit.checkpoint", {"seq": cp.seq, "hash": cp.hash, "rows": cp.rows, "at": cp.created_at.isoformat() + "Z",
                                            "checkpointId": cp.id}, key=f"audit.checkpoint:{cp.id}")
    return cp


def daily_checkpoint(db: Session) -> None:
    from .models import AuditCheckpoint

    last = db.execute(select(AuditCheckpoint).where(AuditCheckpoint.kind == "checkpoint")
                      .order_by(AuditCheckpoint.created_at.desc()).limit(1)).scalar_one_or_none()
    if last is None or utcnow() - last.created_at > timedelta(hours=24):
        if _head(db).seq > (last.seq if last else 0):
            checkpoint(db, "system", "daily")


def export_rows(db: Session, tenant_ids: set[str] | None) -> list[dict]:
    """Rows for an export. With tenant_ids, other customers' rows (and platform rows) keep only their chain fields, so
    the export still links end to end without disclosing anyone else's activity."""
    out = []
    anchor = _anchor(db)
    query = select(AuditLog).order_by(AuditLog.seq.asc().nulls_first(), AuditLog.id)
    if anchor:
        query = query.where(AuditLog.seq > anchor.seq)
    for row in db.execute(query).scalars():
        chain = {"seq": row.seq, "prevHash": row.prev_hash, "hash": row.hash}
        if tenant_ids is None or row.tenant_id in tenant_ids:
            out.append({**chain, "tenant": row.tenant_id, "actor": row.actor, "action": row.action, "target": row.target,
                        "details": row.details, "at": row.at.isoformat()})
        else:
            out.append({**chain, "redacted": True})
    return out


def apply_retention(db: Session, actor: str = "system") -> int:
    """Prune rows older than the retention period, but only up to a checkpoint, which becomes the anchor verification
    starts from. Nothing is pruned under legal hold or without a retention period."""
    from .models import AuditCheckpoint, AuditPolicy

    policy = db.get(AuditPolicy, 1)
    if policy is None or policy.legal_hold or not policy.retention_days:
        return 0
    cutoff = utcnow() - timedelta(days=policy.retention_days)
    oldest_kept = db.execute(select(AuditLog.seq).where(AuditLog.at >= cutoff).order_by(AuditLog.seq.asc()).limit(1)).scalar()
    candidates = select(AuditCheckpoint).where(AuditCheckpoint.kind == "checkpoint")
    if oldest_kept is not None:
        candidates = candidates.where(AuditCheckpoint.seq < oldest_kept)
    cp = db.execute(candidates.order_by(AuditCheckpoint.seq.desc()).limit(1)).scalar_one_or_none()
    anchor = _anchor(db)
    if cp is None or (anchor and cp.seq <= anchor.seq):
        return 0
    row = db.execute(select(AuditLog).where(AuditLog.seq == cp.seq)).scalar_one_or_none()
    if row is None or row.hash != cp.hash:
        return 0  # the chain does not match the checkpoint: keep everything for investigation
    pruned = db.execute(delete(AuditLog).where(AuditLog.seq <= cp.seq)).rowcount
    db.add(AuditCheckpoint(kind="anchor", seq=cp.seq, hash=cp.hash, rows=pruned, reason=f"retention {policy.retention_days} days",
                           created_by=actor))
    record(db, actor, "audit.pruned", f"up to {cp.seq}", None, rows=pruned, retentionDays=policy.retention_days)
    return pruned
