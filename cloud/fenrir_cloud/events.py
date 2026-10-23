"""Durable, idempotent event processing between modules.

``publish`` writes an event row in the caller's transaction (so it exists only if the
change that caused it commits). The scheduler calls ``process`` every pass: each
registered handler runs inside its own savepoint, its outcome is stored, and failed
handlers are retried with exponential back-off. After ``MAX_ATTEMPTS`` the event is
marked dead and shown to administrators.

Handlers must be idempotent: they can run again after a crash between their work and
the commit.
"""

from __future__ import annotations

import logging
import uuid
import traceback
from collections.abc import Callable
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import PlatformEvent, utcnow

log = logging.getLogger("fenrir.events")

MAX_ATTEMPTS = 8
Handler = Callable[[Session, PlatformEvent], object]
_handlers: dict[str, list[tuple[str, Handler]]] = {}


def handler(event_type: str, name: str | None = None):
    """Register ``fn`` for ``event_type``. Names must be stable: they key retry state."""

    def wrap(fn: Handler) -> Handler:
        handler_name = name or f"{fn.__module__}.{fn.__name__}"
        entries = _handlers.setdefault(event_type, [])
        if all(existing != handler_name for existing, _ in entries):
            entries.append((handler_name, fn))
        return fn

    return wrap


def registered() -> dict[str, list[str]]:
    return {event_type: [name for name, _ in entries] for event_type, entries in sorted(_handlers.items())}


def publish(db: Session, event_type: str, payload: dict, tenant_id: str | None = None, key: str | None = None) -> PlatformEvent:
    """Queue an event. Publishing the same ``key`` twice returns the first event (no duplicate)."""
    key = key or f"{event_type}:{uuid.uuid4().hex}"
    if len(key) > 200:
        raise ValueError("Event idempotency keys must not exceed 200 characters")
    existing = db.execute(select(PlatformEvent).where(PlatformEvent.key == key)).scalar_one_or_none()
    if existing is not None:
        return existing
    event = PlatformEvent(type=event_type, tenant_id=tenant_id, key=key, payload=payload, results={})
    nested = db.begin_nested()
    try:
        db.add(event)
        db.flush()
        nested.commit()
    except IntegrityError:
        nested.rollback()
        return db.execute(select(PlatformEvent).where(PlatformEvent.key == key)).scalar_one()
    return event


def _run(db: Session, event: PlatformEvent) -> None:
    results = dict(event.results or {})
    errors = []
    for name, fn in _handlers.get(event.type, []):
        if results.get(name) == "ok":
            continue
        savepoint = db.begin_nested()
        try:
            fn(db, event)
            db.flush()
            savepoint.commit()
            results[name] = "ok"
        except Exception as exc:  # noqa: BLE001 - one handler must not stop the others
            savepoint.rollback()
            results[name] = f"error: {exc}"[:500]
            errors.append(f"{name}: {exc}")
            log.warning("event %s handler %s failed: %s", event.id, name, traceback.format_exc(limit=3))
    event.results = results
    event.attempts = (event.attempts or 0) + 1
    if errors:
        event.status = "pending"
        event.last_error = "; ".join(errors)[:2000]
        if event.attempts >= MAX_ATTEMPTS:
            event.status = "dead"
        else:
            event.next_attempt_at = utcnow() + timedelta(seconds=min(3600, 30 * 2 ** (event.attempts - 1)))
    else:
        event.status, event.last_error, event.processed_at = "done", "", utcnow()


def process(db: Session, limit: int = 200) -> int:
    """Run due events. Returns how many were attempted."""
    if limit < 1:
        return 0
    # One write statement claims the batch before reading any handler state.
    # This avoids read-to-write lock upgrades on SQLite. The claim and effects
    # share a transaction, so rollback immediately makes the events eligible.
    candidates = (select(PlatformEvent.id)
                  .where(PlatformEvent.status == "pending", PlatformEvent.next_attempt_at <= utcnow())
                  .order_by(PlatformEvent.id).limit(limit))
    claimed = db.execute(
        update(PlatformEvent).where(PlatformEvent.id.in_(candidates), PlatformEvent.status == "pending",
                                    PlatformEvent.next_attempt_at <= utcnow())
        .values(status="processing").returning(PlatformEvent.id)
        .execution_options(synchronize_session=False)
    ).scalars().all()
    for event_id in claimed:
        event = db.get(PlatformEvent, event_id, populate_existing=True)
        _run(db, event)
    return len(claimed)


def retry(db: Session, event: PlatformEvent) -> None:
    event.status, event.next_attempt_at = "pending", utcnow()
    if event.attempts >= MAX_ATTEMPTS:
        event.attempts = MAX_ATTEMPTS - 1
