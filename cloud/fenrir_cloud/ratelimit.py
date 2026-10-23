"""Database-backed sliding windows shared across API workers and restarts.

Each check commits independently, so failed authentication cannot undo a hit.
Database errors fail closed; there is no per-process fallback.
"""
from __future__ import annotations

import hashlib
import math
from datetime import timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import delete, func, select

from .db import engine
from .models import RateLimitBucket


def check(key: str, limit: int, window_seconds: int) -> None:
    if limit < 1 or window_seconds < 1:
        raise ValueError("Rate limit and window must be positive")
    bucket_key = hashlib.sha256(f"{limit}:{window_seconds}:{key}".encode()).hexdigest()
    table = RateLimitBucket.__table__
    dialect = engine().dialect.name
    if dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    elif dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        raise RuntimeError("Shared rate limiting requires SQLite or PostgreSQL")
    retry_after = None
    with engine().begin() as conn:
        now = conn.scalar(select(func.current_timestamp()))
        if now.tzinfo is not None:
            now = now.astimezone(timezone.utc).replace(tzinfo=None)
        # A no-op upsert locks even an existing bucket before its window is read.
        conn.execute(insert(table).values(key=bucket_key, hits=[], expires_at=now + timedelta(seconds=window_seconds))
                     .on_conflict_do_update(index_elements=[table.c.key], set_={"key": bucket_key}))
        hits = conn.scalar(select(table.c.hits).where(table.c.key == bucket_key))
        stamp = now.replace(tzinfo=timezone.utc).timestamp()
        hits = [hit for hit in hits if hit > stamp - window_seconds]
        if len(hits) >= limit:
            retry_after = max(1, math.ceil(window_seconds - (stamp - hits[0])))
        else:
            hits.append(stamp)
        conn.execute(table.update().where(table.c.key == bucket_key).values(hits=hits, expires_at=now + timedelta(seconds=window_seconds)))
    if retry_after is not None:
        raise HTTPException(429, "Too many attempts. Try again later.", headers={"Retry-After": str(retry_after)})


def reset() -> None:
    """Explicit administrative/test reset; never run during application startup."""
    with engine().begin() as conn:
        conn.execute(delete(RateLimitBucket))
