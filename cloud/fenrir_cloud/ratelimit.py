"""In-process sliding-window rate limiting for abuse-prone endpoints.

The API runs as a single process (one uvicorn worker, see deploy/Dockerfile), so an
in-memory limiter is accurate. Behind several workers each keeps its own window,
which still bounds abuse per worker; put a shared limiter in the reverse proxy for
multi-instance deployments.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from fastapi import HTTPException, status

_lock = threading.Lock()
_hits: dict[str, deque[float]] = {}


def check(key: str, limit: int, window_seconds: int) -> None:
    """Record a hit for ``key``; raise 429 once more than ``limit`` hits fall inside the window."""
    now = time.monotonic()
    with _lock:
        hits = _hits.setdefault(key, deque())
        while hits and now - hits[0] > window_seconds:
            hits.popleft()
        if len(hits) >= limit:
            retry_after = int(window_seconds - (now - hits[0])) + 1
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts. Try again later.",
                                headers={"Retry-After": str(retry_after)})
        hits.append(now)
        if len(_hits) > 50_000:  # keep memory bounded
            for stale in [k for k, v in _hits.items() if not v or now - v[-1] > 3600]:
                _hits.pop(stale, None)


def reset() -> None:
    with _lock:
        _hits.clear()
