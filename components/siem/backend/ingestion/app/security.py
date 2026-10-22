"""Security helpers for verifying signed event ingestion requests."""
from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Tuple

from .config import Settings


def _normalise_payload(payload: bytes) -> bytes:
    """Return a canonical representation of payload bytes for signing."""
    return payload.strip()


def verify_signature(
    settings: Settings,
    payload: bytes,
    signature_b64: str,
    timestamp: int,
) -> Tuple[bool, str]:
    """Verify a base64-encoded HMAC signature with TTL checks."""
    if not settings.hmac_shared_key:
        return False, "missing_shared_key"

    now = int(time.time())
    if abs(now - timestamp) > settings.signature_ttl_seconds:
        return False, "signature_expired"

    try:
        provided = base64.b64decode(signature_b64)
    except (ValueError, TypeError):
        return False, "invalid_signature_encoding"

    message = f"{timestamp}.".encode("utf-8") + _normalise_payload(payload)
    expected = hmac.new(
        settings.hmac_shared_key.encode("utf-8"),
        message,
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(expected, provided):
        return False, "signature_mismatch"

    return True, "ok"
