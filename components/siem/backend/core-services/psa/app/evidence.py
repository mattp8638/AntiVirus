"""Evidence hashing utilities."""
from __future__ import annotations

import hashlib
import json


def build_hash(payload: dict) -> str:
    """Generate a deterministic SHA-256 hash for evidence payloads."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
