"""Transport trust configuration for client certificates."""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Optional

from fastapi import HTTPException, status


@dataclass(frozen=True)
class TrustStore:
    """Simple in-memory allow list of client certificate fingerprints."""

    allowed_fingerprints: FrozenSet[str]

    def is_allowed(self, fingerprint: str) -> bool:
        return fingerprint.lower() in self.allowed_fingerprints


def parse_fingerprints(raw_value: Optional[str]) -> TrustStore:
    """Parse comma-separated fingerprints into a trust store."""
    if not raw_value:
        return TrustStore(allowed_fingerprints=frozenset())

    allowed = frozenset(
        item.strip().lower()
        for item in raw_value.split(",")
        if item.strip()
    )
    return TrustStore(allowed_fingerprints=allowed)


def enforce_trusted_fingerprint(trust_store: TrustStore, fingerprint: str) -> None:
    """Ensure the client certificate fingerprint is allow-listed."""
    if trust_store.allowed_fingerprints and not trust_store.is_allowed(fingerprint):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="untrusted_client_certificate",
        )

