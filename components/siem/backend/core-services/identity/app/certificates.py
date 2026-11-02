"""In-memory certificate registry for MVP-1.

This is a temporary store to support issuance and revocation workflows without
persistence. Replace with database-backed storage in MVP-2+.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional


@dataclass
class CertificateRecord:
    """Represents a certificate lifecycle record."""

    identity_id: str
    fingerprint_sha256: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None


class CertificateRegistry:
    """In-memory registry keyed by fingerprint."""

    def __init__(self) -> None:
        self._records: Dict[str, CertificateRecord] = {}

    def issue(self, record: CertificateRecord) -> CertificateRecord:
        self._records[record.fingerprint_sha256] = record
        return record

    def revoke(self, fingerprint: str, reason: str) -> Optional[CertificateRecord]:
        record = self._records.get(fingerprint)
        if not record:
            return None
        record.revoked_at = datetime.now(timezone.utc)
        record.revocation_reason = reason
        return record

    def get(self, fingerprint: str) -> Optional[CertificateRecord]:
        return self._records.get(fingerprint)

    def is_known(self, fingerprint: str) -> bool:
        return fingerprint in self._records

    def is_revoked(self, fingerprint: str) -> bool:
        record = self._records.get(fingerprint)
        return record is not None and record.revoked_at is not None


registry = CertificateRegistry()
