"""Validation helpers for MVP-13 compliance controls."""
from __future__ import annotations

from datetime import datetime
from typing import Iterable

from .models import ControlCreateRequest, EvidenceIngestRequest, ExceptionRequest, FrameworkMappingRequest


class ValidationError(ValueError):
    """Raised when validation fails."""


def _unique(values: Iterable[str]) -> bool:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            return False
        seen.add(value)
    return True


def validate_control_request(request: ControlCreateRequest) -> None:
    """Validate control creation payloads."""
    if request.evidence_sources and not _unique(request.evidence_sources):
        raise ValidationError("duplicate_evidence_sources")


def validate_evidence_request(request: EvidenceIngestRequest) -> None:
    """Validate evidence ingestion payloads."""
    if not request.attributes:
        raise ValidationError("attributes_required")


def validate_exception_request(request: ExceptionRequest, now: datetime) -> None:
    """Validate exception requests for future expiry."""
    if request.expires_at <= now:
        raise ValidationError("exception_expiry_in_past")


def validate_mapping_request(request: FrameworkMappingRequest) -> None:
    """Validate framework mapping payloads."""
    if not request.control_id or not request.framework or not request.mapped_control:
        raise ValidationError("mapping_incomplete")
