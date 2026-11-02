"""Security utilities for authorization and auditing."""

from .target_validation import (
    TargetAuthorizationError,
    ensure_targets_authorized,
    load_approved_targets,
    normalise_approved_targets,
    validate_targets,
)
from .audit import record_audit_event

__all__ = [
    'TargetAuthorizationError',
    'ensure_targets_authorized',
    'load_approved_targets',
    'normalise_approved_targets',
    'validate_targets',
    'record_audit_event',
]
