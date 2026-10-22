"""Audit logging helpers used across the application."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, Any

from flask import current_app

logger = logging.getLogger(__name__)


def _resolve_audit_log_path() -> str:
    """Return the path where audit events should be written."""

    try:
        config = current_app.config  # type: ignore[attr-defined]
    except RuntimeError:
        config = {}

    configured_path = config.get('AUTHORIZATION_AUDIT_LOG') if isinstance(config, dict) else None
    return configured_path or os.path.join('logs', 'authorization_audit.log')


def record_audit_event(event_details: Dict[str, Any]) -> None:
    """Persist *event_details* to the append-only audit log.

    Failures while writing to disk are logged but never raised to the caller.
    """

    entry = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        **event_details,
    }
    log_path = _resolve_audit_log_path()

    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        fd = os.open(log_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY)
        with os.fdopen(fd, 'a', encoding='utf-8') as handle:
            handle.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
        logger.info("Audit event recorded: %s", entry)
    except Exception as exc:  # pragma: no cover - logging failures should not break flow
        logger.error("Failed to write audit event: %s", exc, exc_info=True)

