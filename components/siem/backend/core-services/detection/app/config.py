"""Configuration for the Detection & Correlation service."""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"))
DETECTION_DATABASE_URL = (
    os.environ["DETECTION_DATABASE_URL"]
    if "DETECTION_DATABASE_URL" in os.environ
    else os.environ.get("DATABASE_URL", "")
)


@dataclass(frozen=True)
class Settings:
    service_name: str
    https_enforced: bool
    retention_events: int
    retention_findings: int
    max_event_age_seconds: int
    max_supporting_events: int
    max_findings_per_request: int
    correlation_time_window_seconds: int
    allow_findings_without_context: bool
    allowed_explanation_variables: tuple[str, ...]


def load_settings() -> Settings:
    allowed_variables = tuple(
        value.strip()
        for value in os.environ.get(
            "DETECTION_ALLOWED_EXPLANATION_VARIABLES",
            "event.event_type,event.source_system,asset.hostname,asset.environment,identity.identity_id",
        ).split(",")
        if value.strip()
    )
    return Settings(
        service_name=os.environ.get("DETECTION_SERVICE_NAME", "detection-service"),
        https_enforced=os.environ.get("DETECTION_HTTPS_ENFORCED", "false").lower() == "true",
        retention_events=int(os.environ.get("DETECTION_RETENTION_EVENTS", "10000")),
        retention_findings=int(os.environ.get("DETECTION_RETENTION_FINDINGS", "5000")),
        max_event_age_seconds=int(os.environ.get("DETECTION_MAX_EVENT_AGE_SECONDS", "3600")),
        max_supporting_events=int(os.environ.get("DETECTION_MAX_SUPPORTING_EVENTS", "50")),
        max_findings_per_request=int(os.environ.get("DETECTION_MAX_FINDINGS_PER_REQUEST", "200")),
        correlation_time_window_seconds=int(
            os.environ.get("DETECTION_CORRELATION_TIME_WINDOW_SECONDS", "900")
        ),
        allow_findings_without_context=os.environ.get(
            "DETECTION_ALLOW_FINDINGS_WITHOUT_CONTEXT", "true"
        ).lower()
        == "true",
        allowed_explanation_variables=allowed_variables,
    )
