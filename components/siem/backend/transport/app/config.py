"""
Configuration for the Transport gateway.

All secrets are sourced from environment variables to avoid hard-coding.
"""
from __future__ import annotations

import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env'))
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Runtime settings sourced from environment variables."""

    environment: str
    database_url: str
    identity_service_url: str
    ingestion_service_url: str
    request_timeout_seconds: float
    service_name: str
    trusted_fingerprints: str


def load_settings() -> Settings:
    """Load settings from the environment with secure defaults."""
    return Settings(
        environment=os.environ.get("TRANSPORT_ENV", "development"),
        # PostgreSQL is now the single backend dependency
        database_url=os.environ["TRANSPORT_DATABASE_URL"] if "TRANSPORT_DATABASE_URL" in os.environ else os.environ["DATABASE_URL"],
        # Internal services only (no penetration.local)
        identity_service_url=os.environ.get(
            "TRANSPORT_IDENTITY_URL", "http://identity:8080"
        ),
        ingestion_service_url=os.environ.get(
            "TRANSPORT_INGESTION_URL", "http://ingestion:8080"
        ),

        request_timeout_seconds=float(
            os.environ.get("TRANSPORT_REQUEST_TIMEOUT", "5")
        ),
        service_name=os.environ.get(
            "TRANSPORT_SERVICE_NAME", "transport-gateway"
        ),
        trusted_fingerprints=os.environ.get(
            "TRANSPORT_TRUSTED_FINGERPRINTS", ""
        ),
    )
