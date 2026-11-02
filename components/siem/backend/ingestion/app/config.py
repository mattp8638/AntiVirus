"""Configuration for the ingestion service."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    environment: str
    service_name: str
    database_dsn: str
    database_min_connections: int
    database_max_connections: int
    telemetry_sample_limit: int
    telemetry_stale_seconds: int
    telemetry_future_seconds: int
    telemetry_baseline_window: int
    telemetry_anomaly_stddev_threshold: float
    event_batch_limit: int
    event_stale_seconds: int
    event_future_seconds: int
    event_clock_drift_seconds: int
    signature_ttl_seconds: int
    hmac_shared_key: str


def load_settings() -> Settings:
    database_dsn = os.environ.get("INGESTION_DATABASE_DSN", "").strip()
    if not database_dsn:
        raise ValueError(
            "INGESTION_DATABASE_DSN is required. Define it in your environment or .env file."
        )
    return Settings(
        environment=os.environ.get("INGESTION_ENV", "development"),
        service_name=os.environ.get("INGESTION_SERVICE_NAME", "ingestion-service"),
        database_dsn=database_dsn,
        database_min_connections=int(os.environ.get("INGESTION_DB_MIN_CONN", "1")),
        database_max_connections=int(os.environ.get("INGESTION_DB_MAX_CONN", "5")),
        telemetry_sample_limit=int(os.environ.get("INGESTION_TELEMETRY_SAMPLE_LIMIT", "500")),
        telemetry_stale_seconds=int(os.environ.get("INGESTION_TELEMETRY_STALE_SECONDS", "600")),
        telemetry_future_seconds=int(os.environ.get("INGESTION_TELEMETRY_FUTURE_SECONDS", "120")),
        telemetry_baseline_window=int(os.environ.get("INGESTION_TELEMETRY_BASELINE_WINDOW", "20")),
        telemetry_anomaly_stddev_threshold=float(
            os.environ.get("INGESTION_TELEMETRY_ANOMALY_THRESHOLD", "3.0")
        ),
        event_batch_limit=int(os.environ.get("INGESTION_EVENT_BATCH_LIMIT", "200")),
        event_stale_seconds=int(os.environ.get("INGESTION_EVENT_STALE_SECONDS", "900")),
        event_future_seconds=int(os.environ.get("INGESTION_EVENT_FUTURE_SECONDS", "120")),
        event_clock_drift_seconds=int(
            os.environ.get("INGESTION_EVENT_CLOCK_DRIFT_SECONDS", "300")
        ),
        signature_ttl_seconds=int(os.environ.get("INGESTION_SIGNATURE_TTL", "120")),
        hmac_shared_key=os.environ.get("INGESTION_HMAC_SHARED_KEY", ""),
    )
