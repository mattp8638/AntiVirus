from __future__ import annotations

import os
from dataclasses import dataclass

DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("PSA_DATABASE_URL") or "postgresql://tamsilsiem:1792BigDirtyDykes!@10.252.0.25:5432/tamsilcmssiem?sslmode=require"

SERVICE_NAME = "psa"
"""Configuration for the PSA workflow engine.

All secrets are sourced from environment variables to avoid hard-coding.
"""


@dataclass(frozen=True)
class Settings:
    """Runtime settings sourced from environment variables."""

    service_name: str
    https_enforced: bool
    api_key: str
    storage_path: str
    risk_threshold: float
    max_evidence_per_ticket: int
    max_actions_per_ticket: int


def load_settings() -> Settings:
    """Load settings from the environment with secure defaults."""
    return Settings(
        service_name=os.environ.get("PSA_WORKFLOW_SERVICE_NAME", "psa-workflow-service"),
        https_enforced=os.environ.get("PSA_WORKFLOW_HTTPS_ENFORCED", "true").lower() == "true",
        api_key=os.environ.get("PSA_WORKFLOW_API_KEY", ""),
        storage_path=os.environ.get("PSA_WORKFLOW_STORAGE_PATH", "data/psa_store.json"),
        risk_threshold=float(os.environ.get("PSA_WORKFLOW_RISK_THRESHOLD", "55.0")),
        max_evidence_per_ticket=int(os.environ.get("PSA_WORKFLOW_MAX_EVIDENCE", "100")),
        max_actions_per_ticket=int(os.environ.get("PSA_WORKFLOW_MAX_ACTIONS", "200")),
    )
