"""Configuration for the Compliance & Audit Automation service."""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"))
COMPLIANCE_DATABASE_URL = (
    os.environ["COMPLIANCE_DATABASE_URL"]
    if "COMPLIANCE_DATABASE_URL" in os.environ
    else os.environ.get("DATABASE_URL", "")
)


@dataclass(frozen=True)
class Settings:
    service_name: str
    https_enforced: bool
    api_key: str
    storage_path: str
    default_evaluation_frequency_days: int
    max_evidence_records: int
    max_assessments_per_control: int
    max_exceptions_per_control: int


def load_settings() -> Settings:
    return Settings(
        service_name=os.environ.get("COMPLIANCE_SERVICE_NAME", "compliance-service"),
        https_enforced=os.environ.get("COMPLIANCE_HTTPS_ENFORCED", "false").lower() == "true",
        api_key=os.environ.get("COMPLIANCE_API_KEY", ""),
        storage_path=os.environ.get(
            "COMPLIANCE_STORAGE_PATH",
            os.path.join(os.getcwd(), "data", "compliance_store.json"),
        ),
        default_evaluation_frequency_days=int(
            os.environ.get("COMPLIANCE_DEFAULT_EVALUATION_FREQUENCY_DAYS", "30")
        ),
        max_evidence_records=int(os.environ.get("COMPLIANCE_MAX_EVIDENCE_RECORDS", "500")),
        max_assessments_per_control=int(
            os.environ.get("COMPLIANCE_MAX_ASSESSMENTS_PER_CONTROL", "250")
        ),
        max_exceptions_per_control=int(
            os.environ.get("COMPLIANCE_MAX_EXCEPTIONS_PER_CONTROL", "200")
        ),
    )
