import os
import requests
from typing import Optional

PSA_BASE = os.environ.get("PSA_BASE_URL", "http://localhost:8001")


class EscalationClient:
    """Generic client to create cases in PSA. Reusable by multiple producers."""

    def __init__(self, base_url: Optional[str] = None):
        self.base = base_url or PSA_BASE

    def create_case(self, organisation_id: str, case_type: str = "incident", source_system: str = "external", severity: int = 1, extra: dict | None = None) -> dict:
        url = f"{self.base}/psa/cases"
        payload = {
            "organisation_id": organisation_id,
            "case_type": case_type,
            "source_system": source_system,
            "severity": severity,
        }
        if extra:
            payload.update(extra)
        r = requests.post(url, json=payload, timeout=10)
        r.raise_for_status()
        return r.json()
