"""In-memory risk scoring for MVP-2 visibility."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class RiskScore:
    identity_id: str
    score: float
    rationale: str


class RiskStore:
    def __init__(self) -> None:
        self._scores: Dict[str, RiskScore] = {}

    def upsert(self, identity_id: str, score: float, rationale: str) -> None:
        self._scores[identity_id] = RiskScore(
            identity_id=identity_id,
            score=score,
            rationale=rationale,
        )

    def list_all(self) -> List[RiskScore]:
        return list(self._scores.values())


store = RiskStore()
