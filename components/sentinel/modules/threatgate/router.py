from enum import Enum
from typing import List, Optional
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

class Decision(str, Enum):
    block = "BLOCK"
    monitor = "MONITOR"
    review = "REVIEW"
    ignore = "IGNORE"

class IOCInput(BaseModel):
    value: str
    type: str = "unknown"
    confidence: int = 0
    source_count: int = 1
    seen_in_environment: bool = False
    note: Optional[str] = None

class DecisionRequest(BaseModel):
    iocs: List[IOCInput]

def decide_indicator(ioc: IOCInput):
    score = max(0, min(100, ioc.confidence))
    if ioc.source_count >= 2:
        score += 10
    if ioc.seen_in_environment:
        score += 15
    if ioc.type in ["hash", "url"]:
        score += 5
    if ioc.type == "ip":
        score -= 10
    if ioc.type == "unknown":
        score -= 30
    score = max(0, min(100, score))

    if score >= 85:
        decision = Decision.block
        reason = "High confidence indicator suitable for blocking."
    elif score >= 65:
        decision = Decision.monitor
        reason = "Credible indicator; monitor and correlate before broad blocking."
    elif score >= 40:
        decision = Decision.review
        reason = "Indicator needs further enrichment or analyst review."
    else:
        decision = Decision.ignore
        reason = "Low confidence or weakly classified indicator."

    return {"value": ioc.value, "type": ioc.type, "score": score, "decision": decision, "reason": reason}

@router.post("/decide")
def decide(request: DecisionRequest):
    decisions = [decide_indicator(ioc) for ioc in request.iocs]
    return {"count": len(decisions), "decisions": decisions}
