from enum import Enum
from typing import List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .database import SessionLocal, engine
from .models import Base, DecisionLog

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ThreatGate API", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

class DecisionResult(BaseModel):
    value: str
    type: str
    score: int
    decision: Decision
    reason: str

class DecisionRequest(BaseModel):
    iocs: List[IOCInput]

class DecisionResponse(BaseModel):
    count: int
    decisions: List[DecisionResult]

def decide_one(ioc: IOCInput) -> DecisionResult:
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

    return DecisionResult(value=ioc.value, type=ioc.type, score=score, decision=decision, reason=reason)

@app.post("/decide", response_model=DecisionResponse)
def decide(request: DecisionRequest):
    db = SessionLocal()
    results = []

    for ioc in request.iocs:
        res = decide_one(ioc)
        results.append(res)

        db_entry = DecisionLog(value=res.value, type=res.type, score=res.score, decision=res.decision, reason=res.reason)
        db.add(db_entry)

    db.commit()
    db.close()

    return DecisionResponse(count=len(results), decisions=results)

@app.get("/history")
def history():
    db = SessionLocal()
    return db.query(DecisionLog).all()
