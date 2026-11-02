import re
from enum import Enum
from typing import List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .database import SessionLocal, engine
from .models import Base, IOCRun, IOCItem

Base.metadata.create_all(bind=engine)

app = FastAPI(title="IOC Validator API", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class IOCType(str, Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash = "hash"
    cve = "cve"
    email = "email"
    unknown = "unknown"

class ValidationRequest(BaseModel):
    input: str

class IOCResult(BaseModel):
    value: str
    type: IOCType
    valid: bool
    confidence: int
    recommendation: str
    reason: str

class ValidationResponse(BaseModel):
    count: int
    valid_count: int
    results: List[IOCResult]

PATTERNS = {
    IOCType.url: re.compile(r"https?://[^\s]+"),
    IOCType.email: re.compile(r"\S+@\S+"),
    IOCType.ip: re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
}

def extract(raw):
    results = []
    for pattern in PATTERNS.values():
        results.extend(pattern.findall(raw))
    return list(set(results))

@app.post("/validate")
def validate(data: ValidationRequest):
    extracted = extract(data.input)
    results = []

    db = SessionLocal()

    run = IOCRun(raw_input=data.input, total_count=len(extracted), valid_count=len(extracted))
    db.add(run)
    db.commit()
    db.refresh(run)

    for ioc in extracted:
        result = IOCResult(value=ioc, type="unknown", valid=True, confidence=50, recommendation="review", reason="basic match")
        results.append(result)

        db_item = IOCItem(run_id=run.id, value=ioc, type="unknown", confidence=50, recommendation="review", reason="basic match")
        db.add(db_item)

    db.commit()
    db.close()

    return {"count": len(results), "valid_count": len(results), "results": results}

@app.get("/history")
def history():
    db = SessionLocal()
    runs = db.query(IOCRun).all()
    return runs
