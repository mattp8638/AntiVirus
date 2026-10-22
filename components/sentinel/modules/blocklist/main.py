from typing import List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .database import SessionLocal, engine
from .models import Base, BlocklistRun, BlocklistItem

Base.metadata.create_all(bind=engine)

app = FastAPI(title="BlocklistForge API", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class DecisionInput(BaseModel):
    value: str
    type: str = "unknown"
    score: int = 0
    decision: str

class BlocklistRequest(BaseModel):
    decisions: List[DecisionInput]
    include_monitor: bool = False

class BlocklistItemResponse(BaseModel):
    indicator: str
    type: str
    score: int
    action: str
    reason: str

@app.post("/build")
def build_blocklist(request: BlocklistRequest):
    allowed = {"BLOCK"}
    block_items = []
    seen = set()

    db = SessionLocal()

    for item in request.decisions:
        value = item.value.strip().lower()
        if not value or value in seen:
            continue
        if item.decision.upper() not in allowed:
            continue

        seen.add(value)
        block_items.append({
            "indicator": value,
            "type": item.type,
            "score": item.score,
            "action": "block",
            "reason": "ThreatGate decision met blocklist policy threshold."
        })

    run = BlocklistRun(count=len(block_items), policy="BLOCK only")
    db.add(run)
    db.commit()
    db.refresh(run)

    for item in block_items:
        db_item = BlocklistItem(run_id=run.id, indicator=item["indicator"], type=item["type"], score=item["score"])
        db.add(db_item)

    db.commit()
    db.close()

    plain_text = "\n".join(item["indicator"] for item in block_items)

    return {
        "count": len(block_items),
        "policy": "BLOCK only",
        "blocklist": block_items,
        "plain_text": plain_text,
    }

@app.get("/history")
def history():
    db = SessionLocal()
    return db.query(BlocklistRun).all()
