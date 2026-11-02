from fastapi import APIRouter
from pydantic import BaseModel
from typing import List

router = APIRouter()

class DecisionItem(BaseModel):
    value: str
    decision: str

class BlockRequest(BaseModel):
    decisions: List[DecisionItem]

@router.post("/build")
def build(data: BlockRequest):
    blocked = [d.value for d in data.decisions if d.decision == "BLOCK"]
    return {
        "count": len(blocked),
        "entries": blocked,
        "plain_text": "\n".join(blocked)
    }
