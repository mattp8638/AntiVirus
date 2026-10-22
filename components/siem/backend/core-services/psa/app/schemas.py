from pydantic import BaseModel
from typing import Optional, List

class CaseCreate(BaseModel):
    organisation_id: str
    case_type: Optional[str] = "incident"
    source_system: Optional[str] = "manual"
    severity: Optional[int] = 1

class CaseOut(BaseModel):
    id: str
    organisation_id: str
    case_type: Optional[str]
    source_system: Optional[str]
    severity: int
    status: str

    class Config:
        orm_mode = True

class EvidenceCreate(BaseModel):
    evidence_type: str
    source_system: Optional[str]
    stored_uri: Optional[str]
    hash: Optional[str]

class TaskCreate(BaseModel):
    task_type: str
    assigned_to: Optional[str]
