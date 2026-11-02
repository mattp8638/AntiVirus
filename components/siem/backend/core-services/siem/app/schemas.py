from pydantic import BaseModel
from typing import Optional, List, Any

class RawEventIn(BaseModel):
    source_system: Optional[str]
    event_time: Optional[str]
    payload: Any

class RawEventOut(BaseModel):
    id: str
    source_system: Optional[str]
    received_at: Optional[str]

    class Config:
        orm_mode = True

class EventIn(BaseModel):
    raw_event_id: str
    event_category: Optional[str]
    event_type: Optional[str]
    severity: Optional[int]
    asset_id: Optional[str]
    user_id: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    event_time: Optional[str]

class FindingCreate(BaseModel):
    organisation_id: str
    finding_type: str
    severity: int = 1
    confidence: int = 50
