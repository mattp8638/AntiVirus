from pydantic import BaseModel
from typing import Optional, Any

class ProcessEventIn(BaseModel):
    asset_id: str
    process_id: int
    parent_process_id: Optional[int]
    image_path: Optional[str]
    command_line: Optional[str]
    user_context: Optional[str]
    event_type: Optional[str]
    event_time: Optional[str]

class DetectionCreate(BaseModel):
    asset_id: str
    detection_type: str
    severity: int = 1
    confidence: int = 50
    rule_id: Optional[str]
