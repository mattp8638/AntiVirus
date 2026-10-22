from pydantic import BaseModel
from typing import Optional, Any, Dict

class FrameworkCreate(BaseModel):
    name: str
    version: Optional[str]
    authority: Optional[str]
    description: Optional[str]

class ControlCreate(BaseModel):
    framework_id: str
    control_code: str
    title: str
    description: Optional[str]
    control_type: Optional[str]

class AssessmentCreate(BaseModel):
    organisation_id: str
    control_id: str
    assessment_status: str
    effectiveness: Optional[str]
    assessed_by: Optional[str]
    notes: Optional[str]

class EvidenceCreate(BaseModel):
    control_id: str
    evidence_type: Optional[str]
    source_system: Optional[str]
    storage_uri: Optional[str]
    hash: Optional[str]
    valid_from: Optional[str]
    valid_to: Optional[str]

class GapCreate(BaseModel):
    control_id: str
    organisation_id: str
    gap_description: str
    severity: Optional[int] = 3

class AuditEventCreate(BaseModel):
    audit_session_id: str
    event_type: str
    actor_id: Optional[str]
    metadata: Optional[Dict[str, Any]]
