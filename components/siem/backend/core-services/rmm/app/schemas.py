from pydantic import BaseModel
from typing import Optional, Dict, Any

class ConfigurationProfileCreate(BaseModel):
    name: str
    profile_type: Optional[str]
    description: Optional[str]

class ConfigurationItemCreate(BaseModel):
    profile_id: str
    config_key: str
    desired_value: Optional[str]
    enforcement_mode: Optional[str]

class AssignProfileCreate(BaseModel):
    asset_id: str
    profile_id: str

class PatchCatalogCreate(BaseModel):
    vendor: Optional[str]
    product: Optional[str]
    patch_id: Optional[str]
    release_date: Optional[str]
    severity: Optional[int]

class PatchJobCreate(BaseModel):
    psa_case_id: Optional[str]
    scheduled_for: Optional[str]
    reboot_policy: Optional[str]

class ScriptCreate(BaseModel):
    name: str
    language: Optional[str]
    content: Optional[str]
    requires_approval: Optional[bool]

class ScriptResultCreate(BaseModel):
    job_id: str
    stdout: Optional[str]
    stderr: Optional[str]
    exit_code: Optional[int]
    hash: Optional[str]

class RemoteSessionCreate(BaseModel):
    asset_id: str
    initiated_by: Optional[str]
    session_type: Optional[str]

class EvidenceCreate(BaseModel):
    asset_id: str
    evidence_type: Optional[str]
    related_entity: Optional[str]
    related_id: Optional[str]
    storage_uri: Optional[str]
    hash: Optional[str]

class DeviceInventoryCreate(BaseModel):
    asset_id: str
    hostname: Optional[str]
    os_name: Optional[str]
    os_version: Optional[str]
    serial_number: Optional[str]
    collected_at: Optional[str]
