"""EDR Pydantic Schemas"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class AgentRegister(BaseModel):
    """Agent registration request"""
    agent_id: str
    hostname: str
    os_version: str
    ip_address: str
    agent_version: str


class AgentInfo(BaseModel):
    """Agent information response"""
    id: int
    agent_id: str
    hostname: str
    os_version: str
    ip_address: str
    agent_version: str
    status: str
    last_seen: datetime
    registered_at: datetime
    
    class Config:
        from_attributes = True


class EDREventCreate(BaseModel):
    """Create EDR event"""
    agent_id: str
    event_type: str
    timestamp: Optional[datetime] = None
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    parent_process_id: Optional[int] = None
    user: Optional[str] = None
    severity: str = "info"
    raw_data: Optional[Dict[str, Any]] = None


class EDREventResponse(BaseModel):
    """EDR event response"""
    id: int
    agent_id: str
    event_type: str
    timestamp: datetime
    process_id: Optional[int]
    process_name: Optional[str]
    command_line: Optional[str]
    severity: str
    
    class Config:
        from_attributes = True


class ThreatDetection(BaseModel):
    """Threat detection report"""
    agent_id: str
    threat_type: str
    threat_name: str
    severity: str
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []
    indicators: List[str] = []
    ml_score: Optional[float] = None


class ThreatResponse(BaseModel):
    """Threat response"""
    id: int
    agent_id: str
    threat_type: str
    threat_name: str
    severity: str
    status: str
    process_name: Optional[str]
    file_path: Optional[str]
    file_hash: Optional[str]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    ml_score: Optional[float]
    timestamp: datetime
    
    class Config:
        from_attributes = True


class AgentCommand(BaseModel):
    """Command to send to agent"""
    agent_id: str
    command_type: str  # scan, isolate, kill_process, quarantine
    parameters: Dict[str, Any] = {}


class ProcessInfo(BaseModel):
    """Process information"""
    process_id: int
    process_name: str
    command_line: Optional[str]
    user: Optional[str]
    cpu_percent: Optional[float]
    memory_mb: Optional[float]


class NetworkConnectionInfo(BaseModel):
    """Network connection information"""
    process_name: str
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str


class FileOperationInfo(BaseModel):
    """File operation information"""
    process_name: str
    operation_type: str
    file_path: str
    timestamp: datetime
