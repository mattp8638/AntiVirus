"""EDR Data Models"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, Text, Float, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from app.core.database import Base


class EDRAgent(Base):
    """EDR Agent/Endpoint"""
    __tablename__ = "edr_agents"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(255), unique=True, index=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    os_version = Column(String(255))
    ip_address = Column(String(45))  # IPv6 support
    mac_address = Column(String(17))
    agent_version = Column(String(50))
    status = Column(String(50), default="online")  # online, offline, isolated
    last_seen = Column(DateTime, default=datetime.utcnow)
    registered_at = Column(DateTime, default=datetime.utcnow)
    tags = Column(JSON, default=list)
    metadata = Column(JSON, default=dict)
    
    # Relationships
    events = relationship("EDREvent", back_populates="agent")
    threats = relationship("EDRThreat", back_populates="agent")


class EDREvent(Base):
    """EDR Telemetry Event"""
    __tablename__ = "edr_events"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(255), ForeignKey("edr_agents.agent_id"), index=True)
    event_type = Column(String(100), index=True)  # process_create, file_write, network_connect, etc.
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Process info
    process_id = Column(Integer)
    process_name = Column(String(255))
    command_line = Column(Text)
    parent_process_id = Column(Integer)
    user = Column(String(255))
    
    # Event data
    severity = Column(String(50), index=True)  # info, low, medium, high, critical
    raw_data = Column(JSON)
    
    # Relationships
    agent = relationship("EDRAgent", back_populates="events")


class EDRThreat(Base):
    """Detected Threat"""
    __tablename__ = "edr_threats"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(255), ForeignKey("edr_agents.agent_id"), index=True)
    threat_type = Column(String(100))  # malware, ransomware, apt, etc.
    threat_name = Column(String(255))
    severity = Column(String(50), index=True)
    status = Column(String(50), default="detected")  # detected, investigating, contained, resolved
    
    # Process/file info
    process_id = Column(Integer)
    process_name = Column(String(255))
    file_path = Column(Text)
    file_hash = Column(String(64), index=True)  # SHA256
    
    # MITRE ATT&CK mapping
    mitre_tactics = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    
    # Detection info
    indicators = Column(JSON, default=list)
    ml_score = Column(Float)  # 0.0 - 100.0
    
    # Response
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    responded_at = Column(DateTime)
    responded_by = Column(String(255))
    
    # Relationships
    agent = relationship("EDRAgent", back_populates="threats")


class EDRProcess(Base):
    """Running Process"""
    __tablename__ = "edr_processes"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(255), index=True)
    process_id = Column(Integer)
    process_name = Column(String(255))
    command_line = Column(Text)
    parent_process_id = Column(Integer)
    user = Column(String(255))
    start_time = Column(DateTime, default=datetime.utcnow)
    is_running = Column(Boolean, default=True)
    cpu_percent = Column(Float)
    memory_mb = Column(Float)


class EDRNetworkConnection(Base):
    """Network Connection"""
    __tablename__ = "edr_network_connections"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(255), index=True)
    process_id = Column(Integer)
    process_name = Column(String(255))
    protocol = Column(String(10))  # TCP, UDP
    local_address = Column(String(45))
    local_port = Column(Integer)
    remote_address = Column(String(45), index=True)
    remote_port = Column(Integer)
    state = Column(String(50))  # ESTABLISHED, LISTEN, etc.
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)
    timestamp = Column(DateTime, default=datetime.utcnow)


class EDRFileOperation(Base):
    """File System Operation"""
    __tablename__ = "edr_file_operations"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(255), index=True)
    process_id = Column(Integer)
    process_name = Column(String(255))
    operation_type = Column(String(50), index=True)  # create, write, delete, rename
    file_path = Column(Text)
    file_hash = Column(String(64))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
