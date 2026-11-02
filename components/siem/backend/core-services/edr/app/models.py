import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Integer, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from .db import Base

def gen_uuid():
    return str(uuid.uuid4())

class ProcessEvent(Base):
    __tablename__ = "process_events"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    asset_id = Column(String(36))
    process_id = Column(Integer)
    parent_process_id = Column(Integer)
    image_path = Column(Text)
    command_line = Column(Text)
    user_context = Column(Text)
    event_type = Column(Text)
    event_time = Column(DateTime, default=datetime.utcnow)

class FileEvent(Base):
    __tablename__ = "file_events"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    asset_id = Column(String(36))
    process_event_id = Column(String(36), ForeignKey("process_events.id"))
    file_path = Column(Text)
    action = Column(Text)
    hash = Column(Text)
    event_time = Column(DateTime, default=datetime.utcnow)

class NetworkEvent(Base):
    __tablename__ = "network_events"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    asset_id = Column(String(36))
    process_event_id = Column(String(36), ForeignKey("process_events.id"))
    local_ip = Column(Text)
    remote_ip = Column(Text)
    remote_port = Column(Integer)
    protocol = Column(Text)
    event_time = Column(DateTime, default=datetime.utcnow)

class EdrRule(Base):
    __tablename__ = "edr_rules"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    name = Column(Text)
    description = Column(Text)
    logic = Column(JSON)
    severity = Column(Integer, default=1)
    enabled = Column(Integer, default=1)

class EdrDetection(Base):
    __tablename__ = "edr_detections"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    asset_id = Column(String(36))
    detection_type = Column(Text)
    severity = Column(Integer, default=1)
    confidence = Column(Integer, default=50)
    rule_id = Column(String(36), ForeignKey("edr_rules.id"))
    status = Column(Text, default="new")
    detected_at = Column(DateTime, default=datetime.utcnow)
    siem_event_id = Column(String(36), nullable=True)
    psa_case_id = Column(String(36), nullable=True)

class DetectionEvent(Base):
    __tablename__ = "detection_events"
    detection_id = Column(String(36), ForeignKey("edr_detections.id"), primary_key=True)
    related_event_id = Column(String(36), primary_key=True)
    event_type = Column(Text)

class ResponseAction(Base):
    __tablename__ = "response_actions"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    detection_id = Column(String(36), ForeignKey("edr_detections.id"))
    action_type = Column(Text)
    initiated_by = Column(Text)
    status = Column(Text, default="pending")
    executed_at = Column(DateTime, nullable=True)

class EndpointIsolation(Base):
    __tablename__ = "endpoint_isolation_state"
    asset_id = Column(String(36), primary_key=True)
    isolated = Column(Integer, default=0)
    reason = Column(Text)
    since = Column(DateTime, default=datetime.utcnow)

class EdrEvidence(Base):
    __tablename__ = "edr_evidence"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    detection_id = Column(String(36), ForeignKey("edr_detections.id"))
    evidence_type = Column(Text)
    storage_uri = Column(Text)
    hash = Column(Text)
    captured_at = Column(DateTime, default=datetime.utcnow)
