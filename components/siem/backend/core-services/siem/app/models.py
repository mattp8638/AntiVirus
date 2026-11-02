import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Integer, ForeignKey, JSON, Text, Boolean
from sqlalchemy.orm import relationship
from .db import Base

def gen_uuid():
    return str(uuid.uuid4())

class RawEvent(Base):
    __tablename__ = "raw_events"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    source_system = Column(Text)
    received_at = Column(DateTime, default=datetime.utcnow)
    event_time = Column(DateTime)
    payload = Column(JSON)
    payload_hash = Column(Text)
    ingestion_node = Column(Text)

class Event(Base):
    __tablename__ = "events"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    raw_event_id = Column(String(36), ForeignKey("raw_events.id"))
    event_category = Column(Text)
    event_type = Column(Text)
    severity = Column(Integer, default=1)
    asset_id = Column(String(36))
    user_id = Column(String(36), nullable=True)
    source_ip = Column(Text)
    destination_ip = Column(Text)
    event_time = Column(DateTime)
    raw = relationship("RawEvent")

class EventTag(Base):
    __tablename__ = "event_tags"
    event_id = Column(String(36), ForeignKey("events.id"), primary_key=True)
    tag = Column(Text, primary_key=True)

class EventEnrichment(Base):
    __tablename__ = "event_enrichment"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    event_id = Column(String(36), ForeignKey("events.id"))
    enrichment_type = Column(Text)
    enrichment_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)

class CorrelationRule(Base):
    __tablename__ = "correlation_rules"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    name = Column(Text)
    description = Column(Text)
    logic = Column(JSON)
    enabled = Column(Boolean, default=True)
    severity = Column(Integer, default=1)

class CorrelationHit(Base):
    __tablename__ = "correlation_hits"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    rule_id = Column(String(36), ForeignKey("correlation_rules.id"))
    triggered_at = Column(DateTime, default=datetime.utcnow)
    event_ids = Column(JSON, default=list)
    confidence = Column(Integer, default=50)

class SiemFinding(Base):
    __tablename__ = "siem_findings"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    organisation_id = Column(String(36))
    finding_type = Column(Text)
    severity = Column(Integer, default=1)
    confidence = Column(Integer, default=50)
    status = Column(Text, default="new")
    created_at = Column(DateTime, default=datetime.utcnow)
    psa_case_id = Column(String(36), nullable=True)

class FindingEvent(Base):
    __tablename__ = "finding_events"
    finding_id = Column(String(36), ForeignKey("siem_findings.id"), primary_key=True)
    event_id = Column(String(36), ForeignKey("events.id"), primary_key=True)

class EvidencePackage(Base):
    __tablename__ = "evidence_packages"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    finding_id = Column(String(36), ForeignKey("siem_findings.id"))
    package_uri = Column(Text)
    hash = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class Escalation(Base):
    __tablename__ = "escalations"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    source_service = Column(Text, nullable=False)
    source_id = Column(String(36))
    organisation_id = Column(String(36))
    psa_case_id = Column(String(36), nullable=True)
    status = Column(Text, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)

