import uuid
from sqlalchemy import Column, String, Text, Boolean, TIMESTAMP, ForeignKey, JSON, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from .db import Base

def gen_uuid():
    return str(uuid.uuid4())

class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False)
    version = Column(String, nullable=True)
    authority = Column(String, nullable=True)
    description = Column(Text)

class ComplianceControl(Base):
    __tablename__ = "compliance_controls"
    id = Column(String, primary_key=True, default=gen_uuid)
    framework_id = Column(String, ForeignKey("compliance_frameworks.id"), nullable=False)
    control_code = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text)
    control_type = Column(String)

class ControlRelationship(Base):
    __tablename__ = "control_relationships"
    id = Column(String, primary_key=True, default=gen_uuid)
    control_id = Column(String, ForeignKey("compliance_controls.id"), nullable=False)
    related_control_id = Column(String, ForeignKey("compliance_controls.id"), nullable=False)
    relationship_type = Column(String)

class ControlApplicability(Base):
    __tablename__ = "control_applicability"
    id = Column(String, primary_key=True, default=gen_uuid)
    organisation_id = Column(String, nullable=False)
    control_id = Column(String, ForeignKey("compliance_controls.id"), nullable=False)
    applicable = Column(Boolean, default=True)
    justification = Column(Text)
    decided_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

class ControlAssessment(Base):
    __tablename__ = "control_assessments"
    id = Column(String, primary_key=True, default=gen_uuid)
    organisation_id = Column(String, nullable=False)
    control_id = Column(String, ForeignKey("compliance_controls.id"), nullable=False)
    assessment_status = Column(String)  # pass, fail, partial
    effectiveness = Column(String)  # effective, weak
    assessed_by = Column(String)
    assessed_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    notes = Column(Text)

class ControlEvidence(Base):
    __tablename__ = "control_evidence"
    id = Column(String, primary_key=True, default=gen_uuid)
    control_id = Column(String, ForeignKey("compliance_controls.id"), nullable=False)
    evidence_type = Column(String)
    source_system = Column(String)
    storage_uri = Column(String)
    hash = Column(String)
    valid_from = Column(TIMESTAMP(timezone=True))
    valid_to = Column(TIMESTAMP(timezone=True))

class EvidenceSource(Base):
    __tablename__ = "evidence_sources"
    id = Column(String, primary_key=True, default=gen_uuid)
    evidence_id = Column(String, ForeignKey("control_evidence.id"))
    originating_entity = Column(String)
    originating_id = Column(String)

class ControlGap(Base):
    __tablename__ = "control_gaps"
    id = Column(String, primary_key=True, default=gen_uuid)
    control_id = Column(String, ForeignKey("compliance_controls.id"), nullable=False)
    organisation_id = Column(String, nullable=False)
    gap_description = Column(Text)
    severity = Column(Integer)
    identified_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

class GapCase(Base):
    __tablename__ = "gap_cases"
    id = Column(String, primary_key=True, default=gen_uuid)
    gap_id = Column(String, ForeignKey("control_gaps.id"), nullable=False)
    psa_case_id = Column(String)

class ControlAttestation(Base):
    __tablename__ = "control_attestations"
    id = Column(String, primary_key=True, default=gen_uuid)
    control_id = Column(String, ForeignKey("compliance_controls.id"), nullable=False)
    organisation_id = Column(String, nullable=False)
    attested_by = Column(String)
    role = Column(String)
    statement = Column(Text)
    attested_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

class AuditSession(Base):
    __tablename__ = "audit_sessions"
    id = Column(String, primary_key=True, default=gen_uuid)
    organisation_id = Column(String, nullable=False)
    framework_id = Column(String, ForeignKey("compliance_frameworks.id"))
    started_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    completed_at = Column(TIMESTAMP(timezone=True))
    status = Column(String)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(String, primary_key=True, default=gen_uuid)
    audit_session_id = Column(String, ForeignKey("audit_sessions.id"))
    event_type = Column(String)
    actor_id = Column(String)
    timestamp = Column(TIMESTAMP(timezone=True), server_default=func.now())
    event_metadata = Column(JSON)
