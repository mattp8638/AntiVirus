"""Additional SOC workflows reuse canonical events, rules, alerts and incidents."""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .. import audit, detection, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import Device, Incident, IncidentEvidence, AlertSuppression, DetectionRule, utcnow
from ..serialize import to_dict
from .documentation import owned

router = APIRouter(prefix="/api/console/soc", tags=["SOC workflows"])

class EvidenceInput(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=100000)

class SuppressionInput(BaseModel):
    tenantId: str
    ruleId: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=1000)
    expiresAt: datetime

class ExternalEvent(BaseModel):
    eventId: str = Field(min_length=1, max_length=200)
    eventType: str = Field(min_length=1, max_length=100)
    summary: str = Field(default="", max_length=4000)
    occurredAt: datetime | None = None
    payload: dict = Field(default_factory=dict)

class IngestInput(BaseModel):
    deviceId: str
    source: str = Field(min_length=1, max_length=60, pattern=r"^[a-zA-Z0-9_.-]+$")
    events: list[ExternalEvent] = Field(min_length=1, max_length=100)

@router.post("/ingest")
def ingest(body: IngestInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    device = owned(db, Device, body.deviceId, principal)
    ratelimit.check(f"external-ingest:{principal.user.id}", 30, 60)
    rows = []
    for item in body.events:
        row = item.model_dump(mode="json", exclude_none=True)
        if len(json.dumps(row)) > 100000:
            raise HTTPException(413, "An external event exceeds 100KB")
        row["eventId"] = "ext-" + hashlib.sha256((body.source + ":" + item.eventId).encode()).hexdigest()
        row["source"] = "external:" + body.source
        rows.append(row)
    result = detection.ingest(db, device, rows, apply_device_effects=False)
    audit.record(db, principal.actor, "soc.external_ingest", device.id, device.tenant_id, source=body.source, accepted=result.accepted)
    db.commit()
    return {"accepted": result.accepted, "duplicates": result.duplicates, "alerts": result.alerts}

@router.get("/incidents/{incident_id}/evidence")
def evidence(incident_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    owned(db, Incident, incident_id, principal)
    return [to_dict(row) for row in db.scalars(select(IncidentEvidence).where(IncidentEvidence.incident_id == incident_id).order_by(IncidentEvidence.created_at.desc()).limit(500))]

@router.post("/incidents/{incident_id}/evidence")
def attach(incident_id: str, body: EvidenceInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    incident = owned(db, Incident, incident_id, principal)
    row = IncidentEvidence(incident_id=incident.id, tenant_id=incident.tenant_id, name=body.name, content=body.content,
                           sha256=hashlib.sha256(body.content.encode()).hexdigest(), author=principal.actor)
    db.add(row)
    db.flush()
    audit.record(db, principal.actor, "soc.evidence_added", row.id, row.tenant_id, sha256=row.sha256, incident=incident.id)
    db.commit()
    return to_dict(row)

@router.get("/suppressions")
def suppressions(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    return [to_dict(row) for row in db.scalars(select(AlertSuppression).where(AlertSuppression.tenant_id.in_(scoped_tenant(principal, tenant_id)), AlertSuppression.expires_at > utcnow()).limit(1000))]

@router.post("/suppressions")
def suppress(body: SuppressionInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    principal.check_tenant(body.tenantId)
    expiry = body.expiresAt.astimezone(timezone.utc).replace(tzinfo=None) if body.expiresAt.tzinfo else body.expiresAt
    if not utcnow() < expiry <= utcnow() + timedelta(days=30):
        raise HTTPException(400, "Suppression must expire within 30 days")
    rule = db.get(DetectionRule, body.ruleId)
    if rule is None or rule.tenant_id not in (None, body.tenantId):
        raise HTTPException(404, "Rule not found in this tenant")
    row = AlertSuppression(tenant_id=body.tenantId, rule_id=body.ruleId, reason=body.reason, expires_at=expiry, created_by=principal.actor)
    db.add(row)
    db.flush()
    audit.record(db, principal.actor, "soc.suppression_created", row.id, row.tenant_id, rule=row.rule_id, reason=row.reason)
    db.commit()
    return to_dict(row)

@router.delete("/suppressions/{suppression_id}")
def unsuppress(suppression_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = owned(db, AlertSuppression, suppression_id, principal)
    row.expires_at = utcnow()
    audit.record(db, principal.actor, "soc.suppression_revoked", row.id, row.tenant_id)
    db.commit()
    return {"ok": True}
