from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from .models import CorrelationRule, Event, CorrelationHit, SiemFinding, FindingEvent, EvidencePackage, Escalation
from typing import Protocol, Any, Dict

# Define a minimal protocol for the external EscalationClient so this module
# doesn't require the external package to be importable in all environments.
class EscalationClient(Protocol):
    def create_case(self, organisation_id: str, case_type: str, source_system: str, severity: int) -> Dict[str, Any]:
        ...

import json


def evaluate_rule(rule_id: str, session: Session, escalation_client: EscalationClient | None = None) -> dict:
    """Evaluate a correlation rule and, if hit, create correlation_hit, finding and escalate to PSA.

    Rules are stored as JSON in `logic`. Supported pattern (simple):
    {"match_event_type": "login_failed", "count": 5, "within_minutes": 10}
    """
    rule = session.query(CorrelationRule).filter(CorrelationRule.id == rule_id).first()
    if not rule:
        raise ValueError("Rule not found")

    logic = rule.logic or {}
    # Basic implementation for the supported pattern
    match_type = logic.get("match_event_type")
    count_needed = int(logic.get("count", 1))
    within_minutes = int(logic.get("within_minutes", 60))

    window_start = datetime.utcnow() - timedelta(minutes=within_minutes)
    q = session.query(Event).filter(Event.event_time >= window_start)
    if match_type:
        q = q.filter(Event.event_type == match_type)

    events = q.order_by(Event.event_time.desc()).limit(100).all()
    if len(events) >= count_needed:
        event_ids = [e.id for e in events[:count_needed]]
        hit = CorrelationHit(rule_id=rule.id, event_ids=event_ids, confidence=80)
        session.add(hit)
        session.commit()
        session.refresh(hit)

        # create a finding
        finding = SiemFinding(
            organisation_id=None,
            finding_type=rule.name or "correlation",
            severity=rule.severity or 1,
            confidence=80,
            status="new",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)

        # link events to finding
        for eid in event_ids:
            fe = FindingEvent(finding_id=finding.id, event_id=eid)
            session.add(fe)
        session.commit()

        # create simple evidence package placeholder (real packaging handled elsewhere)
        pkg = EvidencePackage(finding_id=finding.id, package_uri=f"siem://finding/{finding.id}", hash="")
        session.add(pkg)
        session.commit()

        # store escalation record
        esc = Escalation(source_service="siem", source_id=finding.id, organisation_id=None, status="pending")
        session.add(esc)
        session.commit()
        session.refresh(esc)

        result = {"hit_id": hit.id, "finding_id": finding.id, "escalation_id": esc.id}

        # escalate to PSA if client provided
        if escalation_client:
            try:
                # organisation_id left None above; callers should fill organisation context if available
                case_resp = escalation_client.create_case(organisation_id=esc.organisation_id or "", case_type="incident", source_system="siem", severity=finding.severity)
                psa_case = case_resp.get("id") or case_resp
                finding.psa_case_id = psa_case
                esc.psa_case_id = psa_case
                esc.status = "escalated"
                session.commit()
                result["psa_case_id"] = psa_case
            except Exception:
                esc.status = "failed"
                session.commit()

        return result
