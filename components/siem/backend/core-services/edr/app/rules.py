from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from .models import EdrRule, ProcessEvent, EdrDetection, EdrEvidence
from core_services.common.escalation import EscalationClient

def evaluate_rule(rule_id: str, session: Session, escalation_client: EscalationClient | None = None) -> dict:
    rule = session.query(EdrRule).filter(EdrRule.id == rule_id).first()
    if not rule:
        raise ValueError("Rule not found")

    logic = rule.logic or {}
    # Example supported logic: {"event_type": "start", "image_contains": "powershell", "within_minutes": 5}
    event_type = logic.get("event_type")
    image_contains = logic.get("image_contains")
    within_minutes = int(logic.get("within_minutes", 5))

    window_start = datetime.utcnow() - timedelta(minutes=within_minutes)
    q = session.query(ProcessEvent).filter(ProcessEvent.event_time >= window_start)
    if event_type:
        q = q.filter(ProcessEvent.event_type == event_type)
    if image_contains:
        q = q.filter(ProcessEvent.image_path.ilike(f"%{image_contains}%"))

    hits = q.limit(50).all()
    if not hits:
        return {"matched": False}

    # create a detection summarising the matches
    det = EdrDetection(asset_id=hits[0].asset_id if hits else None, detection_type=rule.name or "behavioral", severity=rule.severity or 1, confidence=70, rule_id=rule.id)
    session.add(det)
    session.commit()
    session.refresh(det)

    # add evidence placeholder
    ev = EdrEvidence(detection_id=det.id, evidence_type="process_snapshot", storage_uri=f"edr://detection/{det.id}", hash="")
    session.add(ev)
    session.commit()

    result = {"detection_id": det.id, "matches": len(hits)}

    if escalation_client:
        try:
            resp = escalation_client.create_case(organisation_id="", case_type="incident", source_system="edr", severity=det.severity)
            psa_case = resp.get("id") or resp
            det.psa_case_id = psa_case
            det.status = "escalated"
            session.commit()
            result["psa_case_id"] = psa_case
            # record escalation row in shared escalations table
            session.execute("INSERT INTO escalations (source_service, source_id, organisation_id, psa_case_id, status) VALUES ($1,$2,$3,$4,$5)", ("edr", det.id, None, psa_case, "escalated"))
            session.commit()
        except Exception:
            det.status = "escalation_failed"
            session.commit()

    return result
