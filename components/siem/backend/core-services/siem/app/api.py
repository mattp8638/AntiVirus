from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from . import db, models, schemas
from .rules import evaluate_rule
from core_services.common.escalation import EscalationClient

router = APIRouter()

def get_db():
    session = db.SessionLocal()
    try:
        yield session
    finally:
        session.close()

@router.post("/raw_events", response_model=schemas.RawEventOut)
def ingest_raw(event: schemas.RawEventIn, session: Session = Depends(get_db)):
    rv = models.RawEvent(
        source_system=event.source_system,
        event_time=event.event_time,
        payload=event.payload,
    )
    session.add(rv)
    session.commit()
    session.refresh(rv)
    return rv

@router.post("/events")
def create_event(event_in: schemas.EventIn, session: Session = Depends(get_db)):
    ev = models.Event(
        raw_event_id=event_in.raw_event_id,
        event_category=event_in.event_category,
        event_type=event_in.event_type,
        severity=event_in.severity or 1,
        asset_id=event_in.asset_id,
        user_id=event_in.user_id,
        source_ip=event_in.source_ip,
        destination_ip=event_in.destination_ip,
        event_time=event_in.event_time,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return {"id": ev.id}

@router.post("/findings")
def create_finding(f: schemas.FindingCreate, session: Session = Depends(get_db)):
    finding = models.SiemFinding(
        organisation_id=f.organisation_id,
        finding_type=f.finding_type,
        severity=f.severity,
        confidence=f.confidence,
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return {"id": finding.id}


@router.post("/rules/{rule_id}/evaluate")
def run_rule(rule_id: str, session: Session = Depends(get_db)):
    client = EscalationClient()
    try:
        res = evaluate_rule(rule_id=rule_id, session=session, escalation_client=client)
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/rules/evaluate_all")
def run_all_rules(session: Session = Depends(get_db)):
    rules = session.query(models.CorrelationRule).filter(models.CorrelationRule.enabled == True).all()
    client = EscalationClient()
    results = []
    for r in rules:
        try:
            results.append({"rule_id": r.id, "result": evaluate_rule(r.id, session=session, escalation_client=client)})
        except Exception as e:
            results.append({"rule_id": r.id, "error": str(e)})
    return results
