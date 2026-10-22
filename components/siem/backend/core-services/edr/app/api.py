from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from . import db, models, schemas
from core_services.common.escalation import EscalationClient

router = APIRouter()

def get_db():
    s = db.SessionLocal()
    try:
        yield s
    finally:
        s.close()

@router.post("/process_events")
def ingest_process(ev: schemas.ProcessEventIn, session: Session = Depends(get_db)):
    pe = models.ProcessEvent(
        asset_id=ev.asset_id,
        process_id=ev.process_id,
        parent_process_id=ev.parent_process_id,
        image_path=ev.image_path,
        command_line=ev.command_line,
        user_context=ev.user_context,
        event_type=ev.event_type,
    )
    session.add(pe)
    session.commit()
    session.refresh(pe)
    return {"id": pe.id}

@router.post("/detections")
def create_detection(d: schemas.DetectionCreate, session: Session = Depends(get_db)):
    det = models.EdrDetection(
        asset_id=d.asset_id,
        detection_type=d.detection_type,
        severity=d.severity,
        confidence=d.confidence,
        rule_id=d.rule_id,
    )
    session.add(det)
    session.commit()
    session.refresh(det)
    return {"id": det.id}

@router.post("/detections/{detection_id}/escalate")
def escalate_detection(detection_id: str, session: Session = Depends(get_db)):
    det = session.query(models.EdrDetection).filter(models.EdrDetection.id == detection_id).first()
    if not det:
        raise HTTPException(status_code=404, detail="Detection not found")

    client = EscalationClient()
    # organisation context should be attached to asset; kept simple here
    try:
        resp = client.create_case(organisation_id="", case_type="incident", source_system="edr", severity=det.severity)
        psa_case = resp.get("id") or resp
        det.psa_case_id = psa_case
        det.status = "escalated"
        session.commit()
        # record in shared escalations table
        session.execute("INSERT INTO escalations (source_service, source_id, organisation_id, psa_case_id, status) VALUES ($1,$2,$3,$4,$5)", ("edr", det.id, None, psa_case, "escalated"))
        session.commit()
        return {"psa_case_id": psa_case}
    except Exception as e:
        det.status = "escalation_failed"
        session.commit()
        raise HTTPException(status_code=500, detail=str(e))
