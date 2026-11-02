from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from . import db, models, schemas

router = APIRouter()

def get_db():
    db_session = db.SessionLocal()
    try:
        yield db_session
    finally:
        db_session.close()

@router.post("/cases", response_model=schemas.CaseOut)
def create_case(case_in: schemas.CaseCreate, session: Session = Depends(get_db)):
    case = models.Case(
        organisation_id=case_in.organisation_id,
        case_type=case_in.case_type,
        source_system=case_in.source_system,
        severity=case_in.severity,
    )
    session.add(case)
    session.commit()
    session.refresh(case)
    return case

@router.get("/cases", response_model=list[schemas.CaseOut])
def list_cases(skip: int = 0, limit: int = 50, session: Session = Depends(get_db)):
    cases = session.query(models.Case).offset(skip).limit(limit).all()
    return cases

@router.post("/cases/{case_id}/evidence")
def add_evidence(case_id: str, evidence: schemas.EvidenceCreate, session: Session = Depends(get_db)):
    case = session.query(models.Case).filter(models.Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    ev = models.EvidenceItem(
        case_id=case_id,
        evidence_type=evidence.evidence_type,
        source_system=evidence.source_system,
        stored_uri=evidence.stored_uri,
        hash=evidence.hash,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return {"id": ev.id}

@router.post("/cases/{case_id}/tasks")
def create_task(case_id: str, task_in: schemas.TaskCreate, session: Session = Depends(get_db)):
    case = session.query(models.Case).filter(models.Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    task = models.Task(case_id=case_id, task_type=task_in.task_type, assigned_to=task_in.assigned_to)
    session.add(task)
    session.commit()
    session.refresh(task)
    return {"id": task.id}
