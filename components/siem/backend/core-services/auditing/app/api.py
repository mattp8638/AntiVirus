from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import requests
from . import db, models, schemas, config

router = APIRouter(prefix="/auditing")

def get_db():
    db_session = db.SessionLocal()
    try:
        yield db_session
    finally:
        db_session.close()


@router.post("/frameworks")
def create_framework(fw: schemas.FrameworkCreate, session: Session = Depends(get_db)):
    f = models.ComplianceFramework(name=fw.name, version=fw.version, authority=fw.authority, description=fw.description)
    session.add(f)
    session.commit()
    session.refresh(f)
    return {"id": f.id}


@router.post("/controls")
def create_control(ctrl: schemas.ControlCreate, session: Session = Depends(get_db)):
    c = models.ComplianceControl(framework_id=ctrl.framework_id, control_code=ctrl.control_code, title=ctrl.title, description=ctrl.description, control_type=ctrl.control_type)
    session.add(c)
    session.commit()
    session.refresh(c)
    return {"id": c.id}


@router.post("/assessments")
def record_assessment(a: schemas.AssessmentCreate, session: Session = Depends(get_db)):
    asmt = models.ControlAssessment(organisation_id=a.organisation_id, control_id=a.control_id, assessment_status=a.assessment_status, effectiveness=a.effectiveness, assessed_by=a.assessed_by, notes=a.notes)
    session.add(asmt)
    session.commit()
    session.refresh(asmt)
    return {"id": asmt.id}


@router.post("/evidence")
def add_evidence(e: schemas.EvidenceCreate, session: Session = Depends(get_db)):
    ev = models.ControlEvidence(control_id=e.control_id, evidence_type=e.evidence_type, source_system=e.source_system, storage_uri=e.storage_uri, hash=e.hash)
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return {"id": ev.id}


@router.post("/gaps")
def create_gap(g: schemas.GapCreate, session: Session = Depends(get_db)):
    gap = models.ControlGap(control_id=g.control_id, organisation_id=g.organisation_id, gap_description=g.gap_description, severity=g.severity)
    session.add(gap)
    session.commit()
    session.refresh(gap)

    # create a PSA case via PSA API to track remediation (best-effort, synchronous)
    try:
        payload = {
            "organisation_id": g.organisation_id,
            "title": f"Compliance gap: {g.gap_description[:120]}",
            "description": g.gap_description,
            "tags": ["compliance", "gap"]
        }
        r = requests.post(f"{config.PSA_BASE_URL}/psa/cases", json=payload, timeout=5)
        if r.status_code in (200, 201):
            case = r.json()
            gc = models.GapCase(gap_id=gap.id, psa_case_id=str(case.get("id") or case.get("case_id") or ""))
            session.add(gc)
            session.commit()
            session.refresh(gc)
            return {"gap_id": gap.id, "psa_case_id": gc.psa_case_id}
        else:
            return {"gap_id": gap.id, "psa_error": r.text}
    except Exception as exc:
        return {"gap_id": gap.id, "psa_error": str(exc)}


@router.post("/audit_sessions")
def create_audit_session(org_id: str, framework_id: str, session: Session = Depends(get_db)):
    s = models.AuditSession(organisation_id=org_id, framework_id=framework_id, status="started")
    session.add(s)
    session.commit()
    session.refresh(s)
    return {"id": s.id}


@router.post("/audit_events")
def add_audit_event(ev: schemas.AuditEventCreate, session: Session = Depends(get_db)):
    e = models.AuditEvent(audit_session_id=ev.audit_session_id, event_type=ev.event_type, actor_id=ev.actor_id, metadata=ev.metadata)
    session.add(e)
    session.commit()
    session.refresh(e)
    return {"id": e.id}
