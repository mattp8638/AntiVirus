from fastapi import APIRouter, Depends
from datetime import datetime
from sqlalchemy.orm import Session
import requests
from . import db, models, schemas, config

router = APIRouter(prefix="/rmm")

def get_db():
    s = db.SessionLocal()
    try:
        yield s
    finally:
        s.close()


@router.post("/configuration_profiles")
def create_profile(p: schemas.ConfigurationProfileCreate, session: Session = Depends(get_db)):
    prof = models.ConfigurationProfile(name=p.name, profile_type=p.profile_type, description=p.description)
    session.add(prof)
    session.commit()
    session.refresh(prof)
    return {"id": prof.id}


@router.post("/configuration_items")
def add_configuration_item(it: schemas.ConfigurationItemCreate, session: Session = Depends(get_db)):
    ci = models.ConfigurationItem(profile_id=it.profile_id, config_key=it.config_key, desired_value=it.desired_value, enforcement_mode=it.enforcement_mode)
    session.add(ci)
    session.commit()
    session.refresh(ci)
    return {"id": ci.id}


@router.post("/assign_profile")
def assign_profile(a: schemas.AssignProfileCreate, session: Session = Depends(get_db)):
    ap = models.AssetConfigurationProfile(asset_id=a.asset_id, profile_id=a.profile_id)
    session.add(ap)
    session.commit()
    session.refresh(ap)
    return {"id": ap.id}


@router.post("/patch_catalog")
def add_patch_catalog(p: schemas.PatchCatalogCreate, session: Session = Depends(get_db)):
    pc = models.PatchCatalog(vendor=p.vendor, product=p.product, patch_id=p.patch_id, severity=p.severity)
    session.add(pc)
    session.commit()
    session.refresh(pc)
    return {"id": pc.id}


@router.post("/patch_jobs")
def create_patch_job(job: schemas.PatchJobCreate, session: Session = Depends(get_db)):
    pj = models.PatchJob(psa_case_id=job.psa_case_id, scheduled_for=job.scheduled_for, reboot_policy=job.reboot_policy, status="scheduled")
    session.add(pj)
    session.commit()
    session.refresh(pj)

    # If PSA case id not provided, create a PSA case to track remediation
    if not job.psa_case_id:
        try:
            payload = {"organisation_id": "unknown", "title": "RMM patch job", "description": f"Patch job {pj.id}", "tags": ["rmm", "patch"]}
            r = requests.post(f"{config.PSA_BASE_URL}/psa/cases", json=payload, timeout=5)
            if r.status_code in (200,201):
                resp = r.json()
                pj.psa_case_id = str(resp.get("id") or resp.get("case_id") or "")
                session.add(pj)
                session.commit()
        except Exception:
            pass

    return {"id": pj.id, "psa_case_id": pj.psa_case_id}


@router.post("/script_results")
def record_script_result(r: schemas.ScriptResultCreate, session: Session = Depends(get_db)):
    sr = models.ScriptResult(job_id=r.job_id, stdout=r.stdout, stderr=r.stderr, exit_code=r.exit_code, hash=r.hash)
    session.add(sr)
    session.commit()
    session.refresh(sr)
    return {"id": sr.id}


@router.post("/remote_sessions")
def create_remote_session(s: schemas.RemoteSessionCreate, session: Session = Depends(get_db)):
    rs = models.RemoteSession(asset_id=s.asset_id, initiated_by=s.initiated_by, session_type=s.session_type, recorded=False)
    session.add(rs)
    session.commit()
    session.refresh(rs)
    return {"id": rs.id}


@router.post("/evidence")
def add_evidence(e: schemas.EvidenceCreate, session: Session = Depends(get_db)):
    ev = models.RMMEvidence(asset_id=e.asset_id, evidence_type=e.evidence_type, related_entity=e.related_entity, related_id=e.related_id, storage_uri=e.storage_uri, hash=e.hash)
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return {"id": ev.id}


@router.post("/device_inventory")
def add_device_inventory(inv: schemas.DeviceInventoryCreate, session: Session = Depends(get_db)):
    collected_at = None
    if inv.collected_at:
        try:
            collected_at = datetime.fromisoformat(inv.collected_at.replace("Z", "+00:00"))
        except ValueError:
            collected_at = None
    device = models.DeviceInventory(
        asset_id=inv.asset_id,
        hostname=inv.hostname,
        os_name=inv.os_name,
        os_version=inv.os_version,
        serial_number=inv.serial_number,
        collected_at=collected_at,
    )
    session.add(device)
    session.commit()
    session.refresh(device)
    return {"id": device.id}
