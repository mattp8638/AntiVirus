"""Suppliers and incidents in the ISMS, built on Fenrir's own registers.

Suppliers stay in third-party risk (``tprm.py``); the ISMS links each one to the assets, risks and controls it touches
and shows its tier and review state. Incidents stay with the SOC; the ISMS adds its view of each one (category,
personal data and regulator notice, root cause, lessons learned and the controls involved), and the closure rules
come from ``domain/suppliers.py``. Every change is audited.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..models import Incident, Vendor, utcnow
from .domain._js import iso_instant, js_trim
from .domain.suppliers import breach_deadline, closure_blockers
from .models import IsmsAsset, IsmsIncidentReview, IsmsRisk, IsmsSupplierLink, IsmsTenantControl

CATEGORIES = ("malware", "phishing", "unauthorized_access", "data_loss", "availability", "physical", "supplier",
              "other")
LINK_TYPES = {"asset": IsmsAsset, "risk": IsmsRisk, "control": IsmsTenantControl}


def _error(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status, message)


def _label(row) -> str:
    ref = getattr(row, "ref", None)
    name = getattr(row, "title", None) or getattr(row, "name", "")
    return f"{ref} {name}" if ref else name


# Suppliers --------------------------------------------------------------------------------------------------------

def supplier_rows(db: Session, tenant_id: str) -> list[dict]:
    vendors = db.execute(select(Vendor).where(Vendor.tenant_id == tenant_id).order_by(Vendor.name)).scalars().all()
    links = db.execute(select(IsmsSupplierLink).where(IsmsSupplierLink.tenant_id == tenant_id)).scalars().all()
    targets = {}
    for kind, model in LINK_TYPES.items():
        ids = {lk.target_id for lk in links if lk.target_type == kind}
        if ids:
            targets.update({(kind, r.id): r for r in db.execute(select(model).where(model.id.in_(ids))).scalars()})
    now = utcnow()
    out = []
    for v in vendors:
        mine = [lk for lk in links if lk.vendor_id == v.id and (lk.target_type, lk.target_id) in targets]
        out.append({"id": v.id, "name": v.name, "services": v.services, "criticality": v.criticality,
                    "dataAccess": v.data_access, "status": v.status, "riskTier": v.risk_tier, "riskScore": v.risk_score,
                    "owner": v.owner, "nextReviewAt": iso_instant(v.next_review_at) if v.next_review_at else None,
                    "reviewOverdue": bool(v.next_review_at and v.next_review_at < now and v.status == "active"),
                    "links": [{"id": lk.id, "type": lk.target_type, "targetId": lk.target_id,
                               "label": _label(targets[(lk.target_type, lk.target_id)])} for lk in mine]})
    return out


def link_supplier(db: Session, tenant_id: str, actor: str, vendor_id: str, target_type: str, target_id: str) -> None:
    vendor = db.get(Vendor, vendor_id)
    if vendor is None or vendor.tenant_id != tenant_id:
        raise _error("Supplier not found.", 404)
    model = LINK_TYPES.get(target_type)
    if model is None:
        raise _error("Link a supplier to an asset, a risk or a control.")
    target = db.get(model, target_id)
    if target is None or target.tenant_id != tenant_id:
        raise _error("Not found.", 404)
    if db.execute(select(IsmsSupplierLink.id).where(IsmsSupplierLink.vendor_id == vendor_id,
                                                    IsmsSupplierLink.target_type == target_type,
                                                    IsmsSupplierLink.target_id == target_id)).first():
        return
    db.add(IsmsSupplierLink(tenant_id=tenant_id, vendor_id=vendor_id, target_type=target_type, target_id=target_id,
                            updated_by=actor))
    audit.record(db, actor, "isms.supplier_linked", vendor.name, tenant_id, vendor_id=vendor_id, type=target_type,
                 target_id=target_id)


def unlink_supplier(db: Session, row: IsmsSupplierLink, actor: str) -> None:
    db.delete(row)
    audit.record(db, actor, "isms.supplier_unlinked", row.vendor_id, row.tenant_id, type=row.target_type,
                 target_id=row.target_id)


# Incidents --------------------------------------------------------------------------------------------------------

def _review_for(db: Session, incident: Incident) -> IsmsIncidentReview | None:
    return db.execute(select(IsmsIncidentReview).where(IsmsIncidentReview.incident_id == incident.id)).scalar_one_or_none()


def _soc_severity(severity: str) -> str:
    return severity if severity in ("low", "medium", "high", "critical") else "medium"


def incident_view(db: Session, incident: Incident, review: IsmsIncidentReview | None,
                  controls: dict[str, IsmsTenantControl], vendors: dict[str, Vendor]) -> dict:
    r = review
    severity = _soc_severity(incident.severity)
    reported = iso_instant(r.reported_to_authority_at) if r and r.reported_to_authority_at else None
    blockers = closure_blockers(severity, r.root_cause if r else "", r.lessons_learned if r else "",
                                bool(r and r.personal_data), reported)
    return {
        "id": incident.id, "title": incident.title, "severity": severity, "socStatus": incident.status,
        "detectedAt": iso_instant(incident.created_at), "assignee": incident.assignee,
        "reviewId": r.id if r else None, "category": r.category if r else None,
        "personalData": bool(r and r.personal_data), "reportedToAuthorityAt": reported,
        "breachDeadline": breach_deadline(iso_instant(incident.created_at)) if r and r.personal_data else None,
        "vendorId": r.vendor_id if r else None,
        "vendorName": vendors[r.vendor_id].name if r and r.vendor_id in vendors else None,
        "rootCause": r.root_cause if r else "", "lessonsLearned": r.lessons_learned if r else "",
        "controls": [{"id": c, "ref": controls[c].ref, "title": controls[c].title}
                     for c in (r.control_ids if r else []) if c in controls],
        "status": r.status if r else "not_started",
        "completedAt": iso_instant(r.completed_at) if r and r.completed_at else None,
        "blockers": blockers,
    }


def incident_rows(db: Session, tenant_id: str, incident_id: str | None = None) -> list[dict]:
    q = select(Incident).where(Incident.tenant_id == tenant_id)
    if incident_id:
        q = q.where(Incident.id == incident_id)
    incidents = db.execute(q.order_by(Incident.created_at.desc()).limit(500)).scalars().all()
    reviews = {r.incident_id: r for r in db.execute(select(IsmsIncidentReview).where(
        IsmsIncidentReview.tenant_id == tenant_id)).scalars()}
    controls = {c.id: c for c in db.execute(select(IsmsTenantControl).where(
        IsmsTenantControl.tenant_id == tenant_id)).scalars()}
    vendors = {v.id: v for v in db.execute(select(Vendor).where(Vendor.tenant_id == tenant_id)).scalars()}
    return [incident_view(db, i, reviews.get(i.id), controls, vendors) for i in incidents]


def _parse_instant(value) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise _error("Give the date and time it was reported.") from None
    if dt.tzinfo is not None:  # stored as naive UTC, like every other Fenrir timestamp
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def save_review(db: Session, incident: Incident, actor: str, data: dict) -> IsmsIncidentReview:
    row = _review_for(db, incident)
    if row is not None and row.status == "complete":
        raise _error("The incident review is complete. Reopen it to change it.")
    category = data.get("category") or "other"
    if category not in CATEGORIES:
        raise _error("Choose a category.")
    control_ids = list(dict.fromkeys(str(c) for c in (data.get("controlIds") or [])))
    known = set(db.execute(select(IsmsTenantControl.id).where(IsmsTenantControl.tenant_id == incident.tenant_id,
                                                              IsmsTenantControl.id.in_(control_ids))).scalars()) \
        if control_ids else set()
    if set(control_ids) - known:
        raise _error("Unknown control.")
    vendor_id = data.get("vendorId") or None
    if vendor_id:
        v = db.get(Vendor, vendor_id)
        if v is None or v.tenant_id != incident.tenant_id:
            raise _error("Supplier not found.")
    values = {"category": category, "personal_data": bool(data.get("personalData")),
              "reported_to_authority_at": _parse_instant(data.get("reportedToAuthorityAt")), "vendor_id": vendor_id,
              "root_cause": js_trim(str(data.get("rootCause") or ""))[:8000],
              "lessons_learned": js_trim(str(data.get("lessonsLearned") or ""))[:8000], "control_ids": control_ids}
    if row is None:
        row = IsmsIncidentReview(tenant_id=incident.tenant_id, incident_id=incident.id, updated_by=actor, **values)
        db.add(row)
    else:
        for k, v in values.items():
            setattr(row, k, v)
        row.updated_by, row.updated_at = actor, utcnow()
    db.flush()
    audit.record(db, actor, "isms.incident_review_saved", incident.title, incident.tenant_id, incident_id=incident.id,
                 category=category, personal_data=row.personal_data)
    return row


def complete_review(db: Session, incident: Incident, actor: str) -> None:
    row = _review_for(db, incident)
    if row is None:
        raise _error("Record the ISMS review first.")
    if incident.status not in ("resolved", "closed"):
        raise _error("The SOC must resolve the incident first.")
    view = incident_rows(db, incident.tenant_id, incident.id)[0]
    if view["blockers"]:
        raise _error(" ".join(view["blockers"]))
    row.status, row.completed_at, row.updated_by = "complete", utcnow(), actor
    audit.record(db, actor, "isms.incident_review_completed", incident.title, incident.tenant_id,
                 incident_id=incident.id)
    from .notify import emit
    emit(db, incident.tenant_id, "isms.incident_review_completed", incidentId=incident.id, category=row.category,
         personalData=row.personal_data)


def reopen_review(db: Session, incident: Incident, actor: str) -> None:
    row = _review_for(db, incident)
    if row is None or row.status != "complete":
        return
    row.status, row.completed_at, row.updated_by = "open", None, actor
    audit.record(db, actor, "isms.incident_review_reopened", incident.title, incident.tenant_id,
                 incident_id=incident.id)
