"""Privacy (ported from the standalone app's ``packages/programme/src/privacy.ts``): records of processing (UK GDPR
article 30), DPIAs (articles 35 and 36) and data subject requests (articles 12 and 15 to 22).

The rules (gaps in a record, DPIA screening, risk levels, prior consultation, request deadlines) are the pure
functions in ``domain/privacy.py``, held to the standalone app by the parity test. Suppliers that receive the data
are Fenrir's third-party risk suppliers. Records are retired and requests closed, never deleted; an approved DPIA is
frozen (guard in ``models.py``). Every change is audited.
"""

from __future__ import annotations

import re
from datetime import date

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..models import User, Vendor, utcnow
from .domain._js import iso_instant, js_trim
from .domain.privacy import (DPIA_SCREENING, DSR_TYPE_LABEL, DSR_TYPES, LAWFUL_BASES, LAWFUL_BASIS_LABEL,
                             TRANSFER_SAFEGUARD_LABEL, TRANSFER_SAFEGUARDS, ProcessingRecord, add_calendar_months,
                             dpia_required, dpia_risk_level, dsr_deadline, prior_consultation_needed, processing_gaps)
from .models import IsmsDataSubjectRequest, IsmsDpia, IsmsProcessingActivity

ROLES = ("controller", "processor", "joint_controller")
LEVELS = ("low", "medium", "high")
OUTCOMES = ("proceed", "proceed_with_measures", "do_not_proceed")


def _error(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status, message)


def _today() -> date:
    return utcnow().date()


def _day(value, message: str) -> date:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        raise _error(message) from None


def _names(db: Session, ids) -> dict[str, str]:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return {u.id: (u.name or u.email) for u in db.execute(select(User).where(User.id.in_(ids))).scalars()}


def _next_ref(db: Session, model, tenant_id: str, prefix: str) -> str:
    refs = db.execute(select(model.ref).where(model.tenant_id == tenant_id)).scalars()
    n = max((int(r.split("-")[1]) for r in refs if re.fullmatch(rf"{prefix}-\d+", r)), default=0) + 1
    return f"{prefix}-{n:03d}"


def _list(value) -> list[str]:
    return list(dict.fromkeys(js_trim(str(v))[:120] for v in (value or []) if js_trim(str(v))))[:50]


def options() -> dict:
    return {"lawfulBases": [{"key": k, "label": LAWFUL_BASIS_LABEL[k]} for k in LAWFUL_BASES],
            "safeguards": [{"key": k, "label": TRANSFER_SAFEGUARD_LABEL[k]} for k in TRANSFER_SAFEGUARDS],
            "screening": [{"key": k, "strong": strong, "text": text} for k, strong, text in DPIA_SCREENING],
            "requestTypes": [{"key": k, "label": DSR_TYPE_LABEL[k]} for k in DSR_TYPES], "roles": list(ROLES)}


# Records of processing ----------------------------------------------------------------------------------------

def processing_rows(db: Session, tenant_id: str, processing_id: str | None = None) -> list[dict]:
    q = select(IsmsProcessingActivity).where(IsmsProcessingActivity.tenant_id == tenant_id)
    if processing_id:
        q = q.where(IsmsProcessingActivity.id == processing_id)
    rows = db.execute(q).scalars().all()
    rows.sort(key=lambda r: (r.status, r.ref))
    dpias = db.execute(select(IsmsDpia).where(IsmsDpia.tenant_id == tenant_id)).scalars().all()
    vendors = {v.id: v.name for v in db.execute(select(Vendor).where(Vendor.tenant_id == tenant_id)).scalars()}
    names = _names(db, [r.owner_user_id for r in rows])
    today = _today()
    out = []
    for r in rows:
        mine = sorted((d for d in dpias if d.processing_id == r.id), key=lambda d: d.ref)
        approved = any(d.status == "approved" for d in mine)
        gaps = [] if r.status == "retired" else processing_gaps(ProcessingRecord(
            r.lawful_basis, r.special_category, r.special_condition, r.transfers, r.transfer_safeguard, r.retention,
            tuple(r.data_subjects or []), tuple(r.data_categories or []), r.dpia_required, approved))
        out.append({
            "id": r.id, "ref": r.ref, "name": r.name, "purpose": r.purpose, "role": r.role,
            "lawfulBasis": r.lawful_basis, "specialCategory": r.special_category,
            "specialCondition": r.special_condition, "criminalData": r.criminal_data,
            "dataSubjects": list(r.data_subjects or []), "dataCategories": list(r.data_categories or []),
            "recipients": r.recipients, "transfers": r.transfers, "transferCountries": r.transfer_countries,
            "transferSafeguard": r.transfer_safeguard, "retention": r.retention, "systems": r.systems,
            "suppliers": [{"id": v, "name": vendors[v]} for v in (r.vendor_ids or []) if v in vendors],
            "supplierIds": [v for v in (r.vendor_ids or []) if v in vendors],
            "ownerId": r.owner_user_id, "ownerName": names.get(r.owner_user_id), "status": r.status,
            "screening": dict(r.dpia_screening or {}), "dpiaRequired": r.dpia_required,
            "nextReviewOn": r.next_review_on.isoformat() if r.next_review_on else None,
            "reviewOverdue": bool(r.status == "active" and r.next_review_on and r.next_review_on < today),
            "dpias": [{"id": d.id, "ref": d.ref, "status": d.status, "outcome": d.outcome} for d in mine],
            "gaps": gaps})
    return out


def save_processing(db: Session, tenant_id: str, actor: str, data: dict, members: set[str],
                    row: IsmsProcessingActivity | None = None) -> IsmsProcessingActivity:
    name = js_trim(str(data.get("name") or ""))
    if len(name) < 3:
        raise _error("Name the processing activity.")
    role = data.get("role") or "controller"
    if role not in ROLES:
        raise _error("Choose the organization's role.")
    basis = data.get("lawfulBasis") or None
    if basis and basis not in LAWFUL_BASES:
        raise _error("Choose a lawful basis from the list.")
    transfers = bool(data.get("transfers"))
    safeguard = (data.get("transferSafeguard") or None) if transfers else None
    if safeguard and safeguard not in TRANSFER_SAFEGUARDS:
        raise _error("Choose a transfer safeguard from the list.")
    owner = data.get("ownerId") or None
    if owner and owner not in members:
        raise _error("The owner must have an ISMS role in this customer.")
    vendors = list(dict.fromkeys(str(v) for v in (data.get("supplierIds") or [])))
    known = set(db.execute(select(Vendor.id).where(Vendor.tenant_id == tenant_id, Vendor.id.in_(vendors))).scalars()) \
        if vendors else set()
    if set(vendors) - known:
        raise _error("Supplier not found.")
    screening = {k: True for k, _, _ in DPIA_SCREENING if (data.get("screening") or {}).get(k)}
    special = bool(data.get("specialCategory"))
    values = {
        "name": name[:200], "purpose": js_trim(str(data.get("purpose") or ""))[:4000], "role": role,
        "lawful_basis": basis, "special_category": special,
        "special_condition": js_trim(str(data.get("specialCondition") or ""))[:2000] if special else "",
        "criminal_data": bool(data.get("criminalData")), "data_subjects": _list(data.get("dataSubjects")),
        "data_categories": _list(data.get("dataCategories")),
        "recipients": js_trim(str(data.get("recipients") or ""))[:4000], "transfers": transfers,
        "transfer_countries": js_trim(str(data.get("transferCountries") or ""))[:1000] if transfers else "",
        "transfer_safeguard": safeguard, "retention": js_trim(str(data.get("retention") or ""))[:2000],
        "systems": js_trim(str(data.get("systems") or ""))[:2000], "vendor_ids": vendors, "owner_user_id": owner,
        "dpia_screening": screening, "dpia_required": dpia_required(screening).required,
    }
    if row is None:
        row = IsmsProcessingActivity(tenant_id=tenant_id, ref=_next_ref(db, IsmsProcessingActivity, tenant_id, "ROPA"),
                                     next_review_on=date.fromisoformat(add_calendar_months(_today().isoformat(), 12)),
                                     updated_by=actor, **values)
        db.add(row)
        db.flush()
        action = "isms.processing_added"
    else:
        for k, v in values.items():
            setattr(row, k, v)
        row.updated_at, row.updated_by = utcnow(), actor
        action = "isms.processing_updated"
    audit.record(db, actor, action, row.ref, tenant_id, id=row.id, dpia_required=row.dpia_required)
    return row


def review_processing(db: Session, row: IsmsProcessingActivity, actor: str) -> None:
    row.next_review_on = date.fromisoformat(add_calendar_months(_today().isoformat(), 12))
    row.updated_by = actor
    audit.record(db, actor, "isms.processing_reviewed", row.ref, row.tenant_id, id=row.id)


def set_processing_status(db: Session, row: IsmsProcessingActivity, actor: str, status: str) -> None:
    if status not in ("active", "retired"):
        raise _error("Choose active or retired.")
    row.status, row.updated_by = status, actor
    audit.record(db, actor, f"isms.processing_{status}", row.ref, row.tenant_id, id=row.id)


# DPIAs --------------------------------------------------------------------------------------------------------

def dpia_view(db: Session, d: IsmsDpia) -> dict:
    p = db.get(IsmsProcessingActivity, d.processing_id)
    names = _names(db, [d.approved_by_user_id])
    risks = [{**k, "level": dpia_risk_level(k["likelihood"], k["severity"])} for k in (d.risks or [])]
    view = {"id": d.id, "ref": d.ref, "processingId": d.processing_id, "processingRef": p.ref, "processingName": p.name,
            "title": d.title, "description": d.description, "necessity": d.necessity,
            "consultation": d.consultation, "risks": risks, "dpoAdvice": d.dpo_advice, "outcome": d.outcome,
            "priorConsultation": d.prior_consultation, "status": d.status,
            "approvedByName": names.get(d.approved_by_user_id),
            "approvedAt": iso_instant(d.approved_at) if d.approved_at else None,
            "reviewOn": d.review_on.isoformat() if d.review_on else None, "createdAt": iso_instant(d.created_at)}
    view["blockers"] = [] if d.status == "approved" else approval_blockers(view)
    return view


def dpia_rows(db: Session, tenant_id: str) -> list[dict]:
    rows = db.execute(select(IsmsDpia).where(IsmsDpia.tenant_id == tenant_id)).scalars().all()
    return [dpia_view(db, d) for d in sorted(rows, key=lambda d: d.ref, reverse=True)]


def create_dpia(db: Session, p: IsmsProcessingActivity, actor: str) -> IsmsDpia:
    if p.status != "active":
        raise _error("This processing activity is retired.")
    if db.execute(select(IsmsDpia.id).where(IsmsDpia.processing_id == p.id, IsmsDpia.status == "draft")).first():
        raise _error("A draft DPIA already exists for this activity.")
    d = IsmsDpia(tenant_id=p.tenant_id, ref=_next_ref(db, IsmsDpia, p.tenant_id, "DPIA"), processing_id=p.id,
                 title=f"DPIA: {p.name}"[:200], updated_by=actor)
    db.add(d)
    db.flush()
    audit.record(db, actor, "isms.dpia_started", d.ref, p.tenant_id, id=d.id, processing=p.ref)
    return d


def save_dpia(db: Session, d: IsmsDpia, actor: str, data: dict) -> None:
    if d.status == "approved":
        raise _error("An approved DPIA cannot change. Start a new one to review it.")
    risks = []
    for k in data.get("risks") or []:
        desc = js_trim(str(k.get("description") or ""))
        if not desc:
            continue
        if not all(k.get(f) in LEVELS for f in ("likelihood", "severity", "residual")):
            raise _error("Choose low, medium or high for every risk.")
        risks.append({"description": desc[:2000], "likelihood": k["likelihood"], "severity": k["severity"],
                      "measures": js_trim(str(k.get("measures") or ""))[:4000], "residual": k["residual"]})
    title = js_trim(str(data.get("title") or ""))
    if len(title) < 3:
        raise _error("Give the DPIA a title.")
    outcome = data.get("outcome") or None
    if outcome and outcome not in OUTCOMES:
        raise _error("Choose an outcome from the list.")
    d.title, d.risks, d.outcome = title[:200], risks, outcome
    for field, key in (("description", "description"), ("necessity", "necessity"), ("consultation", "consultation"),
                       ("dpo_advice", "dpoAdvice")):
        setattr(d, field, js_trim(str(data.get(key) or ""))[:8000])
    d.prior_consultation = prior_consultation_needed([k["residual"] for k in risks])
    d.updated_at, d.updated_by = utcnow(), actor
    audit.record(db, actor, "isms.dpia_saved", d.ref, d.tenant_id, id=d.id, prior_consultation=d.prior_consultation)


def approval_blockers(d: dict) -> list[str]:
    out = []
    if not js_trim(d["description"]):
        out.append("Describe the processing.")
    if not js_trim(d["necessity"]):
        out.append("Explain why the processing is necessary and proportionate.")
    if not d["risks"]:
        out.append("Assess at least one risk to people.")
    if any(not js_trim(r["measures"]) for r in d["risks"]):
        out.append("Record measures for every risk.")
    if not js_trim(d["dpoAdvice"]):
        out.append("Record the data protection officer's or privacy lead's advice.")
    if not d["outcome"]:
        out.append("Choose the outcome.")
    return out


def approve_dpia(db: Session, d: IsmsDpia, actor: str, user_id: str) -> None:
    if d.status == "approved":
        raise _error("This DPIA is already approved.")
    blockers = approval_blockers(dpia_view(db, d))
    if blockers:
        raise _error(" ".join(blockers))
    d.status, d.approved_by_user_id, d.approved_at = "approved", user_id, utcnow()
    d.review_on, d.updated_by = date.fromisoformat(add_calendar_months(_today().isoformat(), 12)), actor
    audit.record(db, actor, "isms.dpia_approved", d.ref, d.tenant_id, id=d.id, outcome=d.outcome,
                 prior_consultation=d.prior_consultation)


# Data subject requests ----------------------------------------------------------------------------------------

def dsr_rows(db: Session, tenant_id: str, status: str = "open", dsr_id: str | None = None) -> list[dict]:
    q = select(IsmsDataSubjectRequest).where(IsmsDataSubjectRequest.tenant_id == tenant_id)
    if dsr_id:
        q = q.where(IsmsDataSubjectRequest.id == dsr_id)
    elif status != "all":
        q = q.where(IsmsDataSubjectRequest.status == "open")
    rows = db.execute(q).scalars().all()
    rows.sort(key=lambda r: (r.status != "open", r.due_on, r.ref))
    names = _names(db, [r.owner_user_id for r in rows])
    today = _today()
    return [{"id": r.id, "ref": r.ref, "type": r.type, "typeLabel": DSR_TYPE_LABEL.get(r.type, r.type),
             "requester": r.requester, "details": r.details, "receivedOn": r.received_on.isoformat(),
             "identityVerifiedOn": r.identity_verified_on.isoformat() if r.identity_verified_on else None,
             "clockStartsOn": r.clock_starts_on.isoformat(), "extensionMonths": r.extension_months,
             "extensionReason": r.extension_reason, "dueOn": r.due_on.isoformat(), "ownerId": r.owner_user_id,
             "ownerName": names.get(r.owner_user_id), "status": r.status, "response": r.response,
             "closedOn": r.closed_on.isoformat() if r.closed_on else None,
             "overdue": r.status == "open" and r.due_on < today, "daysLeft": (r.due_on - today).days} for r in rows]


def create_dsr(db: Session, tenant_id: str, actor: str, data: dict, members: set[str]) -> IsmsDataSubjectRequest:
    if data.get("type") not in DSR_TYPES:
        raise _error("Choose the type of request.")
    requester = js_trim(str(data.get("requester") or ""))
    if len(requester) < 2:
        raise _error("Record who made the request.")
    received = _day(data.get("receivedOn"), "Enter the date the request was received (not in the future).")
    if received > _today():
        raise _error("Enter the date the request was received (not in the future).")
    verified = None
    if data.get("identityVerifiedOn"):
        verified = _day(data["identityVerifiedOn"], "Identity can only be confirmed on or after the date received.")
        if verified < received:
            raise _error("Identity can only be confirmed on or after the date received.")
    owner = data.get("ownerId") or None
    if owner and owner not in members:
        raise _error("The owner must have an ISMS role in this customer.")
    clock = verified or received
    row = IsmsDataSubjectRequest(tenant_id=tenant_id, ref=_next_ref(db, IsmsDataSubjectRequest, tenant_id, "DSR"),
                                 type=data["type"], requester=requester[:200],
                                 details=js_trim(str(data.get("details") or ""))[:4000], received_on=received,
                                 identity_verified_on=verified, clock_starts_on=clock,
                                 due_on=date.fromisoformat(dsr_deadline(clock.isoformat())), owner_user_id=owner,
                                 updated_by=actor)
    db.add(row)
    db.flush()
    # The requester's name stays out of the audit trail and webhooks; the reference identifies the request.
    audit.record(db, actor, "isms.dsr_received", row.ref, tenant_id, id=row.id, type=row.type,
                 due_on=row.due_on.isoformat())
    return row


def _open(row: IsmsDataSubjectRequest) -> None:
    if row.status != "open":
        raise _error("This request is closed.")


def verify_identity(db: Session, row: IsmsDataSubjectRequest, actor: str, on) -> None:
    """Identity confirmed later: the clock starts from that date (article 12(6))."""
    _open(row)
    day = _day(on, "Enter a date between receipt and today.")
    if day < row.received_on or day > _today():
        raise _error("Enter a date between receipt and today.")
    row.identity_verified_on, row.clock_starts_on = day, day
    row.due_on = date.fromisoformat(dsr_deadline(day.isoformat(), row.extension_months))
    row.updated_by = actor
    audit.record(db, actor, "isms.dsr_identity_verified", row.ref, row.tenant_id, id=row.id,
                 due_on=row.due_on.isoformat())


def extend(db: Session, row: IsmsDataSubjectRequest, actor: str, months, reason: str) -> None:
    _open(row)
    if not isinstance(months, int) or isinstance(months, bool) or not 1 <= months <= 2:
        raise _error("A deadline can be extended by one or two months.")
    reason = js_trim(reason or "")
    if not reason:
        raise _error("Record why the request is complex or numerous.")
    row.extension_months, row.extension_reason = months, reason[:2000]
    row.due_on = date.fromisoformat(dsr_deadline(row.clock_starts_on.isoformat(), months))
    row.updated_by = actor
    audit.record(db, actor, "isms.dsr_extended", row.ref, row.tenant_id, id=row.id, months=months,
                 due_on=row.due_on.isoformat())


def close(db: Session, row: IsmsDataSubjectRequest, actor: str, status: str, response: str) -> None:
    _open(row)
    if status not in ("completed", "refused", "withdrawn"):
        raise _error("Choose how the request ended.")
    response = js_trim(response or "")
    if not response:
        raise _error("Record the reason for refusing and that the person was told of their right to complain."
                     if status == "refused" else "Record what was done.")
    row.status, row.response, row.closed_on, row.updated_by = status, response[:8000], _today(), actor
    audit.record(db, actor, f"isms.dsr_{status}", row.ref, row.tenant_id, id=row.id)


def summary(db: Session, tenant_id: str) -> dict:
    acts = [a for a in processing_rows(db, tenant_id) if a["status"] == "active"]
    reqs = dsr_rows(db, tenant_id)
    return {"activities": len(acts), "withGaps": sum(1 for a in acts if a["gaps"]),
            "dpiasNeeded": sum(1 for a in acts if a["dpiaRequired"] and not any(d["status"] == "approved"
                                                                                for d in a["dpias"])),
            "openRequests": len(reqs), "overdueRequests": sum(1 for r in reqs if r["overdue"]),
            "dueThisWeek": sum(1 for r in reqs if not r["overdue"] and r["daysLeft"] <= 7)}
