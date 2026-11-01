"""Risk register, policy/evidence tracking and review workflow."""
from datetime import datetime, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session
from .. import audit
from ..grccatalogue import CATALOGUE, framework_labels, retired_framework
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth, scoped_tenant
from ..models import GovernanceRecord, KbArticle, Tenant, utcnow
from ..serialize import to_dict
from .documentation import owned

router = APIRouter(prefix="/api/console/grc", tags=["GRC and ISMS"])
FRAMEWORKS = [f["name"] for f in CATALOGUE.values()]

class RecordInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    kind: Literal["risk", "policy", "evidence", "audit", "exception"]
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(default="", max_length=20000)
    framework: str = Field(default="", max_length=100)
    control: str = Field(default="", max_length=200)
    owner: str = Field(default="", max_length=200)
    likelihood: int = Field(default=1, ge=1, le=5)
    impact: int = Field(default=1, ge=1, le=5)
    reviewDue: datetime | None = None
    documentId: str | None = None
    evidenceUrl: str = Field(default="", max_length=2000)

class ReviewInput(BaseModel):
    status: Literal["draft", "in_review", "approved", "accepted", "closed"]
    reviewDue: datetime | None = None

def serialize(row):
    return {**to_dict(row), "riskScore": row.likelihood * row.impact,
            "reviewOverdue": bool(row.review_due and row.review_due < utcnow() and row.status != "closed")}

@router.get("/frameworks")
def frameworks(principal: Principal = Depends(current_principal)):
    principal.require("read")
    return {"frameworks": FRAMEWORKS, "note": "Mappings are organisation-authored evidence references, not certification or a complete control library."}

@router.get("/records")
def records(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    return [serialize(row) for row in db.scalars(select(GovernanceRecord).where(GovernanceRecord.tenant_id.in_(scoped_tenant(principal, tenant_id))).order_by(GovernanceRecord.created_at.desc()).limit(2000))]

@router.post("/records")
def create(body: RecordInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("grc")
    principal.check_tenant(body.tenantId)
    if retired_framework("", body.framework):
        raise HTTPException(422, "This framework is retired from the UK governance catalogue")
    if body.documentId:
        doc = owned(db, KbArticle, body.documentId, principal)
        if doc.tenant_id != body.tenantId:
            raise HTTPException(400, "Document must belong to the same customer")
    if body.evidenceUrl and not body.evidenceUrl.startswith("https://"):
        raise HTTPException(400, "Evidence links must use HTTPS")
    row = GovernanceRecord(tenant_id=body.tenantId, kind=body.kind, title=body.title, description=body.description,
        framework=body.framework, control=body.control, owner=body.owner, likelihood=body.likelihood, impact=body.impact,
        review_due=body.reviewDue.astimezone(timezone.utc).replace(tzinfo=None) if body.reviewDue and body.reviewDue.tzinfo else body.reviewDue,
        document_id=body.documentId, evidence_url=body.evidenceUrl)
    db.add(row)
    db.flush()
    audit.record(db, principal.actor, "grc.created", row.id, row.tenant_id, kind=row.kind)
    db.commit()
    return serialize(row)

@router.patch("/records/{record_id}/review")
def review(record_id: str, body: ReviewInput, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("grc")
    row = owned(db, GovernanceRecord, record_id, principal)
    if body.status in {"accepted", "approved"}:
        require_reauth(request, principal)
        if body.status == "accepted" and row.kind not in {"risk", "exception"}:
            raise HTTPException(400, "Only risks and exceptions can be accepted")
        due = body.reviewDue or row.review_due
        if due and due.tzinfo:
            due = due.astimezone(timezone.utc).replace(tzinfo=None)
        if not due or due <= utcnow():
            raise HTTPException(400, "Approval requires a future review date")
        row.review_due, row.approved_by = due, principal.actor
    else:
        row.approved_by = ""
        if body.reviewDue:
            row.review_due = body.reviewDue.astimezone(timezone.utc).replace(tzinfo=None) if body.reviewDue.tzinfo else body.reviewDue
    row.status, row.updated_at = body.status, utcnow()
    audit.record(db, principal.actor, "grc.reviewed", row.id, row.tenant_id, status=row.status)
    db.commit()
    return serialize(row)


def _control_matches(record_control: str, control_id: str) -> bool:
    text = (record_control or "").strip()
    return text == control_id or text.startswith(control_id + " ") or text.startswith(control_id + ":")


@router.get("/controls")
def controls(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Statement of applicability: each library control with its automatic check and the register records linked to it."""
    from .. import compliance

    principal.require("read")
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "Not found")
    records = list(db.scalars(select(GovernanceRecord).where(GovernanceRecord.tenant_id == tenant_id)))
    out = []
    for framework in compliance.evaluate(db, tenant):
        label = CATALOGUE.get(framework["framework"], {}).get("name", framework["name"])
        labels = framework_labels(framework["framework"])
        rows, counts = [], {"met": 0, "evidenced": 0, "exception": 0, "gap": 0}
        for control in framework["controls"]:
            linked = [r for r in records if r.framework in labels and _control_matches(r.control, control["id"])]
            approved = [r for r in linked if r.kind in ("policy", "evidence", "audit") and r.status == "approved"]
            excepted = [r for r in linked if r.kind == "exception" and r.status in ("approved", "accepted")]
            status = "met" if control["passed"] else "evidenced" if approved else "exception" if excepted else "gap"
            counts[status] += 1
            rows.append({**control, "status": status, "records": [serialize(r) for r in linked]})
        out.append({"framework": framework["framework"], "label": label, "name": framework["name"], "counts": counts,
                    "coverage": round(100 * (counts["met"] + counts["evidenced"]) / len(rows)) if rows else 0, "controls": rows})
    return {"tenantId": tenant_id, "frameworks": out}
