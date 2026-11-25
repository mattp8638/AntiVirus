"""Console API: AI-governance inventory (GRC-21), fenrir_cloud/ai_governance.py."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import ai_governance as ag
from .. import audit
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import AiSystem, GrcEvidence, Vendor, utcnow

router = APIRouter(prefix="/api/console/grc/ai", tags=["AI governance"])


def bad(msg: str):
    raise HTTPException(400, msg)


def _view(s: AiSystem) -> dict:
    return {"id": s.id, "tenantId": s.tenant_id, "name": s.name, "purpose": s.purpose, "owner": s.owner, "provider": s.provider,
            "vendorId": s.vendor_id, "deployment": s.deployment, "dataCategories": s.data_categories, "answers": s.answers,
            "suggestedTier": s.suggested_tier, "tier": s.tier, "tierRationale": s.tier_rationale, "impacts": s.impacts,
            "oversight": s.oversight, "status": s.status, "approvedBy": s.approved_by,
            "approvedAt": s.approved_at.isoformat() if s.approved_at else None,
            "reviewDue": s.review_due.date().isoformat() if s.review_due else None, "evidenceIds": s.evidence_ids,
            "findings": ag.findings(s), "history": s.history, "updatedAt": s.updated_at.isoformat()}


def _owned(db: Session, p: Principal, sid: str) -> AiSystem:
    s = db.get(AiSystem, sid)
    if s is None or s.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Not found")
    return s


@router.get("/questions")
def questions(p: Principal = Depends(current_principal)):
    p.require("read")
    return {"questions": ag.QUESTIONS, "tiers": list(ag.TIERS)}


@router.get("/systems")
def list_systems(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    rows = db.execute(select(AiSystem).where(AiSystem.tenant_id.in_(scoped_tenant(p, tenantId))).order_by(AiSystem.name)).scalars()
    return [_view(s) for s in rows]


def _apply(db: Session, s: AiSystem, body: dict) -> list[str]:
    changed = []
    for k, attr, n in (("name", "name", 200), ("purpose", "purpose", 10000), ("owner", "owner", 200), ("provider", "provider", 200),
                       ("tierRationale", "tier_rationale", 5000), ("impacts", "impacts", 20000)):
        if k in body:
            setattr(s, attr, str(body[k] or "")[:n])
            changed.append(k)
    if "deployment" in body:
        if body["deployment"] not in ("internal", "customer-facing", "embedded"):
            bad("deployment is internal, customer-facing or embedded")
        s.deployment = body["deployment"]
        changed.append("deployment")
    if "dataCategories" in body:
        s.data_categories = [str(x)[:60] for x in body["dataCategories"] or []][:30]
        changed.append("dataCategories")
    if "vendorId" in body:
        if body["vendorId"]:
            v = db.get(Vendor, str(body["vendorId"]))
            if v is None or v.tenant_id != s.tenant_id:
                bad("the supplier must be in this customer's third-party register")
        s.vendor_id = body["vendorId"] or None
        changed.append("vendorId")
    if "answers" in body:
        ids = {q["id"] for q in ag.QUESTIONS}
        ans = {k: bool(v) for k, v in (body["answers"] or {}).items() if k in ids and isinstance(v, bool)}
        s.answers = {**(s.answers or {}), **ans}
        s.suggested_tier = ag.suggest(s.answers)[0]
        changed.append("answers")
    if "tier" in body:
        if body["tier"] not in ag.TIERS:
            bad("tier is unacceptable, high, limited or minimal")
        s.tier = body["tier"]
        changed.append("tier")
    if "oversight" in body:
        s.oversight = [{"measure": str(o.get("measure") or "")[:500], "owner": str(o.get("owner") or "")[:200],
                        "frequency": str(o.get("frequency") or "")[:60]}
                       for o in body["oversight"] or [] if isinstance(o, dict) and str(o.get("measure") or "").strip()][:30]
        changed.append("oversight")
    if "evidenceIds" in body:
        for e in body["evidenceIds"] or []:
            ev = db.get(GrcEvidence, str(e))
            if ev is None or ev.tenant_id != s.tenant_id:
                bad("evidence must be this customer's")
        s.evidence_ids = [str(e) for e in body["evidenceIds"] or []][:50]
        changed.append("evidenceIds")
    if "reviewDue" in body:
        try:
            s.review_due = datetime.fromisoformat(str(body["reviewDue"])[:10]) if body["reviewDue"] else None
        except ValueError:
            bad("dates are YYYY-MM-DD")
        changed.append("reviewDue")
    return changed


@router.post("/systems")
def create_system(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    tenant = str(body.get("tenantId") or "")
    p.check_tenant(tenant)
    if len(str(body.get("name") or "").strip()) < 2:
        bad("name the AI system or use-case")
    s = AiSystem(tenant_id=tenant, name="", created_by=p.actor, answers={}, oversight=[], data_categories=[], evidence_ids=[],
                 history=[], purpose="", owner="", provider="", deployment="internal", impacts="", tier="", tier_rationale="",
                 suggested_tier="")
    db.add(s)
    _apply(db, s, body)
    db.flush()
    s.history = [{"at": utcnow().isoformat(), "by": p.actor, "text": "added to the inventory"}]
    audit.record(db, p.actor, "grc.ai.created", s.name, tenant, system=s.id)
    db.commit()
    return _view(s)


@router.patch("/systems/{sid}")
def update_system(sid: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    s = _owned(db, p, sid)
    changed = _apply(db, s, body)
    # A change to how it is used or assessed needs a new approval.
    if s.status in ("approved", "in_use") and set(changed) & {"answers", "tier", "purpose", "deployment", "dataCategories", "provider"}:
        s.status = "proposed"
        changed.append("approval withdrawn: re-approve after the change")
    s.updated_at = utcnow()
    s.history = (s.history or []) + [{"at": utcnow().isoformat(), "by": p.actor, "text": "changed " + ", ".join(changed)}]
    audit.record(db, p.actor, "grc.ai.updated", s.name, s.tenant_id, system=s.id, changed=changed)
    db.commit()
    return _view(s)


@router.post("/systems/{sid}/decision")
def decide(sid: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Approve (only with no open findings), reject, mark in use or retire."""
    p.require("grc")
    s = _owned(db, p, sid)
    action = body.get("action")
    if action == "approve":
        f = ag.findings(s)
        if f:
            raise HTTPException(409, "Not ready to approve: " + "; ".join(f))
        s.status, s.approved_by, s.approved_at = "approved", p.actor, utcnow()
    elif action == "in_use":
        if s.status != "approved":
            bad("approve it first")
        s.status = "in_use"
    elif action in ("reject", "retire"):
        s.status = "rejected" if action == "reject" else "retired"
    else:
        bad("action is approve, in_use, reject or retire")
    s.history = (s.history or []) + [{"at": utcnow().isoformat(), "by": p.actor, "text": f"{action}: {str(body.get('note') or '')[:300]}".strip(": ")}]
    audit.record(db, p.actor, f"grc.ai.{action}", s.name, s.tenant_id, system=s.id, tier=s.tier)
    db.commit()
    return _view(s)
