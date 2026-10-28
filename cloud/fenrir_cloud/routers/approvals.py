"""Two-person approvals (CORE-15): the queue of held requests, decisions, and each customer's approval policy."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import approvals, audit
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth, scoped_tenant
from ..models import ApprovalRequest, Tenant, utcnow

router = APIRouter(prefix="/api/console", tags=["Approvals"])


@router.get("/approvals")
def list_approvals(tenant_id: str | None = None, status: str | None = None, principal: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)):
    principal.require("read")
    query = select(ApprovalRequest).where(ApprovalRequest.tenant_id.in_(scoped_tenant(principal, tenant_id)))
    if status:
        query = query.where(ApprovalRequest.status == status)
    rows = db.execute(query.order_by(ApprovalRequest.requested_at.desc()).limit(200)).scalars().all()
    now = utcnow()
    for row in rows:
        if row.status in ("pending", "approved") and row.expires_at <= now:
            row.status = "expired"
    db.commit()
    return [{**approvals.view(r), "mine": r.requested_by == principal.actor} for r in rows]


def _owned(db: Session, principal: Principal, approval_id: str) -> ApprovalRequest:
    row = db.get(ApprovalRequest, approval_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    return row


@router.post("/approvals/{approval_id}/approve")
def approve(approval_id: str, request: Request, body: dict = Body(default={}), principal: Principal = Depends(current_principal),
            db: Session = Depends(get_db)):
    principal.require("approve")
    row = _owned(db, principal, approval_id)
    require_reauth(request, principal)
    approvals.decide(db, principal, row, True, str(body.get("reason") or ""))
    db.commit()
    return approvals.view(row)


@router.post("/approvals/{approval_id}/reject")
def reject(approval_id: str, body: dict = Body(default={}), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("approve")
    row = _owned(db, principal, approval_id)
    approvals.decide(db, principal, row, False, str(body.get("reason") or ""))
    db.commit()
    return approvals.view(row)


@router.get("/tenants/{tenant_id}/approval-policy")
def get_policy(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    own = (tenant.settings or {}).get("approvals") or {}
    return {"twoPerson": bool(own.get("twoPerson")), "bulkThreshold": int(own.get("bulkThreshold") or approvals.DEFAULT_THRESHOLD),
            "effective": approvals.policy_for(db, tenant_id)}


@router.put("/tenants/{tenant_id}/approval-policy")
def set_policy(tenant_id: str, request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal),
               db: Session = Depends(get_db)):
    """Turning approvals off is itself sensitive, so changes need configure + approve and a fresh password check."""
    principal.require("configure")
    principal.require("approve")
    principal.check_tenant(tenant_id)
    require_reauth(request, principal)
    threshold = body.get("bulkThreshold", approvals.DEFAULT_THRESHOLD)
    if not isinstance(threshold, int) or not 1 <= threshold <= 100000:
        raise HTTPException(400, "bulkThreshold must be a whole number of devices from 1")
    tenant = db.get(Tenant, tenant_id)
    policy = {"twoPerson": bool(body.get("twoPerson")), "bulkThreshold": threshold}
    tenant.settings = {**(tenant.settings or {}), "approvals": policy}
    audit.record(db, principal.actor, "approval.policy_changed", tenant.name, tenant_id, **policy)
    db.commit()
    return get_policy(tenant_id, principal, db)
