"""Safe web application assessments of attested external assets (VULN-08)."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crypto, ratelimit, web_assessment as wa
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth
from ..models import WebAssessment
from ..serialize import to_dict

router = APIRouter(prefix="/api/console/web-assessments", tags=["Web application assessment"])


class NewAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    assetId: str
    url: str = Field(max_length=500)
    profile: Literal["passive", "standard"] = "passive"
    maxPages: int = 50
    maxDepth: int = 3
    delay: float = 0.2
    budget: int = 120
    authHeader: Literal["Authorization", "Cookie"] | None = None
    authValue: str | None = Field(default=None, max_length=4000)


def _out(row: WebAssessment) -> dict:
    out = to_dict(row)
    out.pop("authEnvelope", None)
    return out


@router.post("")
def create(body: NewAssessment, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    principal.check_tenant(body.tenantId)
    if body.authValue:
        require_reauth(request, principal)  # a credential for the customer's application
    ratelimit.check(f"web-assessment:{body.tenantId}", 10, 3600)
    try:
        wa.check_target(db, body.tenantId, body.assetId, body.url)
        lim = wa.limits({"max_pages": body.maxPages, "max_depth": body.maxDepth, "delay": body.delay, "budget": body.budget})
    except wa.AssessmentError as exc:
        raise HTTPException(400, str(exc)) from None
    if bool(body.authHeader) != bool(body.authValue):
        raise HTTPException(400, "Give both the header name and its value, or neither")
    row = WebAssessment(tenant_id=body.tenantId, asset_id=body.assetId, url=body.url, profile=body.profile,
                        config={**lim, "authenticated": bool(body.authValue), "authHeader": body.authHeader}, created_by=principal.actor)
    db.add(row)
    db.flush()
    if body.authValue:
        row.auth_envelope = crypto.encrypt(body.authValue, f"web-assessment:{row.id}")
    audit.record(db, principal.actor, "web_assessment.queued", row.id, body.tenantId, url=body.url, profile=body.profile,
                 authenticated=bool(body.authValue), limits=lim)
    db.commit()
    return _out(row)


@router.get("")
def list_(tenantId: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    principal.check_tenant(tenantId)
    rows = db.scalars(select(WebAssessment).where(WebAssessment.tenant_id == tenantId).order_by(WebAssessment.created_at.desc()).limit(100))
    return [_out(r) for r in rows]


@router.get("/{assessment_id}")
def get(assessment_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    row = db.get(WebAssessment, assessment_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Assessment not found")
    return _out(row)
