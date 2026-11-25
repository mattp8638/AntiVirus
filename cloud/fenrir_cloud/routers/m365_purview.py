"""Purview retention and sensitivity labels: inventory, templates, drift and reviewed deployment (M365-27)."""
from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crypto, m365_purview as pv, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth
from ..models import M365Connection, PurviewBaseline, PurviewChange, PurviewInventory
from ..serialize import to_dict

router = APIRouter(prefix="/api/console/m365/purview", tags=["Microsoft Purview"])


def _conn(db, ident, p) -> M365Connection:
    c = db.get(M365Connection, ident)
    if c is None or c.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Connection not found")
    return c


def _baseline(db, ident, p) -> PurviewBaseline:
    b = db.get(PurviewBaseline, ident)
    if b is None or b.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Template not found")
    return b


class Baseline(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    name: str = Field(min_length=1, max_length=200)
    retentionLabels: list[dict] = Field(min_length=1, max_length=100)


@router.post("/baselines")
def create_baseline(body: Baseline, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    p.check_tenant(body.tenantId)
    try:
        labels = pv.validate_labels(body.retentionLabels)
    except pv.PurviewError as exc:
        raise HTTPException(400, str(exc)) from None
    b = PurviewBaseline(tenant_id=body.tenantId, name=body.name, retention_labels=labels, created_by=p.actor)
    db.add(b)
    db.flush()
    audit.record(db, p.actor, "m365.purview_baseline_saved", b.id, body.tenantId, labels=[x["displayName"] for x in labels])
    db.commit()
    return to_dict(b)


@router.get("/baselines")
def list_baselines(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    return [to_dict(b) for b in db.scalars(select(PurviewBaseline).where(PurviewBaseline.tenant_id.in_(list(p.tenant_ids))))]


@router.post("/connections/{ident}/inventory")
def refresh(ident: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    c = _conn(db, ident, p)
    ratelimit.check(f"purview:{p.user.id}", 10, 300)
    try:
        row = pv.inventory(db, c, p.actor)
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError):
        db.rollback()
        raise HTTPException(502, "Microsoft request failed. Check the connection's consent and permissions.") from None
    db.commit()
    return to_dict(row)


@router.get("/connections/{ident}")
def state(ident: str, baselineId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    c = _conn(db, ident, p)
    inv = db.scalars(select(PurviewInventory).where(PurviewInventory.connection_id == c.id)).first()
    out = {"inventory": to_dict(inv) if inv else None,
           "changes": [to_dict(x) for x in db.scalars(select(PurviewChange).where(PurviewChange.connection_id == c.id)
                                                       .order_by(PurviewChange.created_at.desc()).limit(50))]}
    if inv and baselineId:
        out["drift"] = pv.drift(_baseline(db, baselineId, p), inv)
    return out


class Propose(BaseModel):
    model_config = ConfigDict(extra="forbid")
    baselineId: str


@router.post("/connections/{ident}/changes")
def propose(ident: str, body: Propose, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("m365_admin")
    c = _conn(db, ident, p)
    inv = db.scalars(select(PurviewInventory).where(PurviewInventory.connection_id == c.id)).first()
    if inv is None:
        raise HTTPException(409, "Read the tenant's labels first")
    try:
        change = pv.propose(db, c, _baseline(db, body.baselineId, p), inv, p.actor)
    except pv.PurviewError as exc:
        raise HTTPException(409, str(exc)) from None
    db.commit()
    return to_dict(change)


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approve: bool
    note: str = Field(default="", max_length=1000)


@router.post("/changes/{change_id}/review")
def review(change_id: str, body: Review, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("m365_admin")
    change = db.get(PurviewChange, change_id)
    if change is None or change.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Change not found")
    if body.approve:
        require_reauth(request, p)
    try:
        pv.review(db, change, _conn(db, change.connection_id, p), body.approve, body.note, p.actor)
    except pv.PurviewError as exc:
        raise HTTPException(409, str(exc)) from None
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError):
        db.rollback()
        raise HTTPException(502, "Microsoft request failed; check Purview before trying again") from None
    db.commit()
    return to_dict(change)
