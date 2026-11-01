"""Strict EDR exclusions: process-chain and hash rules for RMM agents and trusted tooling."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import audit, edr_exclusions
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import EdrExclusion, utcnow

router = APIRouter(prefix="/api/console/edr/exclusions", tags=["EDR exclusions"])

_COLUMNS = ("kind", "name", "parent_image", "parent_sha256", "child_image", "child_sha256", "command_line_contains", "scopes",
            "reason", "enabled", "expires_at")


def _check_scope(principal: Principal, tenant_id: str | None) -> None:
    principal.require("configure")
    if tenant_id is None:
        principal.require("platform")  # a platform-wide exclusion affects every customer
    else:
        principal.check_tenant(tenant_id)


def _owned(db: Session, principal: Principal, exclusion_id: str) -> EdrExclusion:
    row = db.get(EdrExclusion, exclusion_id)
    if row is None or (row.tenant_id is not None and row.tenant_id not in principal.tenant_ids):
        raise HTTPException(404, "Not found")
    return row


@router.get("")
def list_exclusions(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    visible = or_(EdrExclusion.tenant_id.is_(None), EdrExclusion.tenant_id.in_(principal.tenant_ids))
    query = select(EdrExclusion).where(visible)
    if tenant_id:
        principal.check_tenant(tenant_id)
        query = query.where(or_(EdrExclusion.tenant_id.is_(None),
                                EdrExclusion.tenant_id.in_(edr_exclusions.ancestors(db, tenant_id))))
    rows = db.execute(query.order_by(EdrExclusion.created_at.desc())).scalars().all()
    return [edr_exclusions.view(r) for r in rows]


def _create(db: Session, principal: Principal, body: dict, tenant_id: str | None, profile: str = "") -> EdrExclusion:
    try:
        values = edr_exclusions.validate(body)
    except edr_exclusions.ExclusionError as exc:
        raise HTTPException(422, str(exc)) from exc
    row = EdrExclusion(tenant_id=tenant_id, created_by=principal.actor, profile=profile, **values)
    db.add(row)
    db.flush()
    audit.record(db, principal.actor, "edr.exclusion.created", row.id, tenant_id, name=row.name, kind=row.kind,
                 parentImage=row.parent_image, scopes=row.scopes, reason=row.reason)
    return row


@router.post("")
def create_exclusion(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    tenant_id = body.get("tenantId") or None
    _check_scope(principal, tenant_id)
    row = _create(db, principal, body, tenant_id)
    db.commit()
    return edr_exclusions.view(row)


@router.post("/rmm-profile")
def create_rmm_profile(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """One process-chain rule per script interpreter the RMM agent launches, all pinned to the agent's hash."""
    tenant_id = body.get("tenantId") or None
    _check_scope(principal, tenant_id)
    try:
        specs = edr_exclusions.rmm_profile(body)
    except edr_exclusions.ExclusionError as exc:
        raise HTTPException(422, str(exc)) from exc
    profile = str(body.get("name") or "RMM agent")[:80]
    rows = [_create(db, principal, spec, tenant_id, profile) for spec in specs]
    db.commit()
    return [edr_exclusions.view(r) for r in rows]


@router.patch("/{exclusion_id}")
def update_exclusion(exclusion_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                     db: Session = Depends(get_db)):
    row = _owned(db, principal, exclusion_id)
    _check_scope(principal, row.tenant_id)
    try:
        values = edr_exclusions.validate(body, existing=row)
    except edr_exclusions.ExclusionError as exc:
        raise HTTPException(422, str(exc)) from exc
    changed = {column: value for column, value in values.items() if getattr(row, column) != value}
    for column, value in changed.items():
        setattr(row, column, value)
    row.updated_at = utcnow()
    audit.record(db, principal.actor, "edr.exclusion.updated", row.id, row.tenant_id,
                 changed={k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in changed.items()})
    db.commit()
    return edr_exclusions.view(row)


@router.delete("/{exclusion_id}")
def delete_exclusion(exclusion_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = _owned(db, principal, exclusion_id)
    _check_scope(principal, row.tenant_id)
    audit.record(db, principal.actor, "edr.exclusion.deleted", row.id, row.tenant_id, name=row.name)
    db.delete(row)
    db.commit()
    return {"deleted": exclusion_id}


@router.post("/test")
def test_exclusion(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Which rule (if any) would cover a process, for a customer: answers "why was this not blocked?"."""
    principal.require("read")
    tenant_id = body.get("tenantId") or None
    if tenant_id:
        principal.check_tenant(tenant_id)
    rules = edr_exclusions.agent_rules(edr_exclusions.active_for(db, tenant_id))
    hit = next((r for r in rules if edr_exclusions.matches(
        r, image=str(body.get("image") or ""), sha256=str(body.get("sha256") or ""), parent_image=str(body.get("parentImage") or ""),
        parent_sha256=str(body.get("parentSha256") or ""), command_line=str(body.get("commandLine") or ""))), None)
    return {"excluded": hit is not None, "rule": hit}
