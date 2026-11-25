"""Microsoft 365 tenant configuration backup, comparison, change history and restore (M365-14)."""
from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import crypto, m365_config as config, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth
from ..models import M365ConfigRestore, M365ConfigSnapshot, M365Connection
from ..serialize import to_dict

router = APIRouter(prefix="/api/console/m365/config", tags=["Microsoft 365 configuration backup"])


def _connection(db: Session, connection_id: str, principal: Principal) -> M365Connection:
    row = db.get(M365Connection, connection_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Connection not found")
    return row


def _snapshot(db: Session, snapshot_id: str, principal: Principal) -> M365ConfigSnapshot:
    row = db.get(M365ConfigSnapshot, snapshot_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Snapshot not found")
    return row


def _summary(s: M365ConfigSnapshot) -> dict:
    return {"id": s.id, "tenantId": s.tenant_id, "connectionId": s.connection_id, "takenAt": s.taken_at, "checkedAt": s.checked_at,
            "takenBy": s.taken_by, "digest": s.digest, "unavailable": s.errors or {}, "changes": s.changes or {},
            "counts": {r: len(v) for r, v in (s.resources or {}).items()}}


def _provider_error(exc: Exception) -> HTTPException:
    if isinstance(exc, config.ConfigError):
        return HTTPException(400, str(exc))
    return HTTPException(502, "Microsoft request failed. Check the connection's consent and permissions.")


@router.get("/resources")
def resources(principal: Principal = Depends(current_principal)):
    principal.require("configure")
    return {"resources": [{"key": k, "title": v["title"], "restorable": k not in config.NOT_RESTORED} for k, v in config.RESOURCES.items()],
            "notRestored": config.NOT_RESTORED}


@router.post("/connections/{connection_id}/snapshots")
def backup_now(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    conn = _connection(db, connection_id, principal)
    ratelimit.check(f"m365-config-backup:{principal.user.id}", 10, 300)
    try:
        snap, created = config.take(db, conn, principal.actor)
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError) as exc:
        db.rollback()
        raise _provider_error(exc) from None
    db.commit()
    return {**_summary(snap), "created": created}


@router.get("/connections/{connection_id}/snapshots")
def history(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Change history: every snapshot that differed from the one before, newest first."""
    principal.require("configure")
    conn = _connection(db, connection_id, principal)
    rows = db.scalars(select(M365ConfigSnapshot).where(M365ConfigSnapshot.connection_id == conn.id)
                      .order_by(M365ConfigSnapshot.taken_at.desc()).limit(200))
    return [_summary(s) for s in rows]


@router.get("/snapshots/{snapshot_id}")
def get_snapshot(snapshot_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    s = _snapshot(db, snapshot_id, principal)
    return {**_summary(s), "resources": s.resources, "references": s.references, "hashes": s.hashes, "verified": config.verify(s)}


@router.get("/compare")
def compare(left: str, right: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Differences from snapshot ``left`` to ``right``; they may be of different tenants (references compared by name)."""
    principal.require("configure")
    a, b = _snapshot(db, left, principal), _snapshot(db, right, principal)
    return {"left": _summary(a), "right": _summary(b), "differences": config.diff(a, b)}


class Selection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    resource: str = Field(max_length=40)
    name: str = Field(max_length=300)


class PlanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    snapshotId: str
    connectionId: str  # the tenant to restore into: the snapshot's own, or another customer's
    items: list[Selection] = Field(min_length=1, max_length=500)
    keepState: bool = False


@router.post("/restores")
def plan_restore(body: PlanInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("m365_admin")
    snap = _snapshot(db, body.snapshotId, principal)
    target = _connection(db, body.connectionId, principal)
    ratelimit.check(f"m365-config-plan:{principal.user.id}", 20, 300)
    try:
        restore = config.plan(db, snap, target, [i.model_dump() for i in body.items], {"keepState": body.keepState}, principal.actor)
    except (config.ConfigError, httpx.HTTPError, ValueError, KeyError, crypto.VaultError) as exc:
        db.rollback()
        raise _provider_error(exc) from None
    db.commit()
    return to_dict(restore)


def _restore(db: Session, restore_id: str, principal: Principal) -> M365ConfigRestore:
    row = db.get(M365ConfigRestore, restore_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Restore not found")
    return row


@router.get("/restores/{restore_id}")
def get_restore(restore_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    return to_dict(_restore(db, restore_id, principal))


class Execute(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmCount: int  # the number of objects the plan creates or updates, typed by the technician


@router.post("/restores/{restore_id}/execute")
def execute_restore(restore_id: str, body: Execute, request: Request, principal: Principal = Depends(current_principal),
                    db: Session = Depends(get_db)):
    principal.require("m365_admin")
    restore = _restore(db, restore_id, principal)
    require_reauth(request, principal)
    writes = sum(1 for s in restore.plan if s["action"] in ("create", "update"))
    if writes == 0:
        raise HTTPException(409, "The plan changes nothing")
    if body.confirmCount != writes:
        raise HTTPException(409, f"Type the number of objects this restore changes ({writes}) to confirm")
    target = _connection(db, restore.connection_id, principal)
    try:
        config.execute(db, restore, target, principal.actor)
    except (config.ConfigError, httpx.HTTPError, ValueError, KeyError, crypto.VaultError) as exc:
        if isinstance(exc, config.ConfigError):
            raise HTTPException(409, str(exc)) from None
        db.rollback()
        raise _provider_error(exc) from None
    return to_dict(restore)


# ---- Conditional Access simulation and gap analysis (M365-15) ------------------------------------------------------

class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str = Field(default="scenario", max_length=60)
    title: str = Field(default="", max_length=200)
    user: dict = Field(default_factory=lambda: {"kind": "member"})
    app: str | None = Field(default="All", max_length=64)
    userAction: str | None = Field(default=None, max_length=100)
    clientApp: str = Field(default="browser", pattern=r"^(browser|mobileAppsAndDesktopClients|exchangeActiveSync|other)$")
    platform: str = Field(default="windows", max_length=20)
    ip: str | None = Field(default=None, max_length=45)
    country: str | None = Field(default=None, max_length=2)
    signInRisk: str = Field(default="none", pattern=r"^(none|low|medium|high)$")
    userRisk: str = Field(default="none", pattern=r"^(none|low|medium|high)$")
    expect: str | None = Field(default=None, pattern=r"^(mfa|block)$")


class Simulate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenarios: list[Scenario] = Field(default_factory=list, max_length=50)  # empty: the standard gap analysis


@router.post("/snapshots/{snapshot_id}/simulate")
def simulate(snapshot_id: str, body: Simulate, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """A modelled evaluation of the backup's Conditional Access policies. Nothing is sent to the tenant."""
    from .. import m365_ca_simulation as sim

    principal.require("configure")
    snap = _snapshot(db, snapshot_id, principal)
    ratelimit.check(f"m365-ca-sim:{principal.user.id}", 30, 300)
    try:
        row = sim.run(db, snap, [s.model_dump() for s in body.scenarios] or None, principal.actor)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    db.commit()
    return to_dict(row)


@router.get("/connections/{connection_id}/simulations")
def simulations(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    from ..models import M365CaSimulation

    principal.require("configure")
    conn = _connection(db, connection_id, principal)
    rows = db.scalars(select(M365CaSimulation).where(M365CaSimulation.connection_id == conn.id)
                      .order_by(M365CaSimulation.created_at.desc()).limit(100))
    return [to_dict(r) for r in rows]
