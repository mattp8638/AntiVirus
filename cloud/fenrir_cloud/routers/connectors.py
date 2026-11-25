"""Console API: continuous evidence connectors (GRC-11), fenrir_cloud/evidence_connectors.py."""
from __future__ import annotations

import re

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from .. import evidence_connectors as ec
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import GrcConnector, utcnow

router = APIRouter(prefix="/api/console/grc/connectors", tags=["GRC connectors"])


def _view(c: GrcConnector) -> dict:
    return {"id": c.id, "tenantId": c.tenant_id, "kind": c.kind, "name": c.name,
            "config": {k: v for k, v in (c.config or {}).items() if k != "roster"}, "hasSecret": bool(c.secret),
            "maxAgeHours": c.max_age_hours, "lastAttemptAt": c.last_attempt_at.isoformat() if c.last_attempt_at else None,
            "lastSuccessAt": c.last_success_at.isoformat() if c.last_success_at else None, "lastError": c.last_error,
            "problem": ec.freshness(c), "result": c.result,
            "rosterSize": len((c.config or {}).get("roster") or [])}


def _owned(db: Session, p: Principal, cid: str) -> GrcConnector:
    c = db.get(GrcConnector, cid)
    if c is None or c.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Not found")
    return c


@router.get("")
def list_connectors(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    rows = db.execute(select(GrcConnector).where(GrcConnector.tenant_id.in_(scoped_tenant(p, tenantId)))).scalars()
    return [_view(c) for c in rows]


@router.post("")
def create_connector(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    tenant = str(body.get("tenantId") or "")
    p.check_tenant(tenant)
    kind = body.get("kind")
    if kind == "github":
        org = str(body.get("org") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", org) or not str(body.get("token") or "").strip():
            raise HTTPException(400, "the GitHub organisation and a read-only token")
        config = {"org": org}
    elif kind == "hr_roster":
        config = {"roster": [], "uploadedAt": None}
    else:
        raise HTTPException(400, "kind is github or hr_roster")
    c = GrcConnector(tenant_id=tenant, kind=kind, name=str(body.get("name") or ("GitHub " + config.get("org", "") if kind == "github" else "HR roster"))[:200],
                     config=config, created_by=p.actor, max_age_hours=int(body.get("maxAgeHours") or (26 if kind == "github" else 24 * 35)),
                     result={}, last_error="")
    db.add(c)
    db.flush()
    if kind == "github":
        ec.set_secret(c, str(body["token"]).strip())
    audit.record(db, p.actor, "grc.connector.created", c.name, tenant, connector=c.id, kind=kind)
    db.commit()
    return _view(c)


@router.post("/{cid}/roster")
def upload_roster(cid: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The HR roster as CSV: email, status (active / leaver), leave_date."""
    p.require("grc")
    c = _owned(db, p, cid)
    if c.kind != "hr_roster":
        raise HTTPException(400, "not an HR roster connector")
    roster = ec.parse_roster(str(body.get("csv") or ""))
    if not roster:
        raise HTTPException(400, "no rows with an email column")
    c.config = {**c.config, "roster": roster[:50000], "uploadedAt": utcnow().isoformat()}
    ec.run(db, c)
    audit.record(db, p.actor, "grc.connector.roster", c.name, c.tenant_id, connector=c.id, people=len(roster))
    db.commit()
    return _view(c)


@router.post("/{cid}/run")
def run_now(cid: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    c = _owned(db, p, cid)
    ec.run(db, c)
    audit.record(db, p.actor, "grc.connector.run", c.name, c.tenant_id, connector=c.id, ok=not c.last_error)
    db.commit()
    return _view(c)


@router.delete("/{cid}")
def delete_connector(cid: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    c = _owned(db, p, cid)
    db.delete(c)
    audit.record(db, p.actor, "grc.connector.deleted", c.name, c.tenant_id, connector=cid)
    db.commit()
    return {"deleted": True}
