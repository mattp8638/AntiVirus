"""Console API: attack-path analysis (VULN-19)."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import attack_paths as ap
from .. import audit
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import AttackPathRun

router = APIRouter(prefix="/api/console/attack-paths", tags=["Attack paths"])


def _view(r: AttackPathRun) -> dict:
    return {"id": r.id, "tenantId": r.tenant_id, "createdAt": r.created_at.isoformat(), "createdBy": r.created_by,
            "paths": r.paths, "new": r.new, "resolved": r.resolved, "inputs": r.inputs}


@router.post("/analyse")
def analyse(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")  # stores a new analysis run: not for read-only roles
    tenant = str(body.get("tenantId") or "")
    p.check_tenant(tenant)
    result = ap.analyse(db, tenant)
    prev = db.execute(select(AttackPathRun).where(AttackPathRun.tenant_id == tenant)
                      .order_by(AttackPathRun.created_at.desc()).limit(1)).scalars().first()
    before = {x["id"]: x for x in (prev.paths if prev else [])}
    now = {x["id"] for x in result["paths"]}
    run = AttackPathRun(tenant_id=tenant, paths=result["paths"], inputs={**result["inputs"], "method": result["method"]},
                        new=sorted(now - set(before)) if prev else [],
                        resolved=[{"id": i, "target": before[i]["target"], "hops": before[i]["hops"]} for i in sorted(set(before) - now)],
                        created_by=p.actor)
    db.add(run)
    db.flush()
    audit.record(db, p.actor, "attack_paths.analysed", tenant, tenant, paths=len(run.paths), new=len(run.new), resolved=len(run.resolved))
    db.commit()
    return _view(run)


@router.get("/latest")
def latest(tenantId: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    p.check_tenant(tenantId)
    r = db.execute(select(AttackPathRun).where(AttackPathRun.tenant_id == tenantId)
                   .order_by(AttackPathRun.created_at.desc()).limit(1)).scalars().first()
    if r is None:
        raise HTTPException(404, "not analysed yet")
    return _view(r)
