"""Customer onboarding checklists (onboarding.py)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import onboarding, workspace
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import Tenant

router = APIRouter(prefix="/api/console/onboarding", tags=["Customer onboarding"])


@router.get("")
def all_customers(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Every customer in scope with how far its onboarding has got, unfinished first."""
    principal.require("read")
    rows = db.execute(select(Tenant).where(Tenant.id.in_(principal.tenant_ids), Tenant.kind == "customer")).scalars().all()
    out = []
    for tenant in rows:
        if (tenant.settings or {}).get("archived"):
            continue
        result = onboarding.checklist(db, tenant)
        out.append({k: result[k] for k in ("tenantId", "name", "done", "total", "failed", "ready")}
                   | {"next": next((s["title"] for s in result["steps"] if s["required"] and s["status"] != "done"), None)})
    return sorted(out, key=lambda r: (r["ready"], -r["failed"], r["done"] / max(1, r["total"]), r["name"].lower()))


@router.get("/{tenant_id}")
def one_customer(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "Not found")
    return onboarding.checklist(db, tenant)


workspace_router = APIRouter(prefix="/api/console/workspace", tags=["Customer workspace"])


@workspace_router.get("/{tenant_id}")
def customer_workspace(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """One customer's open work and state across modules."""
    principal.require("read")
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "Not found")
    return workspace.build(db, tenant)
