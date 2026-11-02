"""Agent health across the fleet (agent_health.py)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import agent_health
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant

router = APIRouter(prefix="/api/console/agent-health", tags=["Agent health"])


@router.get("")
def fleet_agent_health(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    result = agent_health.report(db, scoped_tenant(principal, tenant_id))
    if not principal.can("platform"):
        # The reason names the device that failed, which may belong to another customer.
        result["stalledRollouts"] = [{**r, "reason": "Paused by Fenrir after a failed update; a platform admin can review it."}
                                     for r in result["stalledRollouts"]]
    return result
