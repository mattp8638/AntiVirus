"""Microsoft 365 diagnostics and the read-only Graph explorer (M365-32)."""
from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from .. import audit, crypto, m365_tools as tools, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import M365Connection

router = APIRouter(prefix="/api/console/m365/tools", tags=["Microsoft 365 diagnostics"])


class DomainInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str = Field(max_length=253)
    tenantId: str | None = None


@router.post("/domain")
def domain(body: DomainInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    if body.tenantId:
        principal.check_tenant(body.tenantId)
    ratelimit.check(f"m365-tools-domain:{principal.user.id}", 30, 300)
    try:
        out = tools.domain_check(body.domain)
    except tools.ToolError as exc:
        raise HTTPException(400, str(exc)) from None
    audit.record(db, principal.actor, "m365.tool_domain_check", out["domain"], body.tenantId,
                 results={c["check"]: c["status"] for c in out["checks"]})
    db.commit()
    return out


class ExploreInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    connectionId: str
    path: str = Field(max_length=1000)


@router.post("/graph")
def graph(body: ExploreInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("m365_admin")
    conn = db.get(M365Connection, body.connectionId)
    if conn is None or conn.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Connection not found")
    ratelimit.check(f"m365-tools-graph:{principal.user.id}", 60, 300)
    try:
        out = tools.explore(conn, body.path)
    except tools.ToolError as exc:
        audit.record(db, principal.actor, "m365.graph_explorer_refused", conn.id, conn.tenant_id, path=body.path[:300], reason=str(exc))
        db.commit()
        raise HTTPException(400, str(exc)) from None
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError):
        raise HTTPException(502, "Microsoft request failed. Check the connection's consent and permissions.") from None
    audit.record(db, principal.actor, "m365.graph_explorer", conn.id, conn.tenant_id, path=out["path"], status=out["status"], bytes=out["bytes"])
    db.commit()
    return out
