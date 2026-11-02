"""Microsoft 365 workspace: the view across tenants, one tenant's workspace, its permissions and its log store."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .. import audit, crypto, m365, m365_partner, m365_permissions, m365_workspace, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import M365Connection
from .documentation import owned

router = APIRouter(prefix="/api/console/m365", tags=["Microsoft 365 workspace"])


def _connection(db: Session, ident: str, principal: Principal) -> M365Connection:
    principal.require("configure")
    return owned(db, M365Connection, ident, principal)


@router.get("/overview")
def overview(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    return m365_workspace.overview(db, scoped_tenant(principal, tenant_id))


@router.get("/connections/{connection_id}/workspace")
def workspace(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return m365_workspace.workspace(db, _connection(db, connection_id, principal))


@router.post("/connections/{connection_id}/permissions/check")
def check_permissions(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Ask Microsoft for a fresh token and read what it allows. Changes nothing in the tenant."""
    row = _connection(db, connection_id, principal)
    ratelimit.check(f"m365-permissions:{row.id}", 10, 300)
    try:
        with httpx.Client(timeout=20, follow_redirects=False) as client:
            token = m365.access_token(client, row)
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError):
        db.commit()  # a rotated partner refresh token is still worth keeping
        raise HTTPException(502, "Microsoft did not issue a token. Check the connection's credentials and consent.") from None
    check = m365.permission_check(token)
    row.snapshot = {**(row.snapshot or {}), "permissions": check}
    row.granted_permissions = check["granted"]
    db.commit()
    return check


@router.post("/connections/{connection_id}/permissions/update")
def update_permissions(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Bring the connection's Microsoft consent up to what Fenrir now uses.

    GDAP: Fenrir replaces the customer's consent through Partner Center itself. Admin sign-in and platform connections
    need a customer admin to approve, so the answer says which sign-in to start. Manual apps list what to add."""
    principal.require("m365_admin")
    row = owned(db, M365Connection, connection_id, principal)
    mode = row.auth_mode or "app"
    if mode == "gdap":
        partner = m365_partner.partner_for(db, row.tenant_id)
        if partner is None:
            raise HTTPException(409, "No Microsoft partner connection is set up for this customer.")
        ratelimit.check(f"m365-consent:{row.id}", 3, 600)
        try:
            outcome = m365_partner.refresh_consent(partner, row.directory_id)
        except (m365_partner.PartnerError, httpx.HTTPError) as exc:
            db.commit()
            raise HTTPException(502, str(exc)[:300] if isinstance(exc, m365_partner.PartnerError) else "Could not reach Partner Center.") from None
        audit.record(db, principal.actor, "m365.consent_updated", row.id, row.tenant_id, mode=mode)
        db.commit()
        return {"mode": mode, "action": "done", "result": outcome,
                "message": "Consent updated with Fenrir's current permissions. Microsoft can take a few minutes to apply it; "
                           "then press Check permissions."}
    if mode == "provisioned":
        return {"mode": mode, "action": "signin", "permissions": m365_permissions.APP_PERMISSIONS,
                "message": "Sign in again as a Global Administrator of this tenant. Fenrir reuses its existing app, adds the new "
                           "permissions and replaces the app's secret."}
    if mode == "platform":
        return {"mode": mode, "action": "consent", "permissions": m365_permissions.APP_PERMISSIONS,
                "message": "First add these application permissions to your multi-tenant Fenrir app registration, then sign in "
                           "again with Microsoft so the customer's admin approves them."}
    return {"mode": mode, "action": "manual", "permissions": m365_permissions.APP_PERMISSIONS,
            "message": "This connection uses an app registration you made yourself. In the customer's Entra admin centre, add these "
                       "Microsoft Graph application permissions to it and grant admin consent."}


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(422, "Dates must be ISO 8601") from None
    return parsed.replace(tzinfo=None) - parsed.utcoffset() if parsed.tzinfo else parsed


@router.get("/connections/{connection_id}/logs")
def logs(connection_id: str, kind: Literal["signin", "audit"] = "signin", q: str = Query("", max_length=100),
         result: str = Query("", max_length=20), since: str | None = None, until: str | None = None,
         limit: int = Query(200, ge=1, le=5000), offset: int = Query(0, ge=0),
         principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = _connection(db, connection_id, principal)
    return m365_workspace.query_logs(db, row, kind, q, result, _date(since), _date(until), limit, offset)


@router.post("/connections/{connection_id}/logs/collect")
def collect(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = _connection(db, connection_id, principal)
    ratelimit.check(f"m365-logs:{row.id}", 3, 300)
    outcome = m365_workspace.collect_logs(db, row, force=True)
    audit.record(db, principal.actor, "m365.logs_collected", row.id, row.tenant_id,
                 added={k: v.get("added", 0) for k, v in outcome.items()})
    db.commit()
    return {"outcome": outcome, "logState": row.log_state or {}}
