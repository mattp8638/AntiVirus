"""Exchange Online administration for a Microsoft 365 connection (m365_exchange.py)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from .. import audit, crypto, m365_exchange as exo, ratelimit
from ..m365_admin import unexpected
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth
from ..models import M365Connection
from .documentation import owned

router = APIRouter(prefix="/api/console/m365/connections/{connection_id}/exchange", tags=["Microsoft 365 Exchange"])


class ExchangeAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: str = Field(max_length=40)
    parameters: dict = Field(default_factory=dict)
    confirmed: bool = False


def _connection(db: Session, ident: str, principal: Principal) -> M365Connection:
    principal.require("m365_admin")
    return owned(db, M365Connection, ident, principal)


def _read(fn, *args):
    try:
        return fn(*args)
    except exo.ExchangeError as exc:
        raise HTTPException(502 if exc.uncertain else 400, str(exc)) from None
    except (ValueError, crypto.VaultError) as exc:
        raise HTTPException(400, f"The connection cannot sign in to Exchange: {exc}") from None
    except Exception as exc:
        raise unexpected(exc, "Exchange Online") from None


@router.get("/mailboxes")
def mailboxes(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return _read(exo.mailboxes, _connection(db, connection_id, principal))


@router.get("/mailboxes/{mailbox}")
def mailbox(connection_id: str, mailbox: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return _read(exo.mailbox_detail, _connection(db, connection_id, principal), mailbox)


@router.get("/groups")
def groups(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return _read(exo.distribution_groups, _connection(db, connection_id, principal))


@router.get("/groups/{group}/members")
def group_members(connection_id: str, group: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return _read(exo.group_members, _connection(db, connection_id, principal), group)


@router.get("/quarantine")
def quarantine(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return _read(exo.quarantine, _connection(db, connection_id, principal))


@router.get("/trace")
def trace(connection_id: str, sender: str = "", recipient: str = "", days: int = 2, principal: Principal = Depends(current_principal),
          db: Session = Depends(get_db)):
    row = _connection(db, connection_id, principal)
    ratelimit.check(f"exo-trace:{principal.user.id}", 30, 300)
    return _read(exo.message_trace, row, sender, recipient, days)


@router.post("/actions")
def action(connection_id: str, body: ExchangeAction, request: Request, principal: Principal = Depends(current_principal),
           db: Session = Depends(get_db)):
    """Without ``confirmed``: what would happen (nothing changes). With it: re-authentication, then the change, audited."""
    row = _connection(db, connection_id, principal)
    try:
        _, _, description = exo.plan(body.operation, body.parameters)
    except exo.ExchangeError as exc:
        raise HTTPException(422, str(exc)) from None
    if not body.confirmed:
        return {"operation": body.operation, "description": description, "title": exo.OPERATIONS[body.operation]}
    require_reauth(request, principal)
    ratelimit.check(f"exo-action:{principal.user.id}", 60, 300)
    try:
        result = exo.execute(row, body.operation, body.parameters)
    except exo.ExchangeError as exc:
        audit.record(db, principal.actor, "m365.exchange.failed", description, row.tenant_id, connection=row.id,
                     operation=body.operation, uncertain=exc.uncertain, error=str(exc)[:300])
        db.commit()
        raise HTTPException(502 if exc.uncertain else 400, str(exc)) from None
    except Exception as exc:
        audit.record(db, principal.actor, "m365.exchange.failed", description, row.tenant_id, connection=row.id,
                     operation=body.operation, uncertain=True, error=type(exc).__name__)
        db.commit()
        raise unexpected(exc, "Exchange Online") from None
    audit.record(db, principal.actor, "m365.exchange." + body.operation, description, row.tenant_id, connection=row.id)
    db.commit()
    return {"status": "succeeded", "message": result}
