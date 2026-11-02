"""Teams, SharePoint and OneDrive for a Microsoft 365 connection (m365_collaboration.py)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import crypto, m365_collaboration as collab
from ..m365_admin import unexpected
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import M365Connection
from .documentation import owned

router = APIRouter(prefix="/api/console/m365/connections/{connection_id}/collaboration", tags=["Microsoft 365 collaboration"])


def _connection(db: Session, ident: str, principal: Principal) -> M365Connection:
    principal.require("m365_admin")
    return owned(db, M365Connection, ident, principal)


def _call(fn, row):
    try:
        return fn(row)
    except collab.CollaborationError as exc:
        raise HTTPException(400, str(exc)) from None
    except (ValueError, crypto.VaultError) as exc:
        raise HTTPException(400, f"The connection cannot sign in: {exc}") from None
    except Exception as exc:
        raise unexpected(exc, "SharePoint and Teams") from None


@router.get("/teams")
def teams(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return _call(collab.teams, _connection(db, connection_id, principal))


@router.get("/sites")
def sites(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return _call(collab.sites, _connection(db, connection_id, principal))


@router.get("/sharing")
def sharing(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return _call(collab.sharing_settings, _connection(db, connection_id, principal))
