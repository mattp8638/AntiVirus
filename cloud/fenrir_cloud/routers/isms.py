"""ISMS API: roles per person per customer, and what the signed-in person may do (docs/ISMS_REWRITE_PLAN.md)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, current_principal
from ..isms import memberships, rls
from ..isms.access import ROLE_PERMISSIONS, TENANT_ROLES
from ..isms.models import IsmsMembership
from ..isms.scope import get_scoped, scoped
from ..models import User

router = APIRouter(prefix="/api/console/isms", tags=["ISMS"])


def isms_db(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> Session:
    """The request's session, with PostgreSQL row-level security bound to the principal's tenants."""
    rls.bind_tenants(db, principal.tenant_ids)
    return db


def _naive_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def _membership(row: IsmsMembership, user: User | None) -> dict:
    return {"id": row.id, "tenantId": row.tenant_id, "userId": row.user_id, "role": row.role,
            "email": user.email if user else "", "name": user.name if user else "",
            "portal": bool(user and user.role == "client"), "expiresAt": _iso(row.expires_at),
            "grantedBy": row.granted_by, "updatedAt": _iso(row.updated_at)}


@router.get("/roles")
def roles(principal: Principal = Depends(current_principal)):
    """The ISMS roles and what each may do."""
    principal.require("read")
    return {"roles": [{"role": r, "permissions": sorted(ROLE_PERMISSIONS[r])} for r in TENANT_ROLES]}


@router.get("/me")
def me(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    """The signed-in person's ISMS role in one customer, and whether they can manage ISMS roles there."""
    principal.check_tenant(tenant_id)
    role = memberships.active_role(db, principal.user, tenant_id)
    return {"tenantId": tenant_id, "role": role, "permissions": sorted(ROLE_PERMISSIONS.get(role or "", ())),
            "canManageRoles": memberships.can_manage(db, principal, tenant_id)}


@router.get("/memberships")
def list_memberships(tenant_id: str, principal: Principal = Depends(current_principal),
                     db: Session = Depends(isms_db)):
    memberships.require_manage(db, principal, tenant_id)
    rows = db.execute(scoped(IsmsMembership, principal, tenant_id)).scalars().all()
    users = {u.id: u for u in db.execute(select(User).where(User.id.in_([r.user_id for r in rows]))).scalars()}
    out = [_membership(r, users.get(r.user_id)) for r in rows]
    return {"memberships": sorted(out, key=lambda m: (m["email"], m["id"]))}


@router.get("/candidates")
def list_candidates(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    """People who can be given an ISMS role in this customer (they can already see it in Fenrir)."""
    return {"people": [{"id": u.id, "email": u.email, "name": u.name, "portal": u.role == "client"}
                       for u in memberships.candidates(db, principal, tenant_id)]}


class Grant(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    tenant_id: str = Field(alias="tenantId", min_length=1, max_length=32)
    user_id: str = Field(alias="userId", min_length=1, max_length=32)
    role: str = Field(min_length=1, max_length=40)
    expires_at: datetime | None = Field(default=None, alias="expiresAt")


@router.put("/memberships")
def put_membership(body: Grant, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    """Gives a person an ISMS role in a customer, or changes it."""
    row = memberships.grant(db, principal, body.tenant_id, body.user_id, body.role, _naive_utc(body.expires_at))
    db.commit()
    return _membership(row, db.get(User, row.user_id))


@router.delete("/memberships/{membership_id}")
def delete_membership(membership_id: str, principal: Principal = Depends(current_principal),
                      db: Session = Depends(isms_db)):
    row = get_scoped(db, IsmsMembership, membership_id, principal)
    memberships.revoke(db, principal, row)
    db.commit()
    return {"ok": True}
