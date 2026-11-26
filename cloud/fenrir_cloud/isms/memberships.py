"""ISMS roles per person per customer (plan decision R7).

* Seeing anything in the ISMS for a customer needs an active ISMS role there, whatever the person's Fenrir role.
* Roles are managed by Fenrir users with the ``grc`` permission, or by people whose ISMS role in that customer allows
  ``tenant.users.manage``, for customers they can see. Managing roles does not by itself grant access to ISMS data.
* The person must already be able to see the customer in Fenrir. Client portal accounts can only be staff (they read
  and acknowledge policies in the portal). Auditor roles must expire.
* Every grant, change and removal writes an audit event.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..deps import Principal, user_tenant_scope
from ..models import User, utcnow
from .access import TENANT_ROLES, can
from .models import IsmsMembership

MAX_AUDITOR_DAYS = 366


def active_role(db: Session, user: User, tenant_id: str, now: datetime | None = None) -> str | None:
    """The person's ISMS role in this customer, or None (no role, expired, or the account is disabled)."""
    if not user.active:
        return None
    row = db.execute(select(IsmsMembership).where(IsmsMembership.tenant_id == tenant_id,
                                                  IsmsMembership.user_id == user.id)).scalar_one_or_none()
    if row is None or (row.expires_at is not None and row.expires_at <= (now or utcnow())):
        return None
    return row.role


def can_manage(db: Session, principal: Principal, tenant_id: str) -> bool:
    principal.check_tenant(tenant_id)
    if principal.can("grc"):
        return True
    return can(active_role(db, principal.user, tenant_id), "tenant.users.manage")


def require_manage(db: Session, principal: Principal, tenant_id: str) -> None:
    if not can_manage(db, principal, tenant_id):
        raise HTTPException(403, "You cannot manage ISMS roles for this organization")


def _check_grant(db: Session, user: User, tenant_id: str, role: str, expires_at: datetime | None,
                 now: datetime) -> None:
    if role not in TENANT_ROLES:
        raise HTTPException(400, f"Unknown ISMS role {role!r}")
    if not user.active:
        raise HTTPException(400, "That account is disabled")
    if user.role == "client":
        if role != "staff":
            raise HTTPException(400, "Client portal accounts can only have the staff role")
        visible = user.tenant_id == tenant_id
    else:
        visible = tenant_id in user_tenant_scope(db, user)
    if not visible:
        raise HTTPException(400, "That person cannot see this organization in Fenrir")
    if expires_at is not None and expires_at <= now:
        raise HTTPException(400, "The expiry must be in the future")
    if role == "auditor":
        if expires_at is None:
            raise HTTPException(400, "Auditor access must have an expiry date")
        if expires_at > now + timedelta(days=MAX_AUDITOR_DAYS):
            raise HTTPException(400, f"Auditor access can last at most {MAX_AUDITOR_DAYS} days")


def candidates(db: Session, principal: Principal, tenant_id: str) -> list[User]:
    """People the principal can see who could be given an ISMS role in this customer."""
    require_manage(db, principal, tenant_id)
    users = db.execute(select(User).where(User.tenant_id.in_(principal.tenant_ids), User.active.is_(True),
                                          User.role != "service").order_by(User.email)).scalars().all()
    return [u for u in users
            if (u.tenant_id == tenant_id if u.role == "client" else tenant_id in user_tenant_scope(db, u))]


def grant(db: Session, principal: Principal, tenant_id: str, user_id: str, role: str,
          expires_at: datetime | None = None) -> IsmsMembership:
    """Gives a person an ISMS role in a customer, or changes the one they have."""
    require_manage(db, principal, tenant_id)
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "Person not found")
    now = utcnow()
    _check_grant(db, user, tenant_id, role, expires_at, now)
    row = db.execute(select(IsmsMembership).where(IsmsMembership.tenant_id == tenant_id,
                                                  IsmsMembership.user_id == user_id)).scalar_one_or_none()
    if row is None:
        row = IsmsMembership(tenant_id=tenant_id, user_id=user_id, role=role, expires_at=expires_at,
                             granted_by=principal.actor, created_at=now, updated_at=now)
        db.add(row)
        audit.record(db, principal.actor, "isms.role_granted", user.email, tenant_id, role=role,
                     expiresAt=expires_at.isoformat() if expires_at else None)
    else:
        before = {"role": row.role, "expiresAt": row.expires_at.isoformat() if row.expires_at else None}
        row.role, row.expires_at, row.granted_by, row.updated_at = role, expires_at, principal.actor, now
        audit.record(db, principal.actor, "isms.role_changed", user.email, tenant_id, before=before, role=role,
                     expiresAt=expires_at.isoformat() if expires_at else None)
    return row


def revoke(db: Session, principal: Principal, membership: IsmsMembership) -> None:
    require_manage(db, principal, membership.tenant_id)
    user = db.get(User, membership.user_id)
    audit.record(db, principal.actor, "isms.role_revoked", user.email if user else membership.user_id,
                 membership.tenant_id, role=membership.role)
    db.delete(membership)
