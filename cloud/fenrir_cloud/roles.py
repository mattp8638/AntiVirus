"""Effective permissions and safe role assignment (CORE-02).

A user's permissions come from a built-in role or a custom role ("custom:<id>"). Nobody can give anyone - including
themselves - a role, or manage a user, whose permissions they do not hold: that is the one rule for creating users,
changing roles and building custom roles, so customer administrators cannot promote anyone to MSP powers.
"""
from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .models import CustomRole, User
from .security import PERMISSIONS, ROLE_PERMISSIONS

CUSTOM_PREFIX = "custom:"
NEVER_CUSTOM = {"platform", "portal"}


def custom_role(db: Session, role: str) -> CustomRole | None:
    if not role.startswith(CUSTOM_PREFIX):
        return None
    return db.get(CustomRole, role[len(CUSTOM_PREFIX):])


def permissions_of(db: Session, role: str) -> set[str]:
    if role.startswith(CUSTOM_PREFIX):
        row = custom_role(db, role)
        return set(row.permissions or []) - NEVER_CUSTOM if row else set()
    return set(ROLE_PERMISSIONS.get(role, set()))


def held(principal) -> set[str]:
    return {p for p in [*PERMISSIONS, "portal"] if principal.can(p)}


def check_assignable(db: Session, principal, role: str, user_tenant_id: str) -> None:
    """Raise unless the principal may give this role to a user of this tenant."""
    from .deps import tenant_subtree

    if role.startswith(CUSTOM_PREFIX):
        row = custom_role(db, role)
        if row is None or row.tenant_id not in principal.tenant_ids:
            raise HTTPException(400, "Unknown role")
        if user_tenant_id not in tenant_subtree(db, row.tenant_id):
            raise HTTPException(400, "This custom role belongs to another customer")
    elif role not in ROLE_PERMISSIONS or role == "service":
        raise HTTPException(400, f"role must be one of {', '.join(r for r in ROLE_PERMISSIONS)} or a custom role")
    missing = permissions_of(db, role) - held(principal) - {"portal"}  # portal access is not a power over anything
    if missing:
        raise HTTPException(403, f"You cannot give a role with permissions you do not have: {', '.join(sorted(missing))}")


def check_manageable(db: Session, principal, user: User) -> None:
    """Raise unless the principal holds every permission the user has (no editing someone more powerful)."""
    if user.id == principal.user.id:
        return
    missing = permissions_of(db, user.role) - held(principal) - {"portal"}
    if missing:
        raise HTTPException(403, "You cannot change an account with more permissions than your own")
