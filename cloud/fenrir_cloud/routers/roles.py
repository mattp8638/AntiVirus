"""Custom roles (CORE-02): an explicit permission set owned by a customer or the MSP. You can only build a role from
permissions you hold yourself, and platform administration can never be part of one."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, roles
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import CustomRole, User, utcnow
from ..security import PERMISSIONS, ROLE_PERMISSIONS

router = APIRouter(prefix="/api/console/roles", tags=["Roles"])


def _view(db: Session, row: CustomRole) -> dict:
    users = db.execute(select(User.id).where(User.role == roles.CUSTOM_PREFIX + row.id)).all()
    return {"id": row.id, "role": roles.CUSTOM_PREFIX + row.id, "tenantId": row.tenant_id, "name": row.name, "description": row.description,
            "permissions": sorted(row.permissions or []), "users": len(users), "createdBy": row.created_by,
            "createdAt": row.created_at.isoformat() + "Z", "updatedAt": row.updated_at.isoformat() + "Z"}


@router.get("")
def list_roles(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    rows = db.execute(select(CustomRole).where(CustomRole.tenant_id.in_(scoped_tenant(principal, tenant_id))).order_by(CustomRole.name)).scalars().all()
    held = roles.held(principal)
    return {"permissions": [{"key": k, "label": v, "grantable": k in held and k not in roles.NEVER_CUSTOM} for k, v in PERMISSIONS.items()],
            "builtIn": [{"role": r, "permissions": sorted(p)} for r, p in ROLE_PERMISSIONS.items() if r != "client"],
            "custom": [_view(db, r) for r in rows]}


class RoleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str | None = None
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    permissions: list[str] = Field(min_length=1, max_length=len(PERMISSIONS))


def _check_permissions(principal: Principal, permissions: list[str]) -> list[str]:
    unknown = [p for p in permissions if p not in PERMISSIONS or p in roles.NEVER_CUSTOM]
    if unknown:
        raise HTTPException(400, f"These permissions cannot be part of a custom role: {', '.join(unknown)}")
    missing = set(permissions) - roles.held(principal)
    if missing:
        raise HTTPException(403, f"You cannot grant permissions you do not have: {', '.join(sorted(missing))}")
    return sorted(set(permissions))


@router.post("")
def create_role(body: RoleInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.tenantId or principal.user.tenant_id
    principal.check_tenant(tenant_id)
    row = CustomRole(tenant_id=tenant_id, name=body.name.strip(), description=body.description.strip(),
                     permissions=_check_permissions(principal, body.permissions), created_by=principal.actor)
    db.add(row)
    db.flush()
    audit.record(db, principal.actor, "role.created", row.name, tenant_id, permissions=row.permissions)
    db.commit()
    return _view(db, row)


def _owned(db: Session, principal: Principal, role_id: str) -> CustomRole:
    row = db.get(CustomRole, role_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    return row


class RoleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    permissions: list[str] | None = Field(default=None, min_length=1, max_length=len(PERMISSIONS))


@router.patch("/{role_id}")
def update_role(role_id: str, body: RoleUpdate, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = _owned(db, principal, role_id)
    if set(row.permissions or []) - roles.held(principal):
        raise HTTPException(403, "You cannot change a role with permissions you do not have")
    if body.name is not None:
        row.name = body.name.strip()
    if body.description is not None:
        row.description = body.description.strip()
    if body.permissions is not None:
        before = list(row.permissions or [])
        row.permissions = _check_permissions(principal, body.permissions)
        audit.record(db, principal.actor, "role.permissions_changed", row.name, row.tenant_id, before=before, after=row.permissions)
        # Holders keep their sessions, but each request re-reads the role, so the change applies at once.
    row.updated_at = utcnow()
    db.commit()
    return _view(db, row)


@router.delete("/{role_id}")
def delete_role(role_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = _owned(db, principal, role_id)
    if set(row.permissions or []) - roles.held(principal):
        raise HTTPException(403, "You cannot delete a role with permissions you do not have")
    if db.execute(select(User.id).where(User.role == roles.CUSTOM_PREFIX + row.id)).first():
        raise HTTPException(409, "Move its users to another role first")
    audit.record(db, principal.actor, "role.deleted", row.name, row.tenant_id)
    db.delete(row)
    db.commit()
    return {"ok": True}
