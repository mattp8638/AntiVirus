"""ISMS API: roles per person per customer, and what the signed-in person may do (docs/ISMS_REWRITE_PLAN.md)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, current_principal
from ..isms import access, memberships, organization, rls
from ..isms.access import ROLE_PERMISSIONS, TENANT_ROLES
from ..isms.models import IsmsAsset, IsmsMembership
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


# Organization, scope and assets (ISO 27001 4.1 to 4.3) ----------------------------------------------------------

def require_isms(db: Session, principal: Principal, tenant_id: str, permission: str) -> str:
    """The principal's ISMS role in this customer, which must allow ``permission``."""
    principal.check_tenant(tenant_id)
    role = memberships.active_role(db, principal.user, tenant_id)
    if not access.can(role, permission):
        raise HTTPException(403, f"Your ISMS role ({role or 'none'}) cannot do this ({permission})")
    return role


def _row(row, fields) -> dict:
    return {"id": row.id, **{_camel(f): getattr(row, f) for f in fields}, "updatedAt": _iso(row.updated_at),
            "updatedBy": row.updated_by}


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(p.title() for p in rest)


def _snake(data: dict) -> dict:
    return {"".join("_" + c.lower() if c.isupper() else c for c in k): v for k, v in data.items()}


class TenantBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    tenant_id: str = Field(alias="tenantId", min_length=1, max_length=32)

    def fields(self) -> dict:
        return _snake(dict(self.model_extra or {}))


@router.get("/scope")
def get_scope(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, tenant_id, "programme.manage")
    row = organization.get_scope(db, tenant_id)
    if row is None:
        return {"statement": "", "boundaries": "", "interfaces": "", "exclusions": "", "version": 0, "updatedAt": None}
    return {**{f: getattr(row, f) for f in organization.SCOPE_FIELDS}, "version": row.version,
            "updatedAt": _iso(row.updated_at), "updatedBy": row.updated_by}


@router.put("/scope")
def put_scope(body: TenantBody, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, body.tenant_id, "programme.manage")
    row = organization.save_scope(db, body.tenant_id, principal.actor, body.fields())
    db.commit()
    return {"version": row.version}


@router.get("/registers/{name}")
def list_register(name: str, tenant_id: str, principal: Principal = Depends(current_principal),
                  db: Session = Depends(isms_db)):
    reg = organization.register(name)
    require_isms(db, principal, tenant_id, "programme.manage")
    return {"items": [_row(r, reg.fields) for r in organization.list_items(db, reg, tenant_id)]}


@router.post("/registers/{name}")
def add_register_item(name: str, body: TenantBody, principal: Principal = Depends(current_principal),
                      db: Session = Depends(isms_db)):
    reg = organization.register(name)
    require_isms(db, principal, body.tenant_id, "programme.manage")
    row = organization.add_item(db, reg, body.tenant_id, principal.actor, body.fields())
    db.commit()
    return _row(row, reg.fields)


@router.patch("/registers/{name}/{item_id}")
def update_register_item(name: str, item_id: str, body: dict = Body(...),
                         principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    reg = organization.register(name)
    row = get_scoped(db, reg.model, item_id, principal)
    require_isms(db, principal, row.tenant_id, "programme.manage")
    organization.update_item(db, reg, row, principal.actor, _snake(body))
    db.commit()
    return _row(row, reg.fields)


@router.delete("/registers/{name}/{item_id}")
def delete_register_item(name: str, item_id: str, principal: Principal = Depends(current_principal),
                         db: Session = Depends(isms_db)):
    reg = organization.register(name)
    row = get_scoped(db, reg.model, item_id, principal)
    require_isms(db, principal, row.tenant_id, "programme.manage")
    organization.delete_item(db, reg, row, principal.actor)
    db.commit()
    return {"ok": True}


ASSET_FIELDS = ("type", "name", "description", "classification", "owner_user_id")


def _asset(row: IsmsAsset, owners: dict[str, User]) -> dict:
    owner = owners.get(row.owner_user_id or "")
    return {**_row(row, ASSET_FIELDS), "ownerId": row.owner_user_id,
            "ownerName": (owner.name or owner.email) if owner else None}


def _owners(db: Session, rows) -> dict[str, User]:
    ids = [r.owner_user_id for r in rows if r.owner_user_id]
    return {u.id: u for u in db.execute(select(User).where(User.id.in_(ids))).scalars()} if ids else {}


@router.get("/assets")
def list_assets(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, tenant_id, "programme.manage")
    rows = db.execute(scoped(IsmsAsset, principal, tenant_id).order_by(IsmsAsset.type, IsmsAsset.name)).scalars().all()
    owners = _owners(db, rows)
    return {"items": [_asset(r, owners) for r in rows], "types": organization.ASSET_TYPES,
            "classifications": organization.CLASSIFICATIONS, "csvColumns": organization.ASSET_CSV_COLUMNS}


@router.post("/assets")
def add_asset(body: TenantBody, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, body.tenant_id, "programme.manage")
    row = organization.add_asset(db, body.tenant_id, principal.actor, dict(body.model_extra or {}))
    db.commit()
    return _asset(row, _owners(db, [row]))


@router.patch("/assets/{asset_id}")
def update_asset(asset_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                 db: Session = Depends(isms_db)):
    row = get_scoped(db, IsmsAsset, asset_id, principal)
    require_isms(db, principal, row.tenant_id, "programme.manage")
    organization.update_asset(db, row, principal.actor, body)
    db.commit()
    return _asset(row, _owners(db, [row]))


@router.delete("/assets/{asset_id}")
def delete_asset(asset_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    row = get_scoped(db, IsmsAsset, asset_id, principal)
    require_isms(db, principal, row.tenant_id, "programme.manage")
    organization.delete_asset(db, row, principal.actor)
    db.commit()
    return {"ok": True}


class CsvImport(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    tenant_id: str = Field(alias="tenantId", min_length=1, max_length=32)
    csv: str = Field(max_length=2_000_000)


@router.post("/assets/import")
def import_assets(body: CsvImport, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    """All or nothing: when any row has a problem nothing is saved and every problem is listed with its line."""
    require_isms(db, principal, body.tenant_id, "programme.manage")
    result = organization.import_assets_csv(db, body.tenant_id, principal.actor, body.csv)
    if result.errors:
        db.rollback()
    else:
        db.commit()
    return {"created": result.created, "updated": result.updated, "errors": result.errors}


@router.get("/members")
def list_members(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    """People with an ISMS role in this customer, to choose as owners."""
    require_isms(db, principal, tenant_id, "programme.manage")
    rows = db.execute(select(User, IsmsMembership.role).join(IsmsMembership, IsmsMembership.user_id == User.id)
                      .where(IsmsMembership.tenant_id == tenant_id).order_by(User.email)).all()
    return {"members": [{"id": u.id, "email": u.email, "name": u.name, "role": role} for u, role in rows]}
