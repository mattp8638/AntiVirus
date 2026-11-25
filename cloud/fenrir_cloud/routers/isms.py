"""ISMS API: roles per person per customer, and what the signed-in person may do (docs/ISMS_REWRITE_PLAN.md)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, current_principal
from ..isms import access, memberships, organization, programme, rls
from ..isms.access import ROLE_PERMISSIONS, TENANT_ROLES
from ..isms.models import IsmsAsset, IsmsMembership, IsmsTenantControl
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
    return {"tenantId": tenant_id, "userId": principal.user.id, "role": role,
            "permissions": sorted(ROLE_PERMISSIONS.get(role or "", ())),
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


# Programme: frameworks, onboarding answers, applicability and controls ---------------------------------------------

class FrameworkChoice(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    status: str = "target_certification"
    target_date: str | None = Field(default=None, alias="targetDate")


class Frameworks(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    tenant_id: str = Field(alias="tenantId", min_length=1, max_length=32)
    frameworks: dict[str, FrameworkChoice]


@router.get("/programme/frameworks")
def get_frameworks(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, tenant_id, "programme.manage")
    return {"frameworks": programme.framework_options(db, tenant_id)}


@router.put("/programme/frameworks")
def put_frameworks(body: Frameworks, principal: Principal = Depends(current_principal),
                   db: Session = Depends(isms_db)):
    """Chooses the customer's frameworks. Applicability is not recomputed until the change is reviewed and applied."""
    require_isms(db, principal, body.tenant_id, "programme.manage")
    programme.set_frameworks(db, body.tenant_id, principal.actor,
                             {k: {"status": v.status, "targetDate": v.target_date} for k, v in body.frameworks.items()})
    db.commit()
    return {"frameworks": programme.framework_options(db, body.tenant_id)}


@router.get("/programme/questions")
def get_questions(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, tenant_id, "programme.manage")
    return {"questions": programme.questions(db, tenant_id)}


class Answers(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    tenant_id: str = Field(alias="tenantId", min_length=1, max_length=32)
    answers: dict[str, object | None] = Field(default_factory=dict)


def _decision(d) -> dict:
    return {"type": d.type, "key": d.key, "applicable": d.applicable, "source": d.source, "reason": d.reason,
            "ruleRefs": list(d.rule_refs), "locked": d.locked, "justification": d.justification}


def _preview(p) -> dict:
    decisions = list(p.decisions.values())
    counts = {t: {"applicable": sum(1 for d in decisions if d.type == t and d.applicable),
                  "excluded": sum(1 for d in decisions if d.type == t and not d.applicable)}
              for t in ("requirement", "control", "template_section")}
    return {"changes": [{"key": c.key, "type": c.type, "item": c.item, "from": c.before, "to": c.after,
                         "reason": c.reason} for c in p.changes],
            "rejectedOverrides": [{"type": r.override.type, "key": r.override.key, "problem": r.problem}
                                  for r in p.rejected], "counts": counts}


@router.post("/programme/preview")
def preview_applicability(body: Answers, principal: Principal = Depends(current_principal),
                          db: Session = Depends(isms_db)):
    """What applying these answers would change, without saving anything."""
    require_isms(db, principal, body.tenant_id, "programme.manage")
    return _preview(programme.preview(db, body.tenant_id, body.answers))


@router.post("/programme/apply")
def apply_applicability(body: Answers, principal: Principal = Depends(current_principal),
                        db: Session = Depends(isms_db)):
    """Saves the answers and applies applicability: decisions, and the customer's controls."""
    require_isms(db, principal, body.tenant_id, "programme.manage")
    result = programme.apply(db, body.tenant_id, principal.actor, body.answers)
    db.commit()
    return _preview(result)


@router.get("/programme/applicability")
def get_applicability(tenant_id: str, principal: Principal = Depends(current_principal),
                      db: Session = Depends(isms_db)):
    """The applied decisions, with the manual overrides."""
    require_isms(db, principal, tenant_id, "controls.view")
    decisions = programme.current_decisions(db, tenant_id)
    return {"decisions": [_decision(d) for d in decisions.values()],
            "overrides": [{"type": o.target_type, "key": o.target_key, "applicable": o.applicable,
                           "justification": o.justification, "setByControl": o.set_by_control}
                          for o in programme.overrides(db, tenant_id)]}


class Override(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    tenant_id: str = Field(alias="tenantId", min_length=1, max_length=32)
    type: str
    key: str = Field(min_length=1, max_length=200)
    applicable: bool
    justification: str = Field(max_length=4000)


@router.put("/programme/overrides")
def put_override(body: Override, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    """Records a manual applicability decision with its justification, then applies applicability."""
    require_isms(db, principal, body.tenant_id, "programme.manage")
    programme.set_override(db, body.tenant_id, principal.actor, body.type, body.key, body.applicable,
                           body.justification)
    result = programme.apply(db, body.tenant_id, principal.actor)
    db.commit()
    return _preview(result)


@router.delete("/programme/overrides")
def delete_override(tenant_id: str, type: str, key: str, principal: Principal = Depends(current_principal),
                    db: Session = Depends(isms_db)):
    require_isms(db, principal, tenant_id, "programme.manage")
    programme.remove_override(db, tenant_id, principal.actor, type, key)
    result = programme.apply(db, tenant_id, principal.actor)
    db.commit()
    return _preview(result)


@router.get("/controls")
def list_controls(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, tenant_id, "controls.view")
    rows = programme.control_rows(db, tenant_id)
    owners = {u.id: u for u in db.execute(select(User).where(
        User.id.in_([r["ownerId"] for r in rows if r["ownerId"]]))).scalars()}
    for r in rows:
        owner = owners.get(r["ownerId"] or "")
        r["ownerName"] = (owner.name or owner.email) if owner else None
    return {"controls": rows, "manualStates": programme.MANUAL_STATES}


class ControlUpdate(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    owner_id: str | None = Field(default=None, alias="ownerId")
    state: str | None = None
    notes: str | None = Field(default=None, max_length=4000)


@router.patch("/controls/{control_id}")
def patch_control(control_id: str, body: ControlUpdate, principal: Principal = Depends(current_principal),
                  db: Session = Depends(isms_db)):
    """Sets a control's owner, state and notes. Owners can edit their own controls (record-level override)."""
    row = get_scoped(db, IsmsTenantControl, control_id, principal)
    role = memberships.active_role(db, principal.user, row.tenant_id)
    if not access.can_on_record(role, principal.user.id, "controls.edit", row.owner_user_id):
        raise HTTPException(403, f"Your ISMS role ({role or 'none'}) cannot do this (controls.edit)")
    owner_given = "owner_id" in body.model_fields_set  # an explicit null clears the owner
    if owner_given and not access.can(role, "controls.edit"):
        raise HTTPException(403, "Only people who can edit every control can change its owner")
    members = {m.user_id for m in db.execute(select(IsmsMembership).where(
        IsmsMembership.tenant_id == row.tenant_id)).scalars()}
    programme.update_control(db, row, principal.actor, (body.owner_id or "") if owner_given else None, body.state,
                             body.notes, members)
    db.commit()
    return next(r for r in programme.control_rows(db, row.tenant_id) if r["id"] == row.id)


class Assessment(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    answer: str
    implementation: str = Field(default="", max_length=4000)
    justification: str | None = Field(default=None, max_length=4000)
    owner_id: str | None = Field(default=None, alias="ownerId")


@router.post("/controls/{control_id}/assessment")
def assess_control(control_id: str, body: Assessment, principal: Principal = Depends(current_principal),
                   db: Session = Depends(isms_db)):
    """"Is this in place today?" for a control. "not_relevant" excludes the control and what it fully satisfies."""
    row = get_scoped(db, IsmsTenantControl, control_id, principal)
    role = memberships.active_role(db, principal.user, row.tenant_id)
    if not access.can_on_record(role, principal.user.id, "controls.edit", row.owner_user_id):
        raise HTTPException(403, f"Your ISMS role ({role or 'none'}) cannot do this (controls.edit)")
    owner_given = "owner_id" in body.model_fields_set
    if owner_given and not access.can(role, "controls.edit"):
        raise HTTPException(403, "Only people who can edit every control can change its owner")
    if body.answer == "not_relevant" and not access.can(role, "programme.manage"):
        raise HTTPException(403, "Only people who run the programme can exclude a control")
    members = {m.user_id for m in db.execute(select(IsmsMembership).where(
        IsmsMembership.tenant_id == row.tenant_id)).scalars()}
    try:
        programme.assess_control(db, row, principal.actor, principal.user.id, body.answer, body.implementation,
                                 body.justification, (body.owner_id or "") if owner_given else None, members)
    except HTTPException:
        db.rollback()
        raise
    db.commit()
    return next(r for r in programme.control_rows(db, row.tenant_id) if r["id"] == row.id)


@router.get("/soa")
def get_soa(tenant_id: str, framework: str, principal: Principal = Depends(current_principal),
            db: Session = Depends(isms_db)):
    require_isms(db, principal, tenant_id, "controls.view")
    return {"framework": framework, "rows": programme.soa_rows(db, tenant_id, framework)}


@router.get("/soa/export")
def export_soa(tenant_id: str, framework: str, principal: Principal = Depends(current_principal),
               db: Session = Depends(isms_db)):
    """The Statement of Applicability as an Excel workbook. Every export is audited."""
    from .. import audit
    from ..isms import soa_export
    from ..models import Tenant

    require_isms(db, principal, tenant_id, "controls.view")
    rows = programme.soa_rows(db, tenant_id, framework)
    pinned = next(f for f in programme.tenant_frameworks(db, tenant_id) if f.framework == framework)
    pack = programme.library.get(db, pinned.pack_id, pinned.pack_version)
    tenant = db.get(Tenant, tenant_id)
    now = datetime.now(timezone.utc)
    data = soa_export.build_workbook(rows, tenant.name, pack.data["meta"]["name"], pack.data["meta"]["version"],
                                     principal.user.name or principal.actor, now)
    audit.record(db, principal.actor, "isms.soa_exported", framework, tenant_id, rows=len(rows))
    db.commit()
    name = f"Statement of Applicability {tenant.name} {framework} {now:%Y-%m-%d}.xlsx"
    safe = "".join(c if c.isalnum() or c in " ._-" else "_" for c in name)
    return Response(content=data, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="{safe}"'})


@router.get("/readiness")
def get_readiness(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, tenant_id, "controls.view")
    return {"frameworks": programme.readiness(db, tenant_id)}
