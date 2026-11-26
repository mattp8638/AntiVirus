"""ISMS API: roles per person per customer, and what the signed-in person may do (docs/ISMS_REWRITE_PLAN.md)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, current_principal
from ..isms import access, memberships, organization, programme, risk_register, rls
from ..isms import evidence as isms_evidence
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
    from ..isms import governance_import

    require_isms(db, principal, tenant_id, "controls.view")
    earlier = governance_import.legacy_answers(db, tenant_id, framework)
    rows = [{**r, "earlierAnswers": earlier.get(r["ref"], [])} for r in programme.soa_rows(db, tenant_id, framework)]
    return {"framework": framework, "rows": rows, "unmatchedEarlierAnswers": earlier.get("", [])}


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


# Risk (ISO 27001 6.1.2, 6.1.3, 8.2, 8.3) ------------------------------------------------------------------------

def _members(db: Session, tenant_id: str) -> set[str]:
    return {m.user_id for m in db.execute(select(IsmsMembership).where(IsmsMembership.tenant_id == tenant_id)).scalars()}


@router.get("/risk/method")
def get_risk_method(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, tenant_id, "risks.view")
    return risk_register.method_dict(*risk_register.get_method(db, tenant_id))


@router.put("/risk/method")
def put_risk_method(body: TenantBody, principal: Principal = Depends(current_principal),
                    db: Session = Depends(isms_db)):
    """Saves the risk method; each change makes a new version."""
    require_isms(db, principal, body.tenant_id, "programme.manage")
    version = risk_register.save_method(db, body.tenant_id, principal.actor,
                                        risk_register.parse_method(dict(body.model_extra or {})))
    db.commit()
    return risk_register.method_dict(*risk_register.get_method(db, body.tenant_id)) | {"version": version}


@router.get("/risks")
def list_risks(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, tenant_id, "risks.view")
    return {"risks": risk_register.risk_views(db, tenant_id), "heatMap": risk_register.heat_map(db, tenant_id),
            "treatments": risk_register.TREATMENTS}


def _risk_row(db: Session, principal: Principal, risk_id: str):
    from ..isms.models import IsmsRisk

    return get_scoped(db, IsmsRisk, risk_id, principal)


def _save_controls(db, row, principal, body: dict) -> None:
    if "controlIds" in body:
        risk_register.set_controls(db, row, principal.actor, [str(c) for c in body.get("controlIds") or []])


@router.post("/risks")
def add_risk(body: TenantBody, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, body.tenant_id, "risks.edit")
    data = dict(body.model_extra or {})
    row = risk_register.save_risk(db, body.tenant_id, principal.actor, data, _members(db, body.tenant_id))
    _save_controls(db, row, principal, data)
    db.commit()
    return risk_register.risk_views(db, row.tenant_id, row.id)[0]


@router.patch("/risks/{risk_id}")
def update_risk(risk_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                db: Session = Depends(isms_db)):
    """Edits a risk. Its owner can edit it without broader rights, but only people who can edit every risk can change
    the owner."""
    row = _risk_row(db, principal, risk_id)
    role = memberships.active_role(db, principal.user, row.tenant_id)
    if not access.can_on_record(role, principal.user.id, "risks.edit", row.owner_user_id):
        raise HTTPException(403, f"Your ISMS role ({role or 'none'}) cannot do this (risks.edit)")
    if (body.get("ownerId") or None) != row.owner_user_id and not access.can(role, "risks.edit"):
        raise HTTPException(403, "Only people who can edit every risk can change its owner")
    risk_register.save_risk(db, row.tenant_id, principal.actor, body, _members(db, row.tenant_id), row)
    _save_controls(db, row, principal, body)
    db.commit()
    return risk_register.risk_views(db, row.tenant_id, row.id)[0]


class Acceptance(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rationale: str = Field(max_length=4000)


@router.post("/risks/{risk_id}/accept")
def accept_risk(risk_id: str, body: Acceptance, principal: Principal = Depends(current_principal),
                db: Session = Depends(isms_db)):
    """The risk owner accepts the residual risk."""
    row = _risk_row(db, principal, risk_id)
    require_isms(db, principal, row.tenant_id, "risks.view")
    risk_register.accept(db, row, principal.actor, principal.user.id, body.rationale)
    db.commit()
    return risk_register.risk_views(db, row.tenant_id, row.id)[0]


@router.post("/risks/snapshots")
def take_snapshot(body: TenantBody, principal: Principal = Depends(current_principal),
                  db: Session = Depends(isms_db)):
    require_isms(db, principal, body.tenant_id, "risks.edit")
    row = risk_register.snapshot(db, body.tenant_id, principal.actor, principal.user.id,
                                 str((body.model_extra or {}).get("reason") or "manual"))
    db.commit()
    return {"id": row.id, "takenAt": _iso(row.taken_at), "risks": len(row.payload["risks"])}


@router.get("/risks/snapshots")
def list_snapshots(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    from ..isms.models import IsmsRiskSnapshot

    require_isms(db, principal, tenant_id, "risks.view")
    rows = db.execute(scoped(IsmsRiskSnapshot, principal, tenant_id).order_by(IsmsRiskSnapshot.taken_at.desc())
                      .limit(50)).scalars().all()
    names = {u.id: (u.name or u.email) for u in db.execute(select(User).where(
        User.id.in_([r.taken_by_user_id for r in rows if r.taken_by_user_id]))).scalars()}
    return {"snapshots": [{"id": r.id, "takenAt": _iso(r.taken_at), "reason": r.reason,
                           "takenBy": names.get(r.taken_by_user_id), "risks": len(r.payload.get("risks", []))}
                          for r in rows]}


# Evidence -------------------------------------------------------------------------------------------------------

def _evidence(row, links: dict[str, list[dict]], names: dict[str, str]) -> dict:
    from ..isms.evidence import is_current

    return {"id": row.id, "title": row.title, "kind": row.kind, "filename": row.filename, "size": row.size,
            "sha256": row.sha256, "url": row.url, "note": row.note, "source": row.source, "passing": row.passing,
            "collectedAt": _iso(row.collected_at),
            "validUntil": row.valid_until.isoformat() if row.valid_until else None, "current": is_current(row),
            "scanStatus": row.scan_status, "scanDetail": row.scan_detail,
            "uploadedBy": names.get(row.uploaded_by_user_id or "", row.updated_by), "controls": links.get(row.id, [])}


def _evidence_rows(db: Session, rows) -> list[dict]:
    from ..isms.models import IsmsEvidenceLink

    ids = [r.id for r in rows]
    links: dict[str, list[dict]] = {}
    if ids:
        for eid, tc in db.execute(select(IsmsEvidenceLink.evidence_id, IsmsTenantControl).join(
                IsmsTenantControl, IsmsTenantControl.id == IsmsEvidenceLink.tenant_control_id)
                .where(IsmsEvidenceLink.evidence_id.in_(ids))).all():
            links.setdefault(eid, []).append({"id": tc.id, "ref": tc.ref, "title": tc.title})
    for v in links.values():
        v.sort(key=lambda c: c["ref"])
    user_ids = [r.uploaded_by_user_id for r in rows if r.uploaded_by_user_id]
    names = {u.id: (u.name or u.email) for u in db.execute(select(User).where(User.id.in_(user_ids))).scalars()} \
        if user_ids else {}
    return [_evidence(r, links, names) for r in rows]


@router.get("/evidence")
def list_evidence(tenant_id: str, control_id: str | None = None, principal: Principal = Depends(current_principal),
                  db: Session = Depends(isms_db)):
    from ..isms.models import IsmsEvidence, IsmsEvidenceLink

    require_isms(db, principal, tenant_id, "evidence.view")
    stmt = scoped(IsmsEvidence, principal, tenant_id).order_by(IsmsEvidence.collected_at.desc()).limit(2000)
    if control_id:
        stmt = stmt.where(IsmsEvidence.id.in_(select(IsmsEvidenceLink.evidence_id)
                                              .where(IsmsEvidenceLink.tenant_control_id == control_id)))
    return {"evidence": _evidence_rows(db, db.execute(stmt).scalars().all())}


def _can_upload(db: Session, principal: Principal, tenant_id: str, control_ids: list[str]) -> None:
    """Evidence upload needs evidence.upload; a control owner may also add evidence to the controls they own."""
    role = memberships.active_role(db, principal.user, tenant_id)
    if access.can(role, "evidence.upload"):
        return
    owned = set(db.execute(select(IsmsTenantControl.id).where(IsmsTenantControl.tenant_id == tenant_id,
                                                              IsmsTenantControl.owner_user_id == principal.user.id))
                .scalars())
    if not (control_ids and set(control_ids) <= owned and access.can(role, "controls.view")):
        raise HTTPException(403, f"Your ISMS role ({role or 'none'}) cannot do this (evidence.upload)")


class EvidenceIn(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    tenant_id: str = Field(alias="tenantId", min_length=1, max_length=32)
    title: str = Field(max_length=300)
    kind: str
    url: str | None = Field(default=None, max_length=2000)
    note: str | None = Field(default=None, max_length=10_000)
    valid_until: str | None = Field(default=None, alias="validUntil")
    control_ids: list[str] = Field(default_factory=list, alias="controlIds", max_length=200)


@router.post("/evidence")
def add_evidence(body: EvidenceIn, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    """A link or a written note as evidence for controls."""
    principal.check_tenant(body.tenant_id)
    _can_upload(db, principal, body.tenant_id, body.control_ids)
    row = isms_evidence.add_link_or_note(db, body.tenant_id, principal.actor, principal.user.id, body.title, body.kind,
                                         body.url, body.note, body.valid_until, body.control_ids)
    db.commit()
    return _evidence_rows(db, [row])[0]


@router.post("/evidence/upload")
async def upload_evidence(request: Request, tenant_id: str, filename: str, controls: str, title: str = "",
                          valid_until: str | None = None, principal: Principal = Depends(current_principal),
                          db: Session = Depends(isms_db)):
    """The file is the request body (up to 25 MB); ``controls`` is a comma-separated list of control ids."""
    principal.check_tenant(tenant_id)
    control_ids = [c for c in controls.split(",") if c][:200]
    _can_upload(db, principal, tenant_id, control_ids)
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > isms_evidence.MAX_EVIDENCE_BYTES:
        raise HTTPException(413, "Files can be up to 25 MB.")
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > isms_evidence.MAX_EVIDENCE_BYTES:
            raise HTTPException(413, "Files can be up to 25 MB.")
    row = isms_evidence.add_file(db, tenant_id, principal.actor, principal.user.id, title[:300], filename[:255],
                                 request.headers.get("content-type") or "application/octet-stream", bytes(data),
                                 valid_until, control_ids)
    db.commit()
    return _evidence_rows(db, [row])[0]


class EvidenceUpdate(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    control_ids: list[str] | None = Field(default=None, alias="controlIds", max_length=200)
    valid_until: str | None = Field(default=None, alias="validUntil")


@router.patch("/evidence/{evidence_id}")
def update_evidence(evidence_id: str, body: EvidenceUpdate, principal: Principal = Depends(current_principal),
                    db: Session = Depends(isms_db)):
    from ..isms.models import IsmsEvidence

    row = get_scoped(db, IsmsEvidence, evidence_id, principal)
    require_isms(db, principal, row.tenant_id, "programme.manage")
    if body.control_ids is not None:
        isms_evidence.set_links(db, row, principal.actor, body.control_ids)
    if "valid_until" in body.model_fields_set:
        isms_evidence.set_valid_until(db, row, principal.actor, body.valid_until)
    db.commit()
    return _evidence_rows(db, [row])[0]


@router.delete("/evidence/{evidence_id}")
def delete_evidence(evidence_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    from ..isms.models import IsmsEvidence

    row = get_scoped(db, IsmsEvidence, evidence_id, principal)
    require_isms(db, principal, row.tenant_id, "programme.manage")
    isms_evidence.delete_evidence(db, row, principal.actor)
    db.commit()
    return {"ok": True}


@router.get("/evidence/{evidence_id}/download")
def download_evidence(evidence_id: str, principal: Principal = Depends(current_principal),
                      db: Session = Depends(isms_db)):
    """The file, once it has been scanned clean. Every download is audited."""
    from .. import audit
    from ..isms.models import IsmsEvidence

    row = get_scoped(db, IsmsEvidence, evidence_id, principal)
    require_isms(db, principal, row.tenant_id, "evidence.view")
    data = isms_evidence.file_for_download(row)
    audit.record(db, principal.actor, "isms.evidence_downloaded", row.filename or row.title, row.tenant_id, id=row.id)
    db.commit()
    safe = "".join(c if c.isalnum() or c in " ._-" else "_" for c in (row.filename or "evidence"))
    return Response(content=data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{safe}"',
                             "X-Content-Type-Options": "nosniff"})


@router.post("/evidence/import-fenrir")
def import_fenrir_now(body: TenantBody, principal: Principal = Depends(current_principal),
                      db: Session = Depends(isms_db)):
    """Imports Fenrir's latest automated GRC results now, instead of waiting for the hourly job."""
    require_isms(db, principal, body.tenant_id, "programme.manage")
    out = isms_evidence.import_fenrir(db, body.tenant_id, principal.actor)
    db.commit()
    return out


# Tasks and calendar (ISO 27001 8.1) -----------------------------------------------------------------------------

@router.get("/tasks")
def list_tasks(tenant_id: str, status: str = "open", mine: bool = False,
               principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    """Open, done or all tasks. People who do not run the programme see only their own."""
    from ..isms import tasks as isms_tasks

    role = require_isms(db, principal, tenant_id, "tasks.complete")
    if status not in ("open", "done", "all"):
        raise HTTPException(400, "status is open, done or all")
    own_only = mine or not access.can(role, "programme.manage")
    return {"tasks": isms_tasks.task_rows(db, tenant_id, status, principal.user.id if own_only else None),
            "ownOnly": own_only}


class ManualTask(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    tenant_id: str = Field(alias="tenantId", min_length=1, max_length=32)
    title: str = Field(max_length=300)
    due_on: str = Field(alias="dueOn")
    assignee_id: str | None = Field(default=None, alias="assigneeId")
    description: str | None = Field(default=None, max_length=4000)


@router.post("/tasks")
def add_task(body: ManualTask, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    from ..isms import tasks as isms_tasks

    require_isms(db, principal, body.tenant_id, "programme.manage")
    row = isms_tasks.add_manual(db, body.tenant_id, principal.actor, body.title, body.due_on, body.assignee_id,
                                body.description, _members(db, body.tenant_id))
    db.commit()
    return isms_tasks.task_rows(db, body.tenant_id, "all", task_id=row.id)[0]


class TaskDone(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    note: str = Field(default="", max_length=4000)
    evidence_id: str | None = Field(default=None, alias="evidenceId")


@router.post("/tasks/{task_id}/complete")
def complete_task(task_id: str, body: TaskDone, principal: Principal = Depends(current_principal),
                  db: Session = Depends(isms_db)):
    """Completes a task with what was checked (a note, evidence or both); a recurring one is scheduled again."""
    from ..isms import tasks as isms_tasks
    from ..isms.models import IsmsTask

    row = get_scoped(db, IsmsTask, task_id, principal)
    role = require_isms(db, principal, row.tenant_id, "tasks.complete")
    if row.assignee_user_id != principal.user.id and not access.can(role, "programme.manage"):
        raise HTTPException(403, "Only the person it is assigned to, or an ISMS manager, can complete this task")
    isms_tasks.complete(db, row, principal.actor, principal.user.id, body.note, body.evidence_id)
    db.commit()
    return isms_tasks.task_rows(db, row.tenant_id, "all", task_id=row.id)[0]


# Documents (Phase 3) --------------------------------------------------------------------------------------------

@router.get("/documents")
def list_documents(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    from ..isms import documents as isms_documents

    role = require_isms(db, principal, tenant_id, "documents.view")
    rows = isms_documents.document_rows(db, tenant_id)
    if not (access.can(role, "documents.edit") or access.can(role, "documents.approve")):
        rows = [{**r, "latest": r["published"], "outOfDate": False} for r in rows if r["published"]]
    return {"documents": rows}


class Generate(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    tenant_id: str = Field(alias="tenantId", min_length=1, max_length=32)
    doc_type: str = Field(alias="docType", pattern=r"^[a-z0-9-]{1,80}$")
    change_note: str | None = Field(default=None, alias="changeNote", max_length=2000)


@router.post("/documents/generate")
def generate_document(body: Generate, principal: Principal = Depends(current_principal),
                      db: Session = Depends(isms_db)):
    """A new draft from live data (an existing draft is rebuilt; approved versions are never touched)."""
    from ..isms import documents as isms_documents

    require_isms(db, principal, body.tenant_id, "documents.edit")
    row = isms_documents.generate(db, body.tenant_id, principal.actor, principal.user.id, body.doc_type,
                                  body.change_note)
    db.commit()
    return {"documentId": row.document_id, "versionId": row.id, "version": row.version}


def _document(db: Session, principal: Principal, document_id: str):
    from ..isms.models import IsmsDocument

    return get_scoped(db, IsmsDocument, document_id, principal)


@router.get("/documents/{document_id}")
def get_document(document_id: str, version_id: str | None = None, principal: Principal = Depends(current_principal),
                 db: Session = Depends(isms_db)):
    from ..isms import documents as isms_documents

    doc = _document(db, principal, document_id)
    role = require_isms(db, principal, doc.tenant_id, "documents.view")
    out = isms_documents.detail(db, doc.tenant_id, doc, version_id)
    if not (access.can(role, "documents.edit") or access.can(role, "documents.approve")):
        # Readers see published versions only.
        published = [v for v in out["versions"] if v["state"] == "published"]
        if out["viewing"] and out["viewing"]["state"] != "published":
            out["html"], out["blocks"], out["viewing"] = "", [], None
        out.update(versions=published, changes=[], overrides={}, templateBlocks=[])
    return out


@router.post("/documents/versions/{version_id}/{action}")
def document_action(version_id: str, action: str, principal: Principal = Depends(current_principal),
                    db: Session = Depends(isms_db)):
    """submit, return, approve, publish or withdraw a version."""
    from ..isms import documents as isms_documents
    from ..isms.models import IsmsDocumentVersion

    row = get_scoped(db, IsmsDocumentVersion, version_id, principal)
    if action not in isms_documents.ACTION_PERMISSION:
        raise HTTPException(404, "Unknown action")
    require_isms(db, principal, row.tenant_id, isms_documents.ACTION_PERMISSION[action])
    isms_documents.transition(db, row, action, principal.actor, principal.user)
    db.commit()
    return isms_documents._version(row)


class Wording(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    tenant_id: str = Field(alias="tenantId", min_length=1, max_length=32)
    doc_type: str = Field(alias="docType", pattern=r"^[a-z0-9-]{1,80}$")
    block_ref: str = Field(alias="blockRef", max_length=120)
    content: str | None = Field(default=None, max_length=20_000)


@router.put("/documents/wording")
def put_wording(body: Wording, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    """The customer's own wording for one section; it survives regeneration (empty removes it)."""
    from ..isms import documents as isms_documents

    require_isms(db, principal, body.tenant_id, "documents.edit")
    isms_documents.set_override(db, body.tenant_id, principal.actor, body.doc_type, body.block_ref, body.content)
    db.commit()
    return {"ok": True}


@router.get("/documents/versions/{version_id}/file")
def document_file(version_id: str, format: str = "docx", principal: Principal = Depends(current_principal),
                  db: Session = Depends(isms_db)):
    """The Word or PDF file of a version (the approved copy once approved). Readers can download published versions
    only. Every download is audited."""
    from .. import audit
    from ..isms import documents as isms_documents
    from ..isms.models import IsmsDocument, IsmsDocumentVersion

    row = get_scoped(db, IsmsDocumentVersion, version_id, principal)
    role = require_isms(db, principal, row.tenant_id, "documents.view")
    if row.state != "published" and not (access.can(role, "documents.edit") or access.can(role, "documents.approve")):
        raise HTTPException(404, "Not found")
    if format not in ("docx", "pdf"):
        raise HTTPException(400, "format is docx or pdf")
    data, _ = isms_documents.file_for(row, format)
    doc = db.get(IsmsDocument, row.document_id)
    audit.record(db, principal.actor, "isms.document_downloaded", f"{doc.number} v{row.version}", row.tenant_id,
                 format=format)
    db.commit()
    media = ("application/pdf" if format == "pdf"
             else "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    name = "".join(c if c.isalnum() or c in " ._-" else "_" for c in f"{doc.number} {doc.title} v{row.version}.{format}")
    return Response(content=data, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'})


# Moving the earlier Governance records ---------------------------------------------------------------------------

@router.get("/governance-import")
def governance_import_preview(tenant_id: str, principal: Principal = Depends(current_principal),
                              db: Session = Depends(isms_db)):
    """What moving this customer's earlier Governance records into the ISMS would bring across."""
    from ..isms import governance_import

    require_isms(db, principal, tenant_id, "programme.manage")
    return governance_import.preview(db, tenant_id)


@router.post("/governance-import")
def governance_import_run(body: TenantBody, principal: Principal = Depends(current_principal),
                          db: Session = Depends(isms_db)):
    """Moves the records across. Safe to run again: only what is new is added; the earlier records are not changed."""
    from ..isms import governance_import

    principal.require("grc")
    require_isms(db, principal, body.tenant_id, "programme.manage")
    out = governance_import.run(db, body.tenant_id, principal.actor, principal.user.id)
    db.commit()
    return out


# Improvement, objectives and the change log (Phase 4) -------------------------------------------------------------

def _mgmt():
    from ..isms import management
    return management


@router.get("/nonconformities")
def list_ncs(tenant_id: str, status: str = "open", principal: Principal = Depends(current_principal),
             db: Session = Depends(isms_db)):
    require_isms(db, principal, tenant_id, "controls.view")
    if status not in ("open", "closed", "cancelled", "all"):
        raise HTTPException(400, "status is open, closed, cancelled or all")
    return {"nonconformities": _mgmt().nonconformity_rows(db, tenant_id, status), "sources": _mgmt().NC_SOURCES}


@router.post("/nonconformities")
def raise_nc(body: TenantBody, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, body.tenant_id, "programme.manage")
    row = _mgmt().raise_nc(db, body.tenant_id, principal.actor, principal.user.id, dict(body.model_extra or {}),
                           _members(db, body.tenant_id))
    db.commit()
    return _mgmt().nonconformity_rows(db, body.tenant_id, "all", row.id)[0]


def _nc(db, principal, nc_id):
    from ..isms.models import IsmsNonconformity
    return get_scoped(db, IsmsNonconformity, nc_id, principal)


@router.patch("/nonconformities/{nc_id}")
def update_nc(nc_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
              db: Session = Depends(isms_db)):
    row = _nc(db, principal, nc_id)
    require_isms(db, principal, row.tenant_id, "programme.manage")
    _mgmt().update_nc(db, row, principal.actor, body, _members(db, row.tenant_id))
    db.commit()
    return _mgmt().nonconformity_rows(db, row.tenant_id, "all", row.id)[0]


@router.post("/nonconformities/{nc_id}/actions")
def add_corrective_action(nc_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                          db: Session = Depends(isms_db)):
    row = _nc(db, principal, nc_id)
    require_isms(db, principal, row.tenant_id, "programme.manage")
    _mgmt().add_action(db, row, principal.actor, body, _members(db, row.tenant_id))
    db.commit()
    return _mgmt().nonconformity_rows(db, row.tenant_id, "all", row.id)[0]


@router.post("/corrective-actions/{action_id}/done")
def complete_corrective_action(action_id: str, body: dict = Body(default={}),
                               principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    """The action's owner, or an ISMS manager, records it as done."""
    from ..isms.models import IsmsCorrectiveAction

    a = get_scoped(db, IsmsCorrectiveAction, action_id, principal)
    role = require_isms(db, principal, a.tenant_id, "tasks.complete")
    if a.owner_user_id != principal.user.id and not access.can(role, "programme.manage"):
        raise HTTPException(403, "Only the action's owner or an ISMS manager can complete it")
    _mgmt().complete_action(db, a, principal.actor, principal.user.id, str(body.get("note") or ""))
    db.commit()
    return _mgmt().nonconformity_rows(db, a.tenant_id, "all", a.nonconformity_id)[0]


class Effectiveness(BaseModel):
    model_config = ConfigDict(extra="forbid")
    effective: bool
    note: str = Field(max_length=4000)


@router.post("/nonconformities/{nc_id}/effectiveness")
def nc_effectiveness(nc_id: str, body: Effectiveness, principal: Principal = Depends(current_principal),
                     db: Session = Depends(isms_db)):
    row = _nc(db, principal, nc_id)
    require_isms(db, principal, row.tenant_id, "programme.manage")
    _mgmt().record_effectiveness(db, row, principal.actor, principal.user.id, body.effective, body.note)
    db.commit()
    return _mgmt().nonconformity_rows(db, row.tenant_id, "all", row.id)[0]


class CloseNote(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: str
    note: str = Field(max_length=4000)


@router.post("/nonconformities/{nc_id}/close")
def nc_close(nc_id: str, body: CloseNote, principal: Principal = Depends(current_principal),
             db: Session = Depends(isms_db)):
    row = _nc(db, principal, nc_id)
    require_isms(db, principal, row.tenant_id, "programme.manage")
    _mgmt().close_with_note(db, row, principal.actor, body.outcome, body.note)
    db.commit()
    return _mgmt().nonconformity_rows(db, row.tenant_id, "all", row.id)[0]


@router.get("/objectives")
def list_objectives(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, tenant_id, "controls.view")
    return {"objectives": _mgmt().objective_rows(db, tenant_id)}


@router.post("/objectives")
def add_objective(body: TenantBody, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, body.tenant_id, "programme.manage")
    row = _mgmt().save_objective(db, body.tenant_id, principal.actor, dict(body.model_extra or {}),
                                 _members(db, body.tenant_id))
    db.commit()
    return _mgmt().objective_rows(db, body.tenant_id, row.id)[0]


def _objective(db, principal, obj_id):
    from ..isms.models import IsmsObjective
    return get_scoped(db, IsmsObjective, obj_id, principal)


@router.patch("/objectives/{obj_id}")
def update_objective(obj_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                     db: Session = Depends(isms_db)):
    row = _objective(db, principal, obj_id)
    require_isms(db, principal, row.tenant_id, "programme.manage")
    if "status" in body and set(body) <= {"status", "note"}:
        _mgmt().set_objective_status(db, row, principal.actor, body["status"], str(body.get("note") or ""))
    else:
        _mgmt().save_objective(db, row.tenant_id, principal.actor, body, _members(db, row.tenant_id), row)
    db.commit()
    return _mgmt().objective_rows(db, row.tenant_id, row.id)[0]


@router.post("/objectives/{obj_id}/values")
def record_metric(obj_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                  db: Session = Depends(isms_db)):
    """The objective's owner, or an ISMS manager, records a measurement."""
    row = _objective(db, principal, obj_id)
    role = require_isms(db, principal, row.tenant_id, "controls.view")
    if row.owner_user_id != principal.user.id and not access.can(role, "programme.manage"):
        raise HTTPException(403, "Only the objective's owner or an ISMS manager can record values")
    _mgmt().record_value(db, row, principal.actor, body)
    db.commit()
    return _mgmt().objective_rows(db, row.tenant_id, row.id)[0]


@router.get("/changes")
def list_changes(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, tenant_id, "controls.view")
    return {"changes": _mgmt().change_rows(db, tenant_id)}


@router.post("/changes")
def add_change(body: TenantBody, principal: Principal = Depends(current_principal), db: Session = Depends(isms_db)):
    require_isms(db, principal, body.tenant_id, "programme.manage")
    row = _mgmt().save_change(db, body.tenant_id, principal.actor, dict(body.model_extra or {}),
                              _members(db, body.tenant_id))
    db.commit()
    return next(c for c in _mgmt().change_rows(db, body.tenant_id) if c["id"] == row.id)


@router.patch("/changes/{change_id}")
def update_change(change_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                  db: Session = Depends(isms_db)):
    from ..isms.models import IsmsChange

    row = get_scoped(db, IsmsChange, change_id, principal)
    require_isms(db, principal, row.tenant_id, "programme.manage")
    _mgmt().save_change(db, row.tenant_id, principal.actor, body, _members(db, row.tenant_id), row)
    db.commit()
    return next(c for c in _mgmt().change_rows(db, row.tenant_id) if c["id"] == row.id)
