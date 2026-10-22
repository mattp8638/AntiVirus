"""Sign-in, tenants, users, device groups, enrollment tokens, audit log."""

from __future__ import annotations

import re
from datetime import timedelta

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, policy_schema
from ..config import get_settings
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import AuditLog, DeviceGroup, EnrollmentToken, Policy, Tenant, User, utcnow
from ..security import ROLES, digest, hash_password, issue_token, new_secret, verify_password
from ..serialize import apply_fields, to_dict

router = APIRouter(prefix="/api/console", tags=["Administration"])


@router.post("/auth/login")
def login(body: dict = Body(...), db: Session = Depends(get_db)):
    email = str(body.get("email") or "").strip().lower()
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is None or not user.active or not verify_password(str(body.get("password") or ""), user.password_hash):
        raise HTTPException(401, "Email or password is incorrect")
    user.last_login_at = utcnow()
    audit.record(db, user.email, "auth.login", user.id, user.tenant_id)
    db.commit()
    settings = get_settings()
    token = issue_token(settings.secret_key, user.id, settings.token_ttl_minutes, role=user.role)
    return {"token": token, "user": to_dict(user)}


@router.get("/auth/me")
def me(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    from ..security import ROLE_PERMISSIONS

    tenants = db.execute(select(Tenant).where(Tenant.id.in_(principal.tenant_ids)).order_by(Tenant.name)).scalars().all()
    return {"user": to_dict(principal.user), "permissions": sorted(ROLE_PERMISSIONS.get(principal.user.role, set())),
            "tenants": [to_dict(t) for t in tenants]}


@router.post("/auth/password")
def change_password(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    if not verify_password(str(body.get("currentPassword") or ""), principal.user.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    new = str(body.get("newPassword") or "")
    if len(new) < 12:
        raise HTTPException(400, "Use at least 12 characters")
    user = db.get(User, principal.user.id)
    user.password_hash = hash_password(new)
    audit.record(db, principal.actor, "auth.password_changed", user.id, user.tenant_id)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- tenants


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:70] or "tenant"


@router.get("/tenants")
def list_tenants(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(Tenant).where(Tenant.id.in_(principal.tenant_ids)).order_by(Tenant.name)).scalars().all()
    return [to_dict(t) for t in rows]


@router.post("/tenants")
def create_tenant(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("manage_tenants")
    name = str(body.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "name is required")
    parent_id = body.get("parentId") or principal.user.tenant_id
    principal.check_tenant(parent_id)
    slug = _slugify(body.get("slug") or name)
    if db.execute(select(Tenant).where(Tenant.slug == slug)).scalar_one_or_none():
        slug = f"{slug}-{new_secret('x', 3)[2:].lower()}"
    template = str(body.get("template") or "balanced")
    if template not in policy_schema.TEMPLATES:
        raise HTTPException(400, "unknown template")
    tenant = Tenant(name=name, slug=slug, parent_id=parent_id, kind="customer", plan=str(body.get("plan") or "complete"))
    db.add(tenant)
    db.flush()
    policy = Policy(tenant_id=tenant.id, name=f"{name} default", template=template,
                    settings=policy_schema.template_settings(template), updated_by=principal.actor)
    db.add(policy)
    db.flush()
    tenant.default_policy_id = policy.id
    audit.record(db, principal.actor, "tenant.created", tenant.id, tenant.id, template=template)
    db.commit()
    return to_dict(tenant)


@router.patch("/tenants/{tenant_id}")
def update_tenant(tenant_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    principal.require("manage_tenants")
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    changed = apply_fields(tenant, body, {"name", "plan", "settings", "default_policy_id"})
    audit.record(db, principal.actor, "tenant.updated", tenant.id, tenant.id, fields=changed)
    db.commit()
    return to_dict(tenant)


# --------------------------------------------------------------------------- users


@router.get("/users")
def list_users(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(User).where(User.tenant_id.in_(scoped_tenant(principal, tenant_id))).order_by(User.email)).scalars().all()
    return [to_dict(u) for u in rows]


@router.post("/users")
def create_user(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.get("tenantId") or principal.user.tenant_id
    principal.check_tenant(tenant_id)
    role = str(body.get("role") or "viewer")
    if role not in ROLES:
        raise HTTPException(400, f"role must be one of {', '.join(ROLES)}")
    if role in {"platform_admin"} and not principal.can("platform"):
        raise HTTPException(403, "Only platform admins can create platform admins")
    if role in {"msp_admin", "soc_analyst", "technician", "billing"} and not principal.can("manage_tenants"):
        raise HTTPException(403, "Only MSP admins can create MSP roles")
    email = str(body.get("email") or "").strip().lower()
    password = str(body.get("password") or "")
    if "@" not in email or len(password) < 12:
        raise HTTPException(400, "A valid email and a password of 12+ characters are required")
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        raise HTTPException(409, "That email already has an account")
    user = User(tenant_id=tenant_id, email=email, name=str(body.get("name") or ""), role=role, password_hash=hash_password(password))
    db.add(user)
    audit.record(db, principal.actor, "user.created", email, tenant_id, role=role)
    db.commit()
    return to_dict(user)


@router.patch("/users/{user_id}")
def update_user(user_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(user.tenant_id)
    if "role" in body and (body["role"] not in ROLES or (body["role"] == "platform_admin" and not principal.can("platform"))):
        raise HTTPException(400, "invalid role")
    changed = apply_fields(user, body, {"name", "role", "active"})
    if body.get("password"):
        if len(body["password"]) < 12:
            raise HTTPException(400, "Use at least 12 characters")
        user.password_hash = hash_password(body["password"])
        changed.append("password")
    audit.record(db, principal.actor, "user.updated", user.email, user.tenant_id, fields=changed)
    db.commit()
    return to_dict(user)


# --------------------------------------------------------------------------- groups


@router.get("/groups")
def list_groups(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(DeviceGroup).where(DeviceGroup.tenant_id.in_(scoped_tenant(principal, tenant_id)))
                      .order_by(DeviceGroup.name)).scalars().all()
    return [to_dict(g) for g in rows]


@router.post("/groups")
def create_group(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.get("tenantId")
    principal.check_tenant(tenant_id)
    group = DeviceGroup(tenant_id=tenant_id, name=str(body.get("name") or "New group"), parent_id=body.get("parentId"),
                        policy_id=body.get("policyId"), match_rules=body.get("matchRules") or {})
    db.add(group)
    audit.record(db, principal.actor, "group.created", group.name, tenant_id)
    db.commit()
    return to_dict(group)


@router.patch("/groups/{group_id}")
def update_group(group_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    group = db.get(DeviceGroup, group_id)
    if group is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(group.tenant_id)
    changed = apply_fields(group, body, {"name", "parent_id", "policy_id", "match_rules"})
    audit.record(db, principal.actor, "group.updated", group.name, group.tenant_id, fields=changed)
    db.commit()
    return to_dict(group)


# --------------------------------------------------------------------------- enrollment


@router.get("/enrollment-tokens")
def list_tokens(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(EnrollmentToken).where(EnrollmentToken.tenant_id.in_(scoped_tenant(principal, tenant_id)))
                      .order_by(EnrollmentToken.created_at.desc())).scalars().all()
    return [to_dict(t) for t in rows]


@router.post("/enrollment-tokens")
def create_token(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.get("tenantId")
    principal.check_tenant(tenant_id)
    raw = new_secret("fet", 24)
    days = body.get("expiresInDays")
    token = EnrollmentToken(tenant_id=tenant_id, group_id=body.get("groupId"), label=str(body.get("label") or "Deployment"),
                            token_hash=digest(raw), token_hint=raw[-6:], max_uses=body.get("maxUses"),
                            expires_at=utcnow() + timedelta(days=int(days)) if days else None)
    db.add(token)
    audit.record(db, principal.actor, "enrollment_token.created", token.label, tenant_id)
    db.commit()
    base = get_settings().public_base_url.rstrip("/")
    return {
        **to_dict(token), "token": raw,
        "install": {
            "windows": f'FenrirSetup.exe /quiet SERVER="{base}" TOKEN="{raw}"',
            "linux": f"curl -fsSL {base}/install/linux.sh | sudo FENRIR_SERVER={base} FENRIR_TOKEN={raw} sh",
            "macos": f"sudo installer -pkg FenrirAgent.pkg -target / && sudo /Library/Fenrir/fenrirctl enroll --server {base} --token {raw}",
        },
    }


@router.delete("/enrollment-tokens/{token_id}")
def revoke_token(token_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    token = db.get(EnrollmentToken, token_id)
    if token is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(token.tenant_id)
    token.revoked = True
    audit.record(db, principal.actor, "enrollment_token.revoked", token.label, token.tenant_id)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- audit


@router.get("/audit")
def audit_log(tenant_id: str | None = None, limit: int = 200, principal: Principal = Depends(current_principal),
              db: Session = Depends(get_db)):
    scope = scoped_tenant(principal, tenant_id)
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(min(limit, 1000))
    if not principal.can("platform"):
        query = query.where(AuditLog.tenant_id.in_(scope))
    return [to_dict(row) for row in db.execute(query).scalars()]


@router.get("/audit/verify")
def audit_verify(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("manage_tenants")
    return audit.verify_chain(db)
