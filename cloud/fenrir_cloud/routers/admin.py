"""Sign-in, tenants, users, device groups, enrollment tokens, audit log."""

from __future__ import annotations

import re
from datetime import timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crypto, deployment_installers, policy_schema, ratelimit
from ..config import get_settings
from ..db import get_db
from ..deps import REAUTH_MINUTES, Principal, current_principal, require_reauth, scoped_tenant
from ..models import AuditLog, DeviceGroup, EnrollmentToken, Policy, Tenant, User, utcnow
from ..security import ROLES, digest, hash_password, issue_token, new_secret, new_totp_secret, totp_uri, verify_password, verify_totp, reauth_state
from ..serialize import apply_fields, to_dict

router = APIRouter(prefix="/api/console", tags=["Administration"])
crypto.register_encrypted(User, "mfa_secret", lambda user: f"mfa:{user.id}")


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _mfa_secret(user: User) -> str | None:
    if not user.mfa_secret:
        return None
    return crypto.decrypt(user.mfa_secret, f"mfa:{user.id}")


def _check_mfa(user: User, code) -> None:
    if not user.mfa_enabled:
        return
    if not code:
        # 428: the console shows the code field and submits again.
        raise HTTPException(428, "MFA code required")
    secret = _mfa_secret(user)
    if not secret or not verify_totp(secret, str(code)):
        raise HTTPException(401, "The MFA code is incorrect")


@router.post("/auth/login")
def login(request: Request, body: dict = Body(...), db: Session = Depends(get_db)):
    email = str(body.get("email") or "").strip().lower()
    ratelimit.check(f"login:{_client_ip(request)}", 30, 300)
    ratelimit.check(f"login:{email}", 10, 300)
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is None or not user.active or not verify_password(str(body.get("password") or ""), user.password_hash):
        if user is not None:
            audit.record(db, email, "auth.login_failed", user.id, user.tenant_id, ip=_client_ip(request))
            db.commit()
        raise HTTPException(401, "Email or password is incorrect")
    _check_mfa(user, body.get("code"))
    user.last_login_at = utcnow()
    audit.record(db, user.email, "auth.login", user.id, user.tenant_id)
    db.commit()
    settings = get_settings()
    token = issue_token(settings.secret_key, user.id, settings.token_ttl_minutes, role=user.role, jti=new_secret("session"))
    return {"token": token, "user": to_dict(user)}


@router.get("/auth/me")
def me(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    from ..security import ROLE_PERMISSIONS

    tenants = db.execute(select(Tenant).where(Tenant.id.in_(principal.tenant_ids)).order_by(Tenant.name)).scalars().all()
    return {"user": to_dict(principal.user), "permissions": sorted(ROLE_PERMISSIONS.get(principal.user.role, set())),
            "tenants": [to_dict(t) for t in tenants]}


@router.post("/auth/password")
def change_password(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    ratelimit.check(f"password:{principal.user.id}", 10, 300)
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


@router.post("/auth/reauth")
def reauthenticate(request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Confirm the password (and MFA code) again before a sensitive action; returns a 5-minute token."""
    ratelimit.check(f"reauth:{principal.user.id}", 10, 300)
    user = db.get(User, principal.user.id)
    if not verify_password(str(body.get("password") or ""), user.password_hash):
        audit.record(db, principal.actor, "auth.reauth_failed", user.id, user.tenant_id, ip=_client_ip(request))
        db.commit()
        raise HTTPException(401, "Password is incorrect")
    _check_mfa(user, body.get("code"))
    audit.record(db, principal.actor, "auth.reauth", user.id, user.tenant_id)
    db.commit()
    token = issue_token(get_settings().secret_key, user.id, REAUTH_MINUTES, aud="reauth",
                        session=digest(request.headers.get("Authorization", "")),
                        state=reauth_state(get_settings().secret_key, user))
    return {"reauthToken": token, "expiresInSeconds": REAUTH_MINUTES * 60, "mfaEnabled": bool(user.mfa_enabled)}


@router.post("/auth/mfa/setup")
def mfa_setup(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Start enrolling an authenticator app. MFA is only switched on once a code is confirmed."""
    user = db.get(User, principal.user.id)
    if user.mfa_enabled:
        raise HTTPException(409, "MFA is already on. Turn it off first to enrol a new device.")
    secret = new_totp_secret()
    user.mfa_secret = crypto.encrypt(secret, f"mfa:{user.id}")
    db.commit()
    return {"secret": secret, "otpauthUri": totp_uri(secret, user.email)}


@router.post("/auth/mfa/enable")
def mfa_enable(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    ratelimit.check(f"mfa-enable:{principal.user.id}", 10, 300)
    user = db.get(User, principal.user.id)
    secret = _mfa_secret(user)
    if not secret:
        raise HTTPException(400, "Start MFA setup first")
    if not verify_totp(secret, str(body.get("code") or "")):
        raise HTTPException(400, "That code is not correct. Check the time on your phone and try again.")
    user.mfa_enabled = True
    audit.record(db, principal.actor, "auth.mfa_enabled", user.id, user.tenant_id)
    db.commit()
    return {"mfaEnabled": True}


@router.post("/auth/mfa/disable")
def mfa_disable(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    ratelimit.check(f"mfa-disable:{principal.user.id}", 10, 300)
    user = db.get(User, principal.user.id)
    if not verify_password(str(body.get("password") or ""), user.password_hash):
        raise HTTPException(401, "Password is incorrect")
    _check_mfa(user, body.get("code"))
    user.mfa_enabled, user.mfa_secret = False, None
    audit.record(db, principal.actor, "auth.mfa_disabled", user.id, user.tenant_id)
    db.commit()
    return {"mfaEnabled": False}


@router.post("/users/{user_id}/mfa/reset")
def mfa_reset(user_id: str, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """For a user who lost their phone: an administrator clears their MFA so they can enrol again."""
    principal.require("manage_tenants")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(user.tenant_id)
    require_reauth(request, principal)
    if user.role == "platform_admin" and not principal.can("platform"):
        raise HTTPException(403, "Only platform admins can reset platform admin MFA")
    user.mfa_enabled, user.mfa_secret = False, None
    audit.record(db, principal.actor, "auth.mfa_reset", user.id, user.tenant_id, user=user.email)
    db.commit()
    return {"mfaEnabled": False}


@router.get("/platform/status")
def platform_status(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Operational view for administrators: vault key mode, event queue health."""
    principal.require("configure")
    from sqlalchemy import func

    from .. import events
    from ..models import PlatformEvent

    counts = dict(db.execute(select(PlatformEvent.status, func.count()).group_by(PlatformEvent.status)).all())
    return {"vault": crypto.key_status(), "events": {"pending": counts.get("pending", 0), "done": counts.get("done", 0),
                                                     "dead": counts.get("dead", 0)},
            "handlers": events.registered()}


@router.post("/platform/vault/rotate")
def rotate_vault_key(request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Re-encrypt all stored secrets under the current FENRIR_VAULT_KEY (after changing it)."""
    principal.require("platform")
    from ..deps import require_reauth

    require_reauth(request, principal)
    result = crypto.rotate(db)
    audit.record(db, principal.actor, "platform.vault_rotated", result["keyId"], None, **result)
    db.commit()
    return result


@router.get("/platform/events")
def list_platform_events(status: str | None = None, limit: int = 100, principal: Principal = Depends(current_principal),
                         db: Session = Depends(get_db)):
    principal.require("configure")
    from ..models import PlatformEvent

    query = select(PlatformEvent).order_by(PlatformEvent.id.desc()).limit(min(limit, 500))
    if status:
        query = query.where(PlatformEvent.status == status)
    rows = db.execute(query).scalars().all()
    return [to_dict(row) for row in rows if row.tenant_id is None and principal.can("platform") or row.tenant_id in principal.tenant_ids]


@router.post("/platform/events/{event_id}/retry")
def retry_platform_event(event_id: int, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    from .. import events
    from ..models import PlatformEvent

    event = db.get(PlatformEvent, event_id)
    if event is None or (event.tenant_id is not None and event.tenant_id not in principal.tenant_ids):
        raise HTTPException(404, "Not found")
    events.retry(db, event)
    audit.record(db, principal.actor, "platform.event_retried", str(event.id), event.tenant_id, type=event.type)
    db.commit()
    return to_dict(event)


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
            "windows": f'fenrir-agent-service.exe --install --server "{base}" --enroll-token "{raw}"',
            "linux": f"curl -fsSL {base}/install/linux.sh | sudo FENRIR_SERVER={base} FENRIR_TOKEN={raw} sh",
            "macos": f"sudo installer -pkg FenrirAgent.pkg -target / && sudo /Library/Fenrir/fenrirctl enroll --server {base} --token {raw}",
        },
    }



@router.get("/enrollment-installers/status")
def installer_status(principal: Principal = Depends(current_principal)):
    principal.require("configure")
    return deployment_installers.available()


@router.post("/enrollment-installers")
def download_installer(body: dict = Body(...), principal: Principal = Depends(current_principal),
                       db: Session = Depends(get_db)):
    """Create a token and return its OS-specific installer in one authenticated request.

    The raw token is embedded in the response, never saved in cleartext, never
    exposed in a query parameter and never served from public static files.
    """
    principal.require("configure")
    os_name = body.get("os")
    if os_name not in ("windows", "linux", "macos"):
        raise HTTPException(422, "Select Windows, Linux or macOS.")
    tenant_id = str(body.get("tenantId") or "")
    if not tenant_id:
        raise HTTPException(422, "Select a customer tenant before generating an installer.")
    principal.check_tenant(tenant_id)
    if db.get(Tenant, tenant_id) is None:
        raise HTTPException(404, "Selected customer tenant does not exist.")
    group_id = str(body.get("groupId") or "") or None
    if group_id:
        group = db.get(DeviceGroup, group_id)
        if group is None or group.tenant_id != tenant_id:
            raise HTTPException(422, "Selected device group does not belong to the customer tenant.")
    try:
        days = int(body.get("expiresInDays", 30))
    except (TypeError, ValueError):
        raise HTTPException(422, "Expiry must be a whole number of days.") from None
    if not 1 <= days <= 365:
        raise HTTPException(422, "Expiry must be between 1 and 365 days.")
    label = str(body.get("label") or "Deployment").strip()[:200] or "Deployment"
    raw = new_secret("fet", 24)
    data, filename, media_type = deployment_installers.build(
        os_name, get_settings().public_base_url, raw
    )  # Build/release validation BEFORE issuing a token.
    row = EnrollmentToken(tenant_id=tenant_id, group_id=group_id, label=label,
                          token_hash=digest(raw), token_hint=raw[-6:],
                          expires_at=utcnow() + timedelta(days=days))
    db.add(row)
    audit.record(db, principal.actor, "enrollment_installer.generated", os_name, tenant_id,
                 group=group_id or "", label=label)
    db.commit()
    return Response(
        content=data, media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                 "Cache-Control": "private, no-store, max-age=0",
                 "X-Content-Type-Options": "nosniff"},
    )


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
