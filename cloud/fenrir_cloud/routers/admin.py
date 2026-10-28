"""Sign-in, tenants, users, device groups, enrollment tokens, audit log."""

from __future__ import annotations

import json

import secrets

import re
from datetime import timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from sqlalchemy import text, select
from sqlalchemy.orm import Session

from .. import roles, sessions, audit, crypto, deployment_installers, policy_schema, ratelimit
from ..config import get_settings
from ..db import get_db
from ..deps import REAUTH_MINUTES, Principal, current_principal, require_reauth, scoped_tenant, tenant_subtree
from ..models import AuditLog, Device, DeviceGroup, EnrollmentToken, Policy, Tenant, User, utcnow
from ..security import ROLES, digest, hash_password, issue_token, new_secret, new_totp_secret, totp_uri, verify_password, verify_totp, reauth_state
from ..serialize import apply_fields, to_dict

REINSTATE_PREFIX = "fet_rs-"

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
    token, session = sessions.create(db, user, _client_ip(request), request.headers.get("user-agent", ""))
    audit.record(db, user.email, "auth.login", user.id, user.tenant_id, session=session.id[-8:])
    db.commit()
    return {"token": token, "user": to_dict(user)}


@router.post("/auth/logout")
def logout(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    sessions.revoke(db, principal.session_id, "logout")
    audit.record(db, principal.actor, "auth.logout", principal.user.id, principal.user.tenant_id)
    db.commit()
    return {"ok": True}


def _session_view(row, current: str | None) -> dict:
    return {"id": row.id[-12:], "current": row.id == current, "createdAt": row.created_at.isoformat() + "Z",
            "lastSeenAt": row.last_seen_at.isoformat() + "Z", "expiresAt": row.expires_at.isoformat() + "Z",
            "ip": row.ip, "userAgent": row.user_agent}


@router.get("/auth/sessions")
def my_sessions(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return [_session_view(r, principal.session_id) for r in sessions.list_for(db, principal.user.id)]


@router.delete("/auth/sessions/{short_id}")
def end_my_session(short_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    match = next((r for r in sessions.list_for(db, principal.user.id) if r.id.endswith(short_id) and len(short_id) >= 8), None)
    if match is None:
        raise HTTPException(404, "Not found")
    sessions.revoke(db, match.id, "revoked by user")
    audit.record(db, principal.actor, "auth.session_revoked", principal.user.id, principal.user.tenant_id)
    db.commit()
    return {"ok": True}


@router.post("/auth/sessions/revoke-others")
def end_other_sessions(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    count = sessions.revoke_user(db, principal.user.id, "revoked by user", keep=principal.session_id)
    audit.record(db, principal.actor, "auth.sessions_revoked", principal.user.id, principal.user.tenant_id, count=count)
    db.commit()
    return {"revoked": count}


@router.post("/users/{user_id}/sessions/revoke")
def revoke_user_sessions(user_id: str, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Sign a user out everywhere (lost laptop, suspected compromise)."""
    principal.require("configure")
    user = db.get(User, user_id)
    if user is None or user.role == "service":  # API credentials' service users are managed only as credentials
        raise HTTPException(404, "Not found")
    principal.check_tenant(user.tenant_id)
    if user.role == "platform_admin" and not principal.can("platform"):
        raise HTTPException(403, "Only platform admins can sign out a platform admin")
    roles.check_manageable(db, principal, user)
    require_reauth(request, principal)
    count = sessions.revoke_user(db, user.id, f"revoked by {principal.actor}")
    audit.record(db, principal.actor, "auth.sessions_revoked", user.email, user.tenant_id, count=count)
    db.commit()
    return {"revoked": count}


@router.get("/auth/me")
def me(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    tenants = db.execute(select(Tenant).where(Tenant.id.in_(principal.tenant_ids)).order_by(Tenant.name)).scalars().all()
    return {"user": to_dict(principal.user), "permissions": sorted(roles.held(principal)),
            "tenants": [to_dict(t) for t in tenants]}


@router.post("/auth/password")
def change_password(request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    ratelimit.check(f"password:{principal.user.id}", 10, 300)
    if not verify_password(str(body.get("currentPassword") or ""), principal.user.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    new = str(body.get("newPassword") or "")
    if len(new) < 12:
        raise HTTPException(400, "Use at least 12 characters")
    user = db.get(User, principal.user.id)
    user.password_hash = hash_password(new)
    # Every session, this one included, signed in with the old password: end them all and hand this client a new one.
    revoked = sessions.revoke_user(db, user.id, "password changed")
    token, _ = sessions.create(db, user, _client_ip(request), request.headers.get("user-agent", ""))
    audit.record(db, principal.actor, "auth.password_changed", user.id, user.tenant_id, sessionsRevoked=revoked)
    db.commit()
    return {"ok": True, "token": token, "sessionsRevoked": revoked}


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
    revoked = sessions.revoke_user(db, user.id, "MFA enabled", keep=principal.session_id)  # older sign-ins had no second factor
    audit.record(db, principal.actor, "auth.mfa_enabled", user.id, user.tenant_id, sessionsRevoked=revoked)
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
    revoked = sessions.revoke_user(db, user.id, "MFA disabled", keep=principal.session_id)
    audit.record(db, principal.actor, "auth.mfa_disabled", user.id, user.tenant_id, sessionsRevoked=revoked)
    db.commit()
    return {"mfaEnabled": False}


@router.post("/users/{user_id}/mfa/reset")
def mfa_reset(user_id: str, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """For a user who lost their phone: an administrator clears their MFA so they can enrol again."""
    principal.require("manage_tenants")
    user = db.get(User, user_id)
    if user is None or user.role == "service":  # API credentials' service users are managed only as credentials
        raise HTTPException(404, "Not found")
    principal.check_tenant(user.tenant_id)
    if user.role == "platform_admin" and not principal.can("platform"):
        raise HTTPException(403, "Only platform admins can reset platform admin MFA")
    roles.check_manageable(db, principal, user)
    require_reauth(request, principal)
    user.mfa_enabled, user.mfa_secret = False, None
    revoked = sessions.revoke_user(db, user.id, f"MFA reset by {principal.actor}")
    audit.record(db, principal.actor, "auth.mfa_reset", user.id, user.tenant_id, user=user.email, sessionsRevoked=revoked)
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
    rows = db.execute(select(User).where(User.tenant_id.in_(scoped_tenant(principal, tenant_id)), User.role != "service")
                      .order_by(User.email)).scalars().all()  # API credentials' service users are listed with the credentials
    return [to_dict(u) for u in rows]


@router.post("/users")
def create_user(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.get("tenantId") or principal.user.tenant_id
    principal.check_tenant(tenant_id)
    role = str(body.get("role") or "viewer")
    roles.check_assignable(db, principal, role, tenant_id)
    if role in {"msp_admin", "soc_analyst", "technician", "billing"} and not principal.can("manage_tenants"):
        raise HTTPException(403, "Only MSP admins can create MSP roles")
    assigned = _assignments(db, principal, tenant_id, body.get("assignedTenantIds"))
    email = str(body.get("email") or "").strip().lower()
    password = str(body.get("password") or "")
    if "@" not in email or len(password) < 12:
        raise HTTPException(400, "A valid email and a password of 12+ characters are required")
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        raise HTTPException(409, "That email already has an account")
    user = User(tenant_id=tenant_id, email=email, name=str(body.get("name") or ""), role=role, password_hash=hash_password(password),
                assigned_tenant_ids=assigned)
    db.add(user)
    audit.record(db, principal.actor, "user.created", email, tenant_id, role=role)
    db.commit()
    return to_dict(user)


def _assignments(db: Session, principal: Principal, user_tenant_id: str, value) -> list[str] | None:
    """CORE-02: customers a user is limited to - each visible to the caller and inside the user's own tenant."""
    if value in (None, []):
        return None
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value) or len(value) > 500:
        raise HTTPException(422, "assignedTenantIds must be a list of customer ids")
    allowed = tenant_subtree(db, user_tenant_id)
    for tid in value:
        if tid not in principal.tenant_ids or tid not in allowed:
            raise HTTPException(400, f"{tid} is not a customer this user can be assigned to")
    return sorted(set(value))


@router.patch("/users/{user_id}")
def update_user(user_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    user = db.get(User, user_id)
    if user is None or user.role == "service":  # API credentials' service users are managed only as credentials
        raise HTTPException(404, "Not found")
    principal.check_tenant(user.tenant_id)
    roles.check_manageable(db, principal, user)
    if "role" in body and body["role"] != user.role:
        roles.check_assignable(db, principal, str(body["role"]), user.tenant_id)
        if body["role"] in {"msp_admin", "soc_analyst", "technician", "billing"} and not principal.can("manage_tenants"):
            raise HTTPException(403, "Only MSP admins can give MSP roles")
    changed = apply_fields(user, body, {"name", "role", "active"})
    if "assignedTenantIds" in body:
        user.assigned_tenant_ids = _assignments(db, principal, user.tenant_id, body["assignedTenantIds"])
        changed.append("assignedTenantIds")
    if body.get("password"):
        if len(body["password"]) < 12:
            raise HTTPException(400, "Use at least 12 characters")
        user.password_hash = hash_password(body["password"])
        changed.append("password")
    if "password" in changed or ("active" in changed and not user.active) or "role" in changed:
        sessions.revoke_user(db, user.id, "account changed by " + principal.actor)
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
            "macos": "Download the macOS installer from Deploy, then run: sudo sh Install-Fenrir-macOS.sh",
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
    ratelimit.check(f"installer-download:{principal.user.id}", 5, 300)
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
    reinstatement_id = body.get("reinstateDeviceId")
    reinstatement = None
    if reinstatement_id:
        if not isinstance(reinstatement_id, str):
            raise HTTPException(422, "Invalid reinstatement device ID")
        reinstatement = db.scalar(select(Device).where(Device.id == reinstatement_id).with_for_update())
        if reinstatement is None or reinstatement.tenant_id != tenant_id:
            raise HTTPException(404, "Device not found in this customer")
        if reinstatement.api_key_hash != f"retired-{reinstatement.id}":
            raise HTTPException(409, "Only decommissioned devices can be reinstated")
        if os_name != reinstatement.platform:
            raise HTTPException(422, "Installer platform must match the original device")
        group_id = reinstatement.group_id
        days = 1
    label = (f"Reinstate {reinstatement.id}" if reinstatement else
             str(body.get("label") or "Deployment").strip()[:200] or "Deployment")
    # Reinstatement tokens keep the fet_ shape (letters, digits, "_" and "-") that the installers and
    # Windows setup accept, and name the device they reconnect: fet_rs-<device id>-<hex secret>.
    raw = (f"{REINSTATE_PREFIX}{reinstatement.id}-{secrets.token_hex(24)}") if reinstatement else new_secret("fet", 24)
    data, filename, media_type = deployment_installers.build(
        os_name, get_settings().public_base_url, raw
    )  # Build/release validation BEFORE issuing a token.
    row = EnrollmentToken(tenant_id=tenant_id, group_id=group_id, label=label,
                          token_hash=digest(raw), token_hint=raw[-6:],
                          max_uses=1 if reinstatement else None,
                          expires_at=utcnow() + timedelta(days=days))
    if reinstatement:
        for old in db.scalars(select(EnrollmentToken).where(EnrollmentToken.tenant_id == tenant_id,
                               EnrollmentToken.label == label, EnrollmentToken.revoked.is_(False))):
            old.revoked = True
        audit.record(db, principal.actor, "device.reinstatement_requested", reinstatement.id, tenant_id)
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


@router.get("/platform/readiness")
def platform_readiness(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """CORE-14: production safety warnings for platform administrators (errors stop the server from starting)."""
    principal.require("platform")
    from .. import production
    from ..config import get_settings
    from ..db import LATEST_MIGRATION

    settings = get_settings()
    users = db.execute(select(User.id)).all()
    _, warnings = production.check(settings, len(users))
    schema = db.execute(text("SELECT MAX(version) FROM schema_migrations")).scalar()
    return {"environment": settings.environment, "warnings": warnings, "schemaVersion": schema, "expectedSchemaVersion": LATEST_MIGRATION}


@router.get("/audit/verify")
def audit_verify(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("manage_tenants")
    return audit.verify_chain(db)


@router.get("/audit/checkpoints")
def audit_checkpoints(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("manage_tenants")
    from ..models import AuditCheckpoint

    rows = db.execute(select(AuditCheckpoint).order_by(AuditCheckpoint.created_at.desc()).limit(200)).scalars().all()
    return [to_dict(r) for r in rows]


@router.post("/audit/checkpoints")
def audit_checkpoint(body: dict = Body(default={}), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Record the chain head now (also published to webhooks, so a copy is kept outside this database)."""
    principal.require("manage_tenants")
    cp = audit.checkpoint(db, principal.actor, str(body.get("reason") or "manual")[:300])
    db.commit()
    return to_dict(cp)


@router.get("/audit/export")
def audit_export(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """JSON Lines: a header, then every row from the retention anchor on. Outside the platform administrator's view,
    other customers' rows keep only their chain fields. Check it offline with scripts/verify_audit_export.py."""
    principal.require("configure")
    from fastapi.responses import Response

    from ..models import AuditCheckpoint

    full = principal.can("platform")
    rows = audit.export_rows(db, None if full else set(principal.tenant_ids))
    anchor = audit._anchor(db)
    checkpoints = db.execute(select(AuditCheckpoint).where(AuditCheckpoint.kind == "checkpoint").order_by(AuditCheckpoint.seq)).scalars().all()
    header = {"format": "fenrir-audit-export/1", "exportedAt": utcnow().isoformat() + "Z", "exportedBy": principal.actor,
              "scope": "all" if full else sorted(principal.tenant_ids),
              "anchor": {"seq": anchor.seq, "hash": anchor.hash} if anchor else None,
              "checkpoints": [{"seq": c.seq, "hash": c.hash, "at": c.created_at.isoformat() + "Z"} for c in checkpoints]}
    audit.record(db, principal.actor, "audit.exported", f"{len(rows)} rows", principal.user.tenant_id, scope=header["scope"] if not full else "all")
    db.commit()
    body = "\n".join(json.dumps(line, sort_keys=True, default=str) for line in [header, *rows]) + "\n"
    return Response(body, media_type="application/x-ndjson",
                    headers={"Content-Disposition": f'attachment; filename="fenrir-audit-{utcnow():%Y%m%d%H%M}.jsonl"'})


@router.get("/audit/policy")
def audit_policy(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("manage_tenants")
    from ..models import AuditPolicy

    policy = db.get(AuditPolicy, 1)
    return {"retentionDays": policy.retention_days if policy else None, "legalHold": bool(policy and policy.legal_hold),
            "holdReason": policy.hold_reason if policy else "", "updatedBy": policy.updated_by if policy else "",
            "updatedAt": policy.updated_at.isoformat() + "Z" if policy else None}


@router.put("/audit/policy")
def set_audit_policy(request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Retention (days, or null to keep everything; at least 365) and legal hold. Platform administrators, with a
    fresh password check."""
    principal.require("platform")
    require_reauth(request, principal)
    from ..models import AuditPolicy

    days = body.get("retentionDays")
    if days is not None and (not isinstance(days, int) or days < 365 or days > 3650):
        raise HTTPException(400, "retentionDays must be between 365 and 3650, or null to keep everything")
    hold = bool(body.get("legalHold"))
    reason = str(body.get("holdReason") or "").strip()[:500]
    if hold and not reason:
        raise HTTPException(400, "Say why the audit trail is on legal hold")
    policy = db.get(AuditPolicy, 1) or AuditPolicy(id=1)
    db.add(policy)
    policy.retention_days, policy.legal_hold, policy.hold_reason = days, hold, reason
    policy.updated_by, policy.updated_at = principal.actor, utcnow()
    audit.record(db, principal.actor, "audit.policy_changed", "audit", None, retentionDays=days, legalHold=hold, reason=reason)
    db.commit()
    return audit_policy(principal, db)


@router.post("/audit/retention/apply")
def apply_audit_retention(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("platform")
    pruned = audit.apply_retention(db, principal.actor)
    db.commit()
    return {"pruned": pruned}
