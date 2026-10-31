"""Sign-in, tenants, users, device groups, enrollment tokens, audit log."""

from __future__ import annotations

import json

import secrets

import re
from datetime import timedelta
from urllib.parse import quote

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, func, or_, select, text
from sqlalchemy.orm import Session

from .. import roles, sessions, sso, audit, crypto, deployment_installers, passkeys, platform_security, ratelimit
from ..config import get_settings
from ..db import get_db
from ..deps import REAUTH_MINUTES, Principal, current_principal, require_reauth, scoped_tenant, tenant_subtree
from ..models import AuditLog, Device, DeviceGroup, EnrollmentToken, PasskeyCredential, Tenant, User, UserSession, utcnow
from ..security import ROLES, digest, hash_password, issue_token, new_secret, new_totp_secret, read_token, totp_uri, verify_password, verify_totp, reauth_state
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


def _staff_sign_in_checks(db: Session, user: User, request: Request) -> None:
    """Platform security for a password or passkey sign-in: required Microsoft sign-in and console networks."""
    if user.role == "client":
        return
    security = platform_security.get(db)
    sso_config = security.get("sso") or {}
    if sso_config.get("enabled") and sso_config.get("required") and user.role != "platform_admin":
        raise HTTPException(403, "Your organisation signs in with Microsoft: use \"Sign in with Microsoft\"")
    if not get_settings().ignore_console_allowlist and not platform_security.ip_allowed(
            security.get("consoleAllowedNetworks") or [], _client_ip(request)):
        audit.record(db, user.email, "auth.login_blocked_network", user.id, user.tenant_id, ip=_client_ip(request))
        db.commit()
        raise HTTPException(403, f"Console access is not allowed from this network ({_client_ip(request)})")


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
    _staff_sign_in_checks(db, user, request)
    _check_mfa(user, body.get("code"))
    user.last_login_at = utcnow()
    token, session = sessions.create(db, user, _client_ip(request), request.headers.get("user-agent", ""))
    audit.record(db, user.email, "auth.login", user.id, user.tenant_id, session=session.id[-8:])
    db.commit()
    return {"token": token, "user": to_dict(user), "mfaSetupRequired": platform_security.mfa_required(db, user)}


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
            "tenants": [to_dict(t) for t in tenants],
            "mfaSetupRequired": principal.credential_id is None and platform_security.mfa_required(
                db, principal.user, getattr(db.get(UserSession, principal.session_id or ""), "method", None)),
            "emergencyStop": platform_security.stopped(db),
            "passkeys": len(passkeys.list_for(db, principal.user.id))}


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
    if isinstance(body.get("passkey"), dict):  # a passkey is the password and the second factor in one
        try:
            owner, _ = passkeys.verify_assertion(db, body["passkey"].get("token"), body["passkey"].get("credential"))
        except passkeys.PasskeyError as exc:
            raise HTTPException(401, str(exc)) from None
        if owner.id != user.id:
            raise HTTPException(401, "That passkey belongs to a different account")
    else:
        if not verify_password(str(body.get("password") or ""), user.password_hash):
            audit.record(db, principal.actor, "auth.reauth_failed", user.id, user.tenant_id, ip=_client_ip(request))
            db.commit()
            raise HTTPException(401, "Password is incorrect")
        _check_mfa(user, body.get("code"))
    audit.record(db, principal.actor, "auth.reauth", user.id, user.tenant_id,
                 method="passkey" if isinstance(body.get("passkey"), dict) else "password")
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
    if user.role != "client" and platform_security.get(db).get("requireMfa"):
        raise HTTPException(409, "Your organisation requires MFA. To move it to a new phone, ask an administrator to reset it.")
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
    """For a user who lost their phone: an administrator clears their MFA and passkeys so they can enrol again."""
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
    removed = db.execute(delete(PasskeyCredential).where(PasskeyCredential.user_id == user.id)).rowcount
    revoked = sessions.revoke_user(db, user.id, f"MFA reset by {principal.actor}")
    audit.record(db, principal.actor, "auth.mfa_reset", user.id, user.tenant_id, user=user.email, sessionsRevoked=revoked,
                 passkeysRemoved=removed)
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
    jobs = []
    if principal.can("platform"):  # job errors can name any customer, so only platform administrators see them
        from ..models import BackgroundJob

        jobs = [{"name": j.name, "ok": j.ok, "failures": j.failures, "error": j.error, "durationMs": j.duration_ms,
                 "runningSince": j.running_since.isoformat() + "Z" if j.running_since else None,
                 "lastRunAt": j.last_run_at.isoformat() + "Z" if j.last_run_at else None,
                 "lastOkAt": j.last_ok_at.isoformat() + "Z" if j.last_ok_at else None}
                for j in db.execute(select(BackgroundJob).order_by(BackgroundJob.name)).scalars()]
    from ..health import background_health

    return {"vault": crypto.key_status(), "events": {"pending": counts.get("pending", 0), "done": counts.get("done", 0),
                                                     "dead": counts.get("dead", 0)},
            "handlers": events.registered(), "jobs": jobs, "background": background_health(db, get_settings())}


@router.get("/platform/telemetry-volume")
def telemetry_volume(tenant_id: str | None = None, device_id: str | None = None, minutes: int = 60,
                     principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """How much telemetry agents are sending, and which devices and event types send most. A noisy agent or event
    type is the usual reason a Fenrir database grows faster than expected."""
    principal.require("configure")
    from sqlalchemy import func

    from ..models import Event

    minutes = max(1, min(int(minutes), 24 * 60))
    since = utcnow() - timedelta(minutes=minutes)
    scope = [Event.tenant_id.in_(scoped_tenant(principal, tenant_id)), Event.occurred_at >= since]
    if device_id:
        scope.append(Event.device_id == device_id)
    total = db.execute(select(func.count()).select_from(Event).where(*scope)).scalar() or 0
    by_type = db.execute(select(Event.event_type, func.count()).where(*scope).group_by(Event.event_type)
                         .order_by(func.count().desc()).limit(15)).all()
    by_device = db.execute(select(Event.device_id, func.count()).where(*scope).group_by(Event.device_id)
                           .order_by(func.count().desc()).limit(10)).all()
    names = dict(db.execute(select(Device.id, Device.hostname).where(Device.id.in_([d for d, _ in by_device if d]))).all())
    from .. import detection

    return {
        "minutes": minutes, "events": total, "perMinute": round(total / minutes, 1),
        "perDayProjected": int(total / minutes * 1440),
        "byType": [{"eventType": t, "events": n} for t, n in by_type],
        "byDevice": [{"deviceId": d, "hostname": names.get(d, ""), "events": n, "perMinute": round(n / minutes, 1)}
                     for d, n in by_device],
        "notStored": detection.storage_skipped(device_id),
    }


@router.get("/platform/security")
def get_platform_security(request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("platform")
    from ..apikeys import SERVICE_ROLE

    security = platform_security.get(db)
    staff = db.execute(select(User).where(User.role.notin_(("client", SERVICE_ROLE)), User.active.is_(True))).scalars().all()
    with_passkeys = _passkey_counts(db, [u.id for u in staff])
    return {**{k: v for k, v in security.items() if k != "sso"}, "sso": sso.public_view(db),
            "staffWithoutMfa": sorted(u.email for u in staff if not u.mfa_enabled and u.id not in with_passkeys),
            "yourAddress": _client_ip(request), "allowListIgnored": get_settings().ignore_console_allowlist}


@router.put("/platform/security")
def set_platform_security(request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal),
                          db: Session = Depends(get_db)):
    """Require MFA for staff, script review, and the networks staff may use the console from. Needs a fresh password check."""
    principal.require("platform")
    require_reauth(request, principal)
    updates: dict = {}
    if "requireMfa" in body:
        updates["requireMfa"] = bool(body["requireMfa"])
    if "scriptReview" in body:
        updates["scriptReview"] = bool(body["scriptReview"])
    if "consoleAllowedNetworks" in body:
        try:
            networks = platform_security.validate_networks(body["consoleAllowedNetworks"])
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        if networks and not platform_security.ip_allowed(networks, _client_ip(request)):
            raise HTTPException(400, f"Your own address ({_client_ip(request)}) is not in that list: you would lock yourself out")
        updates["consoleAllowedNetworks"] = networks
    saved = platform_security.save(db, updates)
    audit.record(db, principal.actor, "platform.security_updated", "platform", principal.user.tenant_id,
                 requireMfa=saved["requireMfa"], consoleAllowedNetworks=saved["consoleAllowedNetworks"],
                 scriptReview=bool(saved.get("scriptReview")))
    db.commit()
    return get_platform_security(request, principal, db)


# --------------------------------------------------------------------------- passkeys (passkeys.py)


def _passkey_error(exc: Exception, status_code: int = 400) -> HTTPException:
    return HTTPException(status_code, str(exc))


@router.get("/auth/passkeys")
def my_passkeys(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return [passkeys.view(row) for row in passkeys.list_for(db, principal.user.id)]


@router.post("/auth/passkeys/options")
def passkey_registration_options(request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Adding a sign-in method is an identity change: it needs a fresh password (or passkey) check."""
    require_reauth(request, principal)
    try:
        return passkeys.registration_options(db, db.get(User, principal.user.id))
    except passkeys.PasskeyError as exc:
        raise _passkey_error(exc) from None


@router.post("/auth/passkeys")
def add_passkey(request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    require_reauth(request, principal)
    ratelimit.check(f"passkey-add:{principal.user.id}", 10, 300)
    user = db.get(User, principal.user.id)
    try:
        row = passkeys.register(db, user, body.get("token"), body.get("credential"), str(body.get("name") or ""))
    except passkeys.PasskeyError as exc:
        raise _passkey_error(exc) from None
    audit.record(db, principal.actor, "auth.passkey_added", user.id, user.tenant_id, name=row.name)
    db.commit()
    return passkeys.view(row)


@router.delete("/auth/passkeys/{passkey_id}")
def remove_passkey(passkey_id: str, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Usually because a phone or key was lost, so every other session ends too."""
    require_reauth(request, principal)
    row = db.get(PasskeyCredential, passkey_id)
    if row is None or row.user_id != principal.user.id:
        raise HTTPException(404, "Not found")
    db.delete(row)
    revoked = sessions.revoke_user(db, principal.user.id, "passkey removed", keep=principal.session_id)
    audit.record(db, principal.actor, "auth.passkey_removed", principal.user.id, principal.user.tenant_id,
                 name=row.name, sessionsRevoked=revoked)
    db.commit()
    return {"ok": True, "sessionsRevoked": revoked}


@router.post("/auth/passkey/options")
def passkey_options(request: Request):
    """A challenge for signing in, or confirming who you are, with a passkey."""
    ratelimit.check(f"passkey-options:{_client_ip(request)}", 60, 300)
    return passkeys.assertion_options()


@router.post("/auth/passkey/login")
def passkey_login(request: Request, body: dict = Body(...), db: Session = Depends(get_db)):
    ratelimit.check(f"login:{_client_ip(request)}", 30, 300)
    try:
        user, row = passkeys.verify_assertion(db, body.get("token"), body.get("credential"))
    except passkeys.PasskeyError as exc:
        audit.record(db, "passkey", "auth.login_failed", "", None, ip=_client_ip(request), reason=str(exc)[:200])
        db.commit()
        raise _passkey_error(exc, 401) from None
    _staff_sign_in_checks(db, user, request)
    user.last_login_at = utcnow()
    token, session = sessions.create(db, user, _client_ip(request), request.headers.get("user-agent", ""), method="passkey")
    audit.record(db, user.email, "auth.login", user.id, user.tenant_id, session=session.id[-8:], method="passkey",
                 passkey=row.name)
    db.commit()
    return {"token": token, "user": to_dict(user), "mfaSetupRequired": False}


# --------------------------------------------------------------------------- Microsoft Entra sign-in (sso.py)


@router.get("/auth/sso/info")
def sso_info(db: Session = Depends(get_db)):
    """For the sign-in page: whether to offer "Sign in with Microsoft", and whether passwords still work."""
    config = sso.settings(db)
    return {"enabled": bool(config["enabled"]), "required": bool(config["enabled"] and config["required"])}


@router.get("/auth/sso/start")
def sso_start(returnTo: str = "/", db: Session = Depends(get_db)):
    try:
        url, binding = sso.start(db, returnTo)
    except sso.SsoError as exc:
        return RedirectResponse(f"/?sso_error={quote(str(exc))}", status_code=302)
    response = RedirectResponse(url, status_code=302)
    response.set_cookie(sso.COOKIE, binding, max_age=sso.STATE_MINUTES * 60, httponly=True, samesite="lax",
                        secure=get_settings().public_base_url.startswith("https://"), path="/api/console/auth/sso")
    return response


@router.get("/auth/sso/callback")
def sso_callback(request: Request, code: str = "", state: str = "", error: str = "", error_description: str = "",
                 db: Session = Depends(get_db)):
    """Microsoft sends the browser back here. Success hands the console a one-minute, single-use code for its
    session token, so the token itself never appears in a URL or the browser history."""
    def fail(message: str) -> RedirectResponse:
        response = RedirectResponse(f"/?sso_error={quote(message[:300])}", status_code=302)
        response.delete_cookie(sso.COOKIE, path="/api/console/auth/sso")
        return response

    if error:
        return fail(f"Microsoft sign-in did not complete: {error_description or error}")
    ratelimit.check(f"sso:{_client_ip(request)}", 30, 300)
    try:
        user, return_to = sso.complete(db, code, state, request.cookies.get(sso.COOKIE, ""))
    except sso.SsoError as exc:
        audit.record(db, "sso", "auth.sso_failed", "", None, ip=_client_ip(request), reason=str(exc)[:200])
        db.commit()
        return fail(str(exc))
    if not get_settings().ignore_console_allowlist and not platform_security.ip_allowed(
            platform_security.get(db).get("consoleAllowedNetworks") or [], _client_ip(request)):
        return fail(f"Console access is not allowed from this network ({_client_ip(request)})")
    user.last_login_at = utcnow()
    _, session = sessions.create(db, user, _client_ip(request), request.headers.get("user-agent", ""), method="sso")
    audit.record(db, user.email, "auth.login", user.id, user.tenant_id, session=session.id[-8:], method="microsoft")
    db.commit()
    handoff = issue_token(get_settings().secret_key, user.id, 1, aud="sso-handoff", jti=session.id)
    separator = "&" if "?" in return_to else "?"
    response = RedirectResponse(f"{return_to}{separator}sso={quote(handoff)}", status_code=302)
    response.delete_cookie(sso.COOKIE, path="/api/console/auth/sso")
    return response


@router.post("/auth/sso/complete")
def sso_complete(body: dict = Body(...), db: Session = Depends(get_db)):
    payload = read_token(get_settings().secret_key, str(body.get("handoff") or ""))
    session = db.get(UserSession, (payload or {}).get("jti") or "")
    if (payload is None or payload.get("aud") != "sso-handoff" or session is None or session.method != "sso"
            or session.user_id != payload.get("sub") or session.claimed_at is not None or session.revoked_at is not None):
        raise HTTPException(401, "This sign-in has expired or was already used. Sign in again.")
    session.claimed_at = utcnow()
    user = db.get(User, session.user_id)
    db.commit()
    token = issue_token(get_settings().secret_key, user.id, get_settings().token_ttl_minutes, role=user.role, jti=session.id)
    return {"token": token, "user": to_dict(user), "mfaSetupRequired": platform_security.mfa_required(db, user, "sso")}


@router.put("/platform/security/sso")
def set_sso(request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("platform")
    require_reauth(request, principal)
    try:
        view = sso.save(db, body)
    except sso.SsoError as exc:
        raise HTTPException(400, str(exc)) from None
    audit.record(db, principal.actor, "platform.sso_updated", "platform", principal.user.tenant_id,
                 enabled=view["enabled"], tenant=view["tenant"], required=view["required"], trustMfa=view["trustMfa"])
    db.commit()
    return view


@router.post("/platform/emergency-stop")
def emergency_stop(request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)):
    """Stop everything reaching devices: for a suspected compromised account, script or server. Turning it on is
    immediate and cancels every command not yet started and every remote session; turning it off needs a fresh
    password (and MFA) check. Isolation, release and ending remote sessions still work while it is on."""
    from ..models import Command, RemoteSession
    from .. import remote, services

    principal.require("platform")
    active = bool(body.get("active"))
    reason = str(body.get("reason") or "").strip()
    if active and not reason:
        raise HTTPException(400, "Say why: the reason is shown to everyone until the stop is lifted")
    if not active:
        require_reauth(request, principal)
    saved = platform_security.save(db, {"emergencyStop": platform_security.stop_record(active, principal.actor, reason)})
    cancelled = sessions_ended = 0
    if active:
        now = utcnow()
        for command in db.execute(select(Command).where(
                Command.status.in_(("pending", "dispatched")),
                Command.type.notin_(platform_security.STOP_EXEMPT_COMMANDS))).scalars():
            # Not started yet: cancelled. Handed out: asked to stop (agents check while long commands run).
            command.status = "cancelled" if command.status == "pending" else "cancelling"
            command.cancel_requested_at = now
            command.updated_at = now
            cancelled += 1
        ended = []
        for session in db.execute(select(RemoteSession).where(RemoteSession.status.in_(("waiting", "connected")))).scalars():
            remote.end_session(db, session, principal.actor, "emergency stop")
            ended.append(session.id)
        sessions_ended = len(ended)
    audit.record(db, principal.actor, "platform.emergency_stop_on" if active else "platform.emergency_stop_off", "platform",
                 principal.user.tenant_id, reason=reason, commandsCancelled=cancelled, remoteSessionsEnded=sessions_ended)
    services.fire_webhooks(db, services.msp_tenant_id(db, principal.user.tenant_id), "platform.emergency_stop",
                           {"active": active, "by": principal.actor, "reason": reason})
    db.commit()
    if active:
        for session_id in ended:
            remote.notify_session_end(session_id, principal.actor)
    return {**saved["emergencyStop"], "commandsCancelled": cancelled, "remoteSessionsEnded": sessions_ended}


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
    from .. import services

    try:
        tenant = services.create_customer(db, name, parent_id, principal.actor, str(body.get("template") or "balanced"),
                                          str(body.get("plan") or "complete"), body.get("slug"))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
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
    counts = _passkey_counts(db, [u.id for u in rows])
    return [{**to_dict(u), "passkeys": counts.get(u.id, 0)} for u in rows]


def _passkey_counts(db: Session, user_ids: list[str]) -> dict[str, int]:
    if not user_ids:
        return {}
    return dict(db.execute(select(PasskeyCredential.user_id, func.count()).where(PasskeyCredential.user_id.in_(user_ids))
                           .group_by(PasskeyCredential.user_id)).all())


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


def _group_view(group: DeviceGroup, devices: dict[str, int], children: dict[str, int]) -> dict:
    return {**to_dict(group), "deviceCount": devices.get(group.id, 0), "childCount": children.get(group.id, 0)}


@router.get("/groups")
def list_groups(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(DeviceGroup).where(DeviceGroup.tenant_id.in_(scoped_tenant(principal, tenant_id)))
                      .order_by(DeviceGroup.name)).scalars().all()
    ids = [g.id for g in rows]
    retired = Device.api_key_hash == ("retired-" + Device.id)
    devices = dict(db.execute(select(Device.group_id, func.count()).where(Device.group_id.in_(ids), ~retired)
                              .group_by(Device.group_id)).all()) if ids else {}
    children: dict[str, int] = {}
    for g in rows:
        if g.parent_id:
            children[g.parent_id] = children.get(g.parent_id, 0) + 1
    return [_group_view(g, devices, children) for g in rows]


def _check_group_fields(db: Session, tenant_id: str, body: dict, group: DeviceGroup | None = None) -> None:
    """Name present; parent in the same customer and not the group itself or one of its sub-groups; policy usable here."""
    from ..models import Policy

    if "name" in body and not str(body.get("name") or "").strip():
        raise HTTPException(422, "A group needs a name")
    parent_id = body.get("parentId")
    if parent_id:
        parent = db.get(DeviceGroup, parent_id)
        if parent is None or parent.tenant_id != tenant_id:
            raise HTTPException(400, "The parent group belongs to another customer")
        seen, cursor = set(), parent
        while cursor is not None and cursor.id not in seen:
            if group is not None and cursor.id == group.id:
                raise HTTPException(400, "A group cannot sit inside itself or one of its own sub-groups")
            seen.add(cursor.id)
            cursor = db.get(DeviceGroup, cursor.parent_id) if cursor.parent_id else None
    policy_id = body.get("policyId")
    if policy_id:
        policy = db.get(Policy, policy_id)
        if policy is None or policy.tenant_id not in (None, tenant_id):
            raise HTTPException(400, "The policy belongs to another customer")


@router.post("/groups")
def create_group(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.get("tenantId")
    if not tenant_id:
        raise HTTPException(422, "Choose the customer the group belongs to")
    principal.check_tenant(tenant_id)
    body = {"name": "", **body}
    _check_group_fields(db, tenant_id, body)
    group = DeviceGroup(tenant_id=tenant_id, name=str(body["name"]).strip()[:200], parent_id=body.get("parentId") or None,
                        policy_id=body.get("policyId") or None, match_rules=body.get("matchRules") or {})
    db.add(group)
    audit.record(db, principal.actor, "group.created", group.name, tenant_id)
    db.commit()
    return _group_view(group, {}, {})


@router.patch("/groups/{group_id}")
def update_group(group_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    group = db.get(DeviceGroup, group_id)
    if group is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(group.tenant_id)
    _check_group_fields(db, group.tenant_id, body, group)
    if "name" in body:
        body = {**body, "name": str(body["name"]).strip()[:200]}
    body = {k: (v or None) if k in ("parentId", "policyId") else v for k, v in body.items()}
    changed = apply_fields(group, body, {"name", "parent_id", "policy_id", "match_rules"})
    audit.record(db, principal.actor, "group.updated", group.name, group.tenant_id, fields=changed)
    db.commit()
    return to_dict(group)


def group_uses(db: Session, group: DeviceGroup) -> list[str]:
    """What would silently change scope if the group disappeared: those must be changed first."""
    from ..models import ConditionPackage, MonitorCondition, PatchPolicy, ScheduledTask

    uses = [f"patch policy '{p.name}'" for p in db.execute(select(PatchPolicy).where(PatchPolicy.group_id == group.id)).scalars()]
    for model, field, label in ((ScheduledTask, "targets", "scheduled task"), (ConditionPackage, "targets", "condition package"),
                                (MonitorCondition, "scope", "monitor")):
        for row in db.execute(select(model).where(or_(model.tenant_id == group.tenant_id, model.tenant_id.is_(None)))).scalars():
            if group.id in ((getattr(row, field) or {}).get("groupIds") or []):
                uses.append(f"{label} '{getattr(row, 'name', row.id)}'")
    for policy in db.execute(select(PatchPolicy).where(PatchPolicy.tenant_id == group.tenant_id)).scalars():
        if any(group.id in (ring.get("groupIds") or []) for ring in (policy.rings or []) if isinstance(ring, dict)):
            uses.append(f"a ring in patch policy '{policy.name}'")
    return uses


@router.delete("/groups/{group_id}")
def delete_group(group_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Delete a group. Its devices, sub-groups and enrolment codes move up to its parent (or out of any group)."""
    principal.require("configure")
    group = db.get(DeviceGroup, group_id)
    if group is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(group.tenant_id)
    uses = group_uses(db, group)
    if uses:
        raise HTTPException(409, "Change these first, so they do not quietly cover more or fewer devices: " + "; ".join(uses))
    moved = 0
    for device in db.execute(select(Device).where(Device.group_id == group.id)).scalars():
        device.group_id = group.parent_id
        moved += 1
    for child in db.execute(select(DeviceGroup).where(DeviceGroup.parent_id == group.id)).scalars():
        child.parent_id = group.parent_id
    for token in db.execute(select(EnrollmentToken).where(EnrollmentToken.group_id == group.id)).scalars():
        token.group_id = group.parent_id
    db.flush()
    db.delete(group)
    audit.record(db, principal.actor, "group.deleted", group.name, group.tenant_id, devicesMoved=moved, movedTo=group.parent_id or "no group")
    db.commit()
    return {"ok": True, "devicesMoved": moved, "movedTo": group.parent_id}


@router.post("/groups/members")
def set_group_members(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Put devices into a group (groupId) or take them out of any group (groupId null)."""
    principal.require("configure")
    ids = body.get("deviceIds")
    if not isinstance(ids, list) or not ids or len(ids) > 5000:
        raise HTTPException(422, "deviceIds must list between 1 and 5000 devices")
    group = None
    if body.get("groupId"):
        group = db.get(DeviceGroup, body["groupId"])
        if group is None:
            raise HTTPException(404, "Group not found")
        principal.check_tenant(group.tenant_id)
    moved, skipped = [], []
    for device_id in dict.fromkeys(str(i) for i in ids):
        device = db.get(Device, device_id)
        if device is None or device.tenant_id not in principal.tenant_ids:
            skipped.append({"deviceId": device_id, "reason": "not found"})
        elif group is not None and device.tenant_id != group.tenant_id:
            skipped.append({"deviceId": device_id, "reason": "belongs to another customer than the group"})
        else:
            device.group_id = group.id if group else None
            moved.append(device_id)
    audit.record(db, principal.actor, "group.members.set", group.name if group else "no group", group.tenant_id if group else None,
                 devices=len(moved))
    db.commit()
    return {"moved": moved, "skipped": skipped}


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
    if body.get("groupId"):
        group = db.get(DeviceGroup, body["groupId"])
        if group is None or group.tenant_id != tenant_id:
            raise HTTPException(400, "The group belongs to another customer")
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
