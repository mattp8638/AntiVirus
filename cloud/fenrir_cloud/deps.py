"""FastAPI dependencies: console users, tenant scoping, and device auth."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import hmac

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import presence
from .config import get_settings
from .db import get_db
from .models import Command, Device, Tenant, User, utcnow
from .security import digest, has_permission, read_token, reauth_state

bearer = HTTPBearer(auto_error=False)


@dataclass
class Principal:
    user: User
    tenant_ids: frozenset[str]
    session_id: str | None = None
    # Set for API credentials (CORE-04): exactly these permissions, whatever the role says.
    scopes: frozenset[str] | None = None
    credential_id: str | None = None

    @property
    def actor(self) -> str:
        return self.user.email

    def can(self, permission: str) -> bool:
        if self.scopes is not None:
            return permission in self.scopes
        return has_permission(self.user.role, permission)

    def require(self, permission: str) -> None:
        if not self.can(permission):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Your role ({self.user.role}) cannot {permission}")

    def check_tenant(self, tenant_id: str | None) -> None:
        if tenant_id is None:
            if not self.can("platform"):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Global objects need a platform admin")
            return
        if tenant_id not in self.tenant_ids:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")


def tenant_subtree(db: Session, root_id: str) -> set[str]:
    tenants = db.execute(select(Tenant.id, Tenant.parent_id)).all()
    children: dict[str | None, list[str]] = {}
    for tid, parent in tenants:
        children.setdefault(parent, []).append(tid)
    out, stack = set(), [root_id]
    while stack:
        current = stack.pop()
        if current in out:
            continue
        out.add(current)
        stack.extend(children.get(current, []))
    return out


def current_principal(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> Principal:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in required", headers={"WWW-Authenticate": "Bearer"})
    from . import apikeys

    if creds.credentials.startswith(apikeys.PREFIX):
        if request.url.path.startswith("/api/portal") or request.url.path.startswith("/api/console/auth"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "API credentials cannot use sign-in or portal endpoints")
        client_ip = request.client.host if request.client else ""
        service_user, cred = apikeys.authenticate(db, creds.credentials, client_ip)
        return Principal(user=service_user, tenant_ids=frozenset(tenant_subtree(db, cred.tenant_id)),
                         scopes=frozenset(cred.scopes), credential_id=cred.id)
    payload = read_token(get_settings().secret_key, creds.credentials)
    # Only session tokens sign a user in; re-auth, remote-session and other purpose tokens carry an "aud".
    if payload is None or payload.get("aud") not in (None, "session"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired", headers={"WWW-Authenticate": "Bearer"})
    user = db.get(User, payload.get("sub"))
    if user is None or not user.active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account disabled")
    from . import sessions

    # The token is only good while its server-side session is: logout, password/MFA changes and revokes end it.
    session_row = sessions.active(db, payload.get("jti"), user.id)
    if session_row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session ended. Sign in again.", headers={"WWW-Authenticate": "Bearer"})
    path = request.url.path
    if user.role == "client" and not (path.startswith("/api/portal") or path.startswith("/api/console/auth")):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Client accounts can only use the client portal")
    if user.role != "client":
        staff_access_check(db, user, request, session_row.method)
    if user.role == "platform_admin":
        scope = {tid for (tid,) in db.execute(select(Tenant.id)).all()}
    else:
        scope = tenant_subtree(db, user.tenant_id)
        if user.assigned_tenant_ids:  # CORE-02: limited to chosen customers inside their own tenant
            assigned: set[str] = set()
            for tid in user.assigned_tenant_ids:
                if tid in scope:
                    assigned |= tenant_subtree(db, tid)
            scope = assigned & scope
    scopes = None
    if user.role.startswith("custom:"):
        from . import roles

        scopes = frozenset(roles.permissions_of(db, user.role))
    return Principal(user=user, tenant_ids=frozenset(scope), session_id=payload.get("jti"), scopes=scopes)


# What a staff member without MFA can still reach while MFA is required: enough to enrol, read who they are, or leave.
# What a staff account still needs while required MFA is not set up: enrol an authenticator app or a passkey, sign out.
MFA_SETUP_PATHS = ("/api/console/auth/me", "/api/console/auth/mfa/setup", "/api/console/auth/mfa/enable",
                   "/api/console/auth/logout", "/api/console/auth/reauth", "/api/console/auth/passkeys")


def staff_access_check(db: Session, user: User, request: Request, session_method: str | None = None) -> None:
    """The install's staff controls: console networks and required MFA (platform_security)."""
    from . import platform_security

    security = platform_security.get(db)
    client_ip = request.client.host if request.client else ""
    if (not get_settings().ignore_console_allowlist
            and not platform_security.ip_allowed(security.get("consoleAllowedNetworks") or [], client_ip)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Console access is not allowed from this network ({client_ip})")
    if platform_security.mfa_required(db, user, session_method) and not request.url.path.startswith(MFA_SETUP_PATHS):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Set up multi-factor authentication to continue",
                            headers={"X-Fenrir-Mfa-Setup": "required"})


def scoped_tenant(principal: Principal, tenant_id: str | None) -> list[str]:
    """Tenant filter for list endpoints: one tenant if asked (and allowed), else all visible."""
    if tenant_id:
        principal.check_tenant(tenant_id)
        return [tenant_id]
    return list(principal.tenant_ids)


def current_device(
    device_id: str,
    x_device_api_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Device:
    if not x_device_api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing X-Device-Api-Key")
    device = db.execute(select(Device).where(Device.api_key_hash == digest(x_device_api_key))).scalar_one_or_none()
    if device is None or device.id != device_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown device credentials")
    presence.touch(device)
    return device


def current_command_device(
    device_id: str, command_id: str, x_device_api_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Device:
    """Only command state/completion may use a narrowly scoped retired cancellation key."""
    if not x_device_api_key:
        raise HTTPException(401, "Missing X-Device-Api-Key")
    key_hash = digest(x_device_api_key)
    device = db.get(Device, device_id)
    if device is not None and hmac.compare_digest(device.api_key_hash, key_hash):
        presence.touch(device)
        return device
    command = db.get(Command, command_id)
    if (device is not None
            and command is not None and command.device_id == device.id and command.tenant_id == device.tenant_id
            and command.cancel_requested_at is not None and command.cancel_requested_at >= utcnow() - timedelta(days=7)
            and command.cancel_api_key_hash and hmac.compare_digest(command.cancel_api_key_hash, key_hash)):
        return device
    raise HTTPException(401, "Unknown device credentials")


REAUTH_HEADER = "X-Fenrir-Reauth"
REAUTH_MINUTES = 5


def require_reauth(request: Request, principal: Principal) -> None:
    """Sensitive actions (revealing secrets, identity changes, restores) need a recent password (+MFA) check.

    The console gets a short-lived token from POST /api/console/auth/reauth and sends it in
    the X-Fenrir-Reauth header. 403 with detail "reauth_required" tells it to ask again.
    """
    token = request.headers.get(REAUTH_HEADER, "")
    payload = read_token(get_settings().secret_key, token) if token else None
    if (payload is None or payload.get("aud") != "reauth" or payload.get("sub") != principal.user.id
            or payload.get("session") != digest(request.headers.get("Authorization", ""))
            or payload.get("state") != reauth_state(get_settings().secret_key, principal.user)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "reauth_required")


def current_device_by_key(x_device_api_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> Device:
    """Device authentication for agent endpoints that have no device id in the path."""
    if not x_device_api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing X-Device-Api-Key")
    device = db.execute(select(Device).where(Device.api_key_hash == digest(x_device_api_key))).scalar_one_or_none()
    if device is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown device credentials")
    presence.touch(device)
    return device
