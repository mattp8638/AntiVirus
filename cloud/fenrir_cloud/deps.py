"""FastAPI dependencies: console users, tenant scoping, and device auth."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import Device, Tenant, User, utcnow
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
    if sessions.active(db, payload.get("jti"), user.id) is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session ended. Sign in again.", headers={"WWW-Authenticate": "Bearer"})
    path = request.url.path
    if user.role == "client" and not (path.startswith("/api/portal") or path.startswith("/api/console/auth")):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Client accounts can only use the client portal")
    if user.role == "platform_admin":
        scope = {tid for (tid,) in db.execute(select(Tenant.id)).all()}
    else:
        scope = tenant_subtree(db, user.tenant_id)
    return Principal(user=user, tenant_ids=frozenset(scope), session_id=payload.get("jti"))


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
    device.last_seen_at = utcnow()
    return device


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
    device.last_seen_at = utcnow()
    return device
