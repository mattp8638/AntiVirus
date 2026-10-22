"""FastAPI dependencies: console users, tenant scoping, and device auth."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import Device, Tenant, User, utcnow
from .security import digest, has_permission, read_token

bearer = HTTPBearer(auto_error=False)


@dataclass
class Principal:
    user: User
    tenant_ids: frozenset[str]

    @property
    def actor(self) -> str:
        return self.user.email

    def can(self, permission: str) -> bool:
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
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> Principal:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in required", headers={"WWW-Authenticate": "Bearer"})
    payload = read_token(get_settings().secret_key, creds.credentials)
    if payload is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired", headers={"WWW-Authenticate": "Bearer"})
    user = db.get(User, payload.get("sub"))
    if user is None or not user.active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account disabled")
    if user.role == "platform_admin":
        scope = {tid for (tid,) in db.execute(select(Tenant.id)).all()}
    else:
        scope = tenant_subtree(db, user.tenant_id)
    return Principal(user=user, tenant_ids=frozenset(scope))


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
