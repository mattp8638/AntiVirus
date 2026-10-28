"""Scoped API credentials for integrations (CORE-04).

A credential is a bearer token "fsk_..." that signs in as its own service user (role "service", which has no
permissions of its own). What it may do is the explicit scope list chosen when it was created - never more than its
creator could do, and never platform, tenant management, vault or Microsoft 365 administration - within one customer
subtree. It expires, can be rotated and revoked, is rate limited and records its last use. Sensitive actions that need
a fresh password check (revealing secrets, step-up approvals) are impossible for it by construction.
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import ratelimit
from .models import ApiCredential, User, utcnow
from .security import digest, new_secret

PREFIX = "fsk_"
GRANTABLE = ("read", "respond", "configure", "crm", "grc", "billing")
SERVICE_ROLE = "service"
MAX_DAYS = 365
REQUESTS_PER_MINUTE = 600


def issue(db: Session, tenant_id: str, name: str, scopes: list[str], days: int, creator: str) -> tuple[ApiCredential, str]:
    token = PREFIX + new_secret("", 36).lstrip("_")
    cred = ApiCredential(tenant_id=tenant_id, name=name, scopes=sorted(set(scopes)), secret_hash=digest(token), prefix=token[:12],
                         created_by=creator, expires_at=utcnow() + timedelta(days=days), service_user_id="")
    db.add(cred)
    db.flush()
    user = User(tenant_id=tenant_id, email=f"api+{cred.id}@service.fenrir", name=f"API: {name}", password_hash="!service",
                role=SERVICE_ROLE, active=True)
    db.add(user)
    db.flush()
    cred.service_user_id = user.id
    return cred, token


def rotate(db: Session, cred: ApiCredential) -> str:
    token = PREFIX + new_secret("", 36).lstrip("_")
    cred.secret_hash, cred.prefix, cred.rotated_at = digest(token), token[:12], utcnow()
    return token


def revoke(db: Session, cred: ApiCredential, actor: str) -> None:
    cred.revoked_at, cred.revoked_by = utcnow(), actor
    user = db.get(User, cred.service_user_id)
    if user is not None:
        user.active = False


def authenticate(db: Session, token: str, client_ip: str) -> tuple[User, ApiCredential]:
    cred = db.execute(select(ApiCredential).where(ApiCredential.secret_hash == digest(token))).scalar_one_or_none()
    now = utcnow()
    if cred is None or cred.revoked_at is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or revoked API credential", headers={"WWW-Authenticate": "Bearer"})
    if cred.expires_at <= now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API credential expired", headers={"WWW-Authenticate": "Bearer"})
    user = db.get(User, cred.service_user_id)
    if user is None or not user.active or user.role != SERVICE_ROLE:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API credential disabled")
    ratelimit.check(f"apikey:{cred.id}", REQUESTS_PER_MINUTE, 60)
    if cred.last_used_at is None or now - cred.last_used_at > timedelta(seconds=30) or cred.last_used_ip != client_ip:
        cred.last_used_at, cred.last_used_ip = now, client_ip[:64]
    cred.use_count = (cred.use_count or 0) + 1
    db.commit()  # usage is recorded even when the request itself only reads
    return user, cred
