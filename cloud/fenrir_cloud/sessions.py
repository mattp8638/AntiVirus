"""Server-side console sessions (FIX-03): issue, check, list and revoke.

A session token is only accepted while its UserSession row exists, belongs to the token's user, has not expired
and has not been revoked. Revocation also cuts off remote-control viewers opened from that session.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .config import get_settings
from .models import User, UserSession, utcnow
from .security import issue_token, new_secret

TOUCH_SECONDS = 60


def create(db: Session, user: User, ip: str = "", user_agent: str = "", method: str = "password") -> tuple[str, UserSession]:
    settings = get_settings()
    row = UserSession(id=new_secret("session"), user_id=user.id, expires_at=utcnow() + timedelta(minutes=settings.token_ttl_minutes),
                      ip=ip[:64], user_agent=user_agent[:300], method=method)
    db.add(row)
    db.flush()
    token = issue_token(settings.secret_key, user.id, settings.token_ttl_minutes, role=user.role, jti=row.id)
    return token, row


def active(db: Session, session_id: str | None, user_id: str | None) -> UserSession | None:
    if not session_id or not user_id:
        return None
    row = db.get(UserSession, session_id)
    now = utcnow()
    if row is None or row.user_id != user_id or row.revoked_at is not None or row.expires_at <= now:
        return None
    if (now - row.last_seen_at).total_seconds() > TOUCH_SECONDS:
        row.last_seen_at = now
    return row


def _cut_remote_viewers(session_ids: list[str]) -> None:
    from . import remote

    remote.hub.revoke_console_sessions(session_ids)


def revoke(db: Session, session_id: str, reason: str) -> bool:
    row = db.get(UserSession, session_id)
    if row is None or row.revoked_at is not None:
        return False
    row.revoked_at, row.revoked_reason = utcnow(), reason[:80]
    _cut_remote_viewers([row.id])
    return True


def revoke_user(db: Session, user_id: str, reason: str, keep: str | None = None) -> int:
    """Revoke every live session of a user (except ``keep``, the caller's own, when given)."""
    ids = [sid for (sid,) in db.execute(select(UserSession.id).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None),
                                                                     UserSession.id != (keep or "")))]
    if ids:
        db.execute(update(UserSession).where(UserSession.id.in_(ids)).values(revoked_at=utcnow(), revoked_reason=reason[:80]))
        _cut_remote_viewers(ids)
    return len(ids)


def list_for(db: Session, user_id: str) -> list[UserSession]:
    return list(db.execute(select(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None),
                                                     UserSession.expires_at > utcnow()).order_by(UserSession.created_at.desc())).scalars())
