"""Password hashing, session tokens, and device/enrollment secrets.

Only the standard library is used: scrypt for passwords, HMAC-SHA256 for
signed session tokens, SHA-256 digests for stored API keys.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

ROLE_PERMISSIONS: dict[str, set[str]] = {
    # Full control of the platform, every tenant.
    "platform_admin": {"read", "respond", "configure", "manage_tenants", "platform", "billing", "crm"},
    # MSP staff manage every customer tenant below their own.
    "msp_admin": {"read", "respond", "configure", "manage_tenants", "billing", "crm"},
    "soc_analyst": {"read", "respond", "configure"},
    "technician": {"read", "respond", "crm"},
    "billing": {"read", "billing", "crm"},
    # Customer-side roles are limited to their own tenant subtree.
    "tenant_admin": {"read", "respond", "configure"},
    "tenant_analyst": {"read", "respond"},
    "viewer": {"read"},
    # Customer end users: the client portal only (their own tickets, invoices and public KB).
    "client": {"portal"},
}
ROLES = tuple(ROLE_PERMISSIONS)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_b64, digest_b64 = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(digest_b64)
    actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=len(expected))
    return hmac.compare_digest(actual, expected)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def issue_token(secret: str, subject: str, ttl_minutes: int, **claims) -> str:
    payload = {"sub": subject, "exp": int(time.time()) + ttl_minutes * 60, **claims}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def read_token(secret: str, token: str) -> dict | None:
    try:
        body, sig = token.split(".")
    except ValueError:
        return None
    expected = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(_unb64(body))
    except (ValueError, json.JSONDecodeError):
        return None
    if int(payload.get("exp", 0)) < time.time():
        return None
    return payload


def new_secret(prefix: str, nbytes: int = 24) -> str:
    return f"{prefix}_{secrets.token_urlsafe(nbytes)}"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())
