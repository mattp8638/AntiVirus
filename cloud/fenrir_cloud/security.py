"""Password hashing, session tokens, and device/enrollment secrets.

Only the standard library is used: scrypt for passwords, HMAC-SHA256 for
signed session tokens, SHA-256 digests for stored API keys.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
import time

ROLE_PERMISSIONS: dict[str, set[str]] = {
    # Full control of the platform, every tenant.
    "platform_admin": {"read", "respond", "configure", "manage_tenants", "platform", "billing", "crm", "vault"},
    # MSP staff manage every customer tenant below their own.
    "msp_admin": {"read", "respond", "configure", "manage_tenants", "billing", "crm", "vault"},
    "soc_analyst": {"read", "respond", "configure"},
    "technician": {"read", "respond", "crm", "vault"},
    "billing": {"read", "billing", "crm"},
    # Customer-side roles are limited to their own tenant subtree.
    "tenant_admin": {"read", "respond", "configure", "vault"},
    "tenant_analyst": {"read", "respond"},
    "viewer": {"read"},
    # Customer end users: the client portal only (their own tickets, invoices and public KB).
    "client": {"portal"},
}
# "vault": reveal and copy stored credentials (always with recent re-authentication and an audit record).
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
    if not isinstance(token, str) or len(token) > 16384 or not token.isascii():
        return None
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
    if not isinstance(payload, dict):
        return None
    expiry = payload.get("exp")
    if isinstance(expiry, bool) or not isinstance(expiry, (int, float)) or not math.isfinite(expiry) or not expiry > time.time():
        return None
    return payload


def new_secret(prefix: str, nbytes: int = 24) -> str:
    return f"{prefix}_{secrets.token_urlsafe(nbytes)}"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


# --------------------------------------------------------------------------- TOTP (RFC 6238)


def new_totp_secret() -> str:
    """160-bit random seed, base32 as authenticator apps expect."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_code(secret: str, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = (int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF) % (10 ** digits)
    return str(value).zfill(digits)


def verify_totp(secret: str, code: str, window: int = 1, at: float | None = None) -> bool:
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != 6:
        return False
    now = time.time() if at is None else at
    return any(hmac.compare_digest(totp_code(secret, now + drift * 30), code) for drift in range(-window, window + 1))


def totp_uri(secret: str, account: str, issuer: str = "Fenrir") -> str:
    from urllib.parse import quote

    return f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def reauth_state(secret: str, user) -> str:
    """Opaque fingerprint invalidated by identity or authentication changes."""
    state = json.dumps([user.password_hash, bool(user.mfa_enabled), user.mfa_secret,
                        user.role, user.tenant_id, bool(user.active)], sort_keys=True)
    return hmac.new(secret.encode(), state.encode(), hashlib.sha256).hexdigest()
