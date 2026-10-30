"""Staff sign-in with Microsoft Entra ID: OpenID Connect, authorization code flow with PKCE.

Settings > Platform > Security holds the Entra tenant, the app registration's client ID and secret (encrypted in the
vault), whether staff must use it, and whether Entra's own MFA (conditional access) satisfies "require MFA".
Microsoft sign-in only ever matches an existing, active staff account by email; it never creates one, so removing
someone from Fenrir or disabling them in Entra both end their access.

The ID token is verified here: RS256 signature against the tenant's published keys, issuer, audience, expiry, and the
nonce sent with the request. The state parameter is encrypted with the platform vault and bound to the browser that
started the sign-in by a short-lived cookie, so a sign-in link cannot be replayed into someone else's browser.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
import urllib.parse

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import crypto, platform_security
from .config import get_settings
from .models import User

AUTHORITY = "https://login.microsoftonline.com"
STATE_MINUTES = 10
CLOCK_SKEW = 120
COOKIE = "fenrir_sso"

_cache_lock = threading.Lock()
_metadata_cache: dict[str, tuple[float, dict]] = {}
_jwks_cache: dict[str, tuple[float, dict]] = {}


class SsoError(Exception):
    """Shown to the person signing in, so it says what to do."""


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# --------------------------------------------------------------------------- configuration


def settings(db: Session) -> dict:
    return {"enabled": False, "tenant": "", "clientId": "", "required": False, "trustMfa": False,
            **(platform_security.get(db).get("sso") or {})}


def public_view(db: Session) -> dict:
    value = settings(db)
    return {"enabled": bool(value["enabled"]), "tenant": value["tenant"], "clientId": value["clientId"],
            "required": bool(value["required"]), "trustMfa": bool(value["trustMfa"]),
            "secretSet": bool(value.get("secret")), "redirectUri": redirect_uri()}


def redirect_uri() -> str:
    return get_settings().public_base_url.rstrip("/") + "/api/console/auth/sso/callback"


def save(db: Session, body: dict) -> dict:
    current = settings(db)
    tenant = str(body.get("tenant", current["tenant"]) or "").strip()
    client_id = str(body.get("clientId", current["clientId"]) or "").strip()
    updated = {**current, "tenant": tenant, "clientId": client_id,
               "enabled": bool(body.get("enabled", current["enabled"])),
               "required": bool(body.get("required", current["required"])),
               "trustMfa": bool(body.get("trustMfa", current["trustMfa"]))}
    if body.get("clientSecret"):
        updated["secret"] = crypto.encrypt(str(body["clientSecret"]), "sso:client-secret")
    if updated["enabled"]:
        if not tenant or tenant.lower() in {"common", "organizations", "consumers"}:
            raise SsoError("Use your own Entra tenant ID or primary domain, not a multi-tenant endpoint")
        if not client_id or not updated.get("secret"):
            raise SsoError("The app registration's client ID and a client secret are both needed")
    if updated["required"] and not updated["enabled"]:
        raise SsoError("Turn Microsoft sign-in on before requiring it")
    platform_security.save(db, {"sso": updated})
    return public_view(db)


# --------------------------------------------------------------------------- provider metadata


def _client() -> httpx.Client:
    return httpx.Client(timeout=10.0)


def metadata(tenant: str) -> dict:
    with _cache_lock:
        cached = _metadata_cache.get(tenant)
        if cached and cached[0] > time.monotonic():
            return cached[1]
    url = f"{AUTHORITY}/{urllib.parse.quote(tenant, safe='')}/v2.0/.well-known/openid-configuration"
    with _client() as client:
        response = client.get(url)
    if response.status_code != 200:
        raise SsoError(f"Microsoft did not recognise the Entra tenant {tenant!r} (HTTP {response.status_code})")
    document = response.json()
    with _cache_lock:
        _metadata_cache[tenant] = (time.monotonic() + 3600, document)
    return document


def _signing_key(jwks_uri: str, kid: str) -> rsa.RSAPublicKey:
    for refresh in (False, True):  # keys rotate: look once more, fresh, before giving up
        with _cache_lock:
            cached = _jwks_cache.get(jwks_uri)
        if refresh or not cached or cached[0] < time.monotonic():
            with _client() as client:
                document = client.get(jwks_uri).json()
            cached = (time.monotonic() + 3600, document)
            with _cache_lock:
                _jwks_cache[jwks_uri] = cached
        for key in cached[1].get("keys", []):
            if key.get("kid") == kid and key.get("kty") == "RSA":
                n = int.from_bytes(_b64url_decode(key["n"]), "big")
                e = int.from_bytes(_b64url_decode(key["e"]), "big")
                return rsa.RSAPublicNumbers(e, n).public_key()
    raise SsoError("Microsoft's signing key for this sign-in was not found")


def verify_id_token(token: str, meta: dict, audience: str, nonce: str) -> dict:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(signature_b64)
    except (ValueError, json.JSONDecodeError):
        raise SsoError("Microsoft returned an unreadable ID token") from None
    if header.get("alg") != "RS256":
        raise SsoError("Unexpected ID token algorithm")
    key = _signing_key(meta["jwks_uri"], str(header.get("kid") or ""))
    try:
        key.verify(signature, f"{header_b64}.{payload_b64}".encode(), padding.PKCS1v15(), hashes.SHA256())
    except Exception:  # noqa: BLE001 - cryptography raises InvalidSignature
        raise SsoError("The ID token's signature is not valid") from None
    now = time.time()
    if claims.get("iss") != meta.get("issuer"):
        raise SsoError("The ID token was issued by a different Entra tenant")
    if claims.get("aud") != audience:
        raise SsoError("The ID token was issued for a different application")
    if float(claims.get("exp", 0)) < now - CLOCK_SKEW or float(claims.get("nbf", 0)) > now + CLOCK_SKEW:
        raise SsoError("The ID token has expired; sign in again")
    if not nonce or claims.get("nonce") != nonce:
        raise SsoError("The sign-in response does not match the request; sign in again")
    return claims


# --------------------------------------------------------------------------- the flow


def start(db: Session, return_to: str = "/") -> tuple[str, str]:
    """Returns (Microsoft sign-in URL, browser binding for the cookie)."""
    config = settings(db)
    if not config["enabled"]:
        raise SsoError("Microsoft sign-in is not set up")
    meta = metadata(config["tenant"])
    verifier, nonce, binding = secrets.token_urlsafe(48), secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    if not return_to.startswith("/") or return_to.startswith("//"):
        return_to = "/"
    state = crypto.encrypt(json.dumps({
        "verifier": verifier, "nonce": nonce, "binding": hashlib.sha256(binding.encode()).hexdigest(),
        "returnTo": return_to[:300], "expires": time.time() + STATE_MINUTES * 60}), "sso:state")
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    query = urllib.parse.urlencode({
        "client_id": config["clientId"], "response_type": "code", "redirect_uri": redirect_uri(),
        "response_mode": "query", "scope": "openid profile email", "state": _b64url(json.dumps(state).encode()),
        "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "select_account"})
    return f"{meta['authorization_endpoint']}?{query}", binding


def complete(db: Session, code: str, state: str, binding: str) -> tuple[User, str]:
    """Checks the response, redeems the code, verifies the ID token and finds the staff account.
    Returns (user, where the console should go next)."""
    config = settings(db)
    if not config["enabled"]:
        raise SsoError("Microsoft sign-in is not set up")
    try:
        saved = json.loads(crypto.decrypt(json.loads(_b64url_decode(state)), "sso:state"))
    except Exception:  # noqa: BLE001 - tampered, truncated or from another server
        raise SsoError("This sign-in link is not valid; start again") from None
    if saved["expires"] < time.time():
        raise SsoError("The sign-in took too long; start again")
    if not binding or hashlib.sha256(binding.encode()).hexdigest() != saved["binding"]:
        raise SsoError("Finish signing in in the same browser you started in")
    meta = metadata(config["tenant"])
    with _client() as client:
        response = client.post(meta["token_endpoint"], data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(),
            "client_id": config["clientId"], "client_secret": crypto.decrypt(config["secret"], "sso:client-secret"),
            "code_verifier": saved["verifier"], "scope": "openid profile email"})
    body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
    if response.status_code != 200 or "id_token" not in body:
        raise SsoError(f"Microsoft refused the sign-in: {body.get('error_description') or body.get('error') or response.status_code}")
    claims = verify_id_token(body["id_token"], meta, config["clientId"], saved["nonce"])
    email = str(claims.get("email") or claims.get("preferred_username") or claims.get("upn") or "").strip().lower()
    if not email:
        raise SsoError("Microsoft did not say which account signed in")
    user = db.execute(select(User).where(func.lower(User.email) == email)).scalar_one_or_none()
    if user is None or not user.active or user.role in ("client", "service"):
        raise SsoError(f"There is no active Fenrir staff account for {email}. Ask an administrator to add you.")
    return user, saved["returnTo"]
