"""Passkeys (WebAuthn): sign in, and confirm who you are before sensitive actions, with a phone, laptop or security key.

A passkey proves two things at once, the device that holds it and the PIN, fingerprint or face that unlocks it, so a
sign-in with one counts as multi-factor. Every request asks for user verification and refuses a response without it.
Passkeys are tied to this server's address (the relying party ID is the host of FENRIR_PUBLIC_URL), so a look-alike
phishing site cannot use them.

Verification is done here with the cryptography package: the client data (type, challenge, origin), the authenticator
data (relying party hash, presence and verification flags, signature counter) and the signature over both. Attestation
is not requested ("none"): Fenrir trusts the person who registered the passkey, not a make of authenticator.
Challenges are signed, expire after five minutes and are accepted once.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import ratelimit
from .config import get_settings
from .models import PasskeyCredential, User, utcnow
from .security import issue_token, read_token

CHALLENGE_MINUTES = 5
ES256, EDDSA, RS256 = -7, -8, -257
FLAG_USER_PRESENT, FLAG_USER_VERIFIED, FLAG_ATTESTED = 0x01, 0x04, 0x40
MAX_PER_USER = 10


class PasskeyError(Exception):
    """Shown to the person using the passkey, so it says what to do."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(value) -> bytes:
    if not isinstance(value, str) or len(value) > 20000:
        raise PasskeyError("The passkey response is not readable")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError):
        raise PasskeyError("The passkey response is not readable") from None


# --------------------------------------------------------------------------- where passkeys are valid


def rp_id() -> str:
    return urlparse(get_settings().public_base_url).hostname or "localhost"


def origin() -> str:
    url = urlparse(get_settings().public_base_url)
    return f"{url.scheme}://{url.netloc}"


# --------------------------------------------------------------------------- CBOR (only what WebAuthn uses)


def _cbor(data: bytes, pos: int = 0, depth: int = 0):
    if depth > 8:
        raise ValueError("nested too deeply")
    initial = data[pos]
    major, info = initial >> 5, initial & 0x1F
    pos += 1
    if info < 24:
        value = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if pos + size > len(data):
            raise ValueError("truncated")
        value = int.from_bytes(data[pos:pos + size], "big")
        pos += size
    else:
        raise ValueError("indefinite lengths are not used by WebAuthn")
    if major == 0:
        return value, pos
    if major == 1:
        return -1 - value, pos
    if major in (2, 3):
        if pos + value > len(data):
            raise ValueError("truncated")
        chunk = data[pos:pos + value]
        return (chunk if major == 2 else chunk.decode()), pos + value
    if major == 4:
        items = []
        for _ in range(value):
            item, pos = _cbor(data, pos, depth + 1)
            items.append(item)
        return items, pos
    if major == 5:
        mapping = {}
        for _ in range(value):
            key, pos = _cbor(data, pos, depth + 1)
            mapping[key], pos = _cbor(data, pos, depth + 1)
        return mapping, pos
    if major == 6:  # a tag: the tagged item is what matters
        return _cbor(data, pos, depth + 1)
    return {20: False, 21: True, 22: None}.get(info), pos


def cbor_decode(data: bytes, pos: int = 0):
    """Returns (value, position after it)."""
    try:
        return _cbor(data, pos)
    except (IndexError, ValueError, UnicodeDecodeError, TypeError):
        raise PasskeyError("The passkey response is not readable") from None


# --------------------------------------------------------------------------- keys and signatures


def public_key_from_cose(cose) -> tuple[int, bytes]:
    """COSE key -> (algorithm, SubjectPublicKeyInfo DER)."""
    if not isinstance(cose, dict):
        raise PasskeyError("The passkey's public key is not readable")
    alg, kty = cose.get(3), cose.get(1)
    try:
        if alg == ES256 and kty == 2 and cose.get(-1) == 1:
            key = ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"),
                                                ec.SECP256R1()).public_key()
        elif alg == EDDSA and kty == 1 and cose.get(-1) == 6:
            key = ed25519.Ed25519PublicKey.from_public_bytes(cose[-2])
        elif alg == RS256 and kty == 3:
            key = rsa.RSAPublicNumbers(int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-1], "big")).public_key()
            if key.key_size < 2048:
                raise PasskeyError("This security key uses an RSA key that is too short")
        else:
            raise PasskeyError("This passkey uses a kind of key Fenrir does not support")
    except (KeyError, TypeError, ValueError):
        raise PasskeyError("The passkey's public key is not readable") from None
    return alg, key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def verify_signature(alg: int, spki: bytes, signature: bytes, signed: bytes) -> None:
    key = serialization.load_der_public_key(spki)
    try:
        if alg == ES256 and isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif alg == EDDSA and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, signed)
        elif alg == RS256 and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise PasskeyError("This passkey uses a kind of key Fenrir does not support")
    except (InvalidSignature, ValueError):
        raise PasskeyError("The passkey's signature is not valid") from None


# --------------------------------------------------------------------------- challenges


def _challenge(purpose: str, user_id: str = "") -> tuple[str, str]:
    """Returns (challenge for the browser, signed token the browser sends back with the response)."""
    challenge = b64url(secrets.token_bytes(32))
    token = issue_token(get_settings().secret_key, user_id or "-", CHALLENGE_MINUTES, aud=f"passkey-{purpose}",
                        challenge=challenge)
    return challenge, token


def _redeem(token, purpose: str, user_id: str = "") -> str:
    payload = read_token(get_settings().secret_key, token) if isinstance(token, str) else None
    if payload is None or payload.get("aud") != f"passkey-{purpose}" or payload.get("sub") != (user_id or "-"):
        raise PasskeyError("This passkey request has expired; try again")
    try:  # once only: a captured response cannot be played back
        ratelimit.check(f"passkey-challenge:{payload['challenge']}", 1, CHALLENGE_MINUTES * 60 + 60)
    except HTTPException:
        raise PasskeyError("This passkey request has already been used; try again") from None
    return payload["challenge"]


def _client_data(raw: bytes, kind: str, challenge: str) -> None:
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise PasskeyError("The passkey response is not readable") from None
    if not isinstance(data, dict) or data.get("type") != kind:
        raise PasskeyError("The passkey response is for a different step; try again")
    if data.get("challenge") != challenge:
        raise PasskeyError("This passkey request has expired; try again")
    if data.get("origin") != origin() or data.get("crossOrigin") is True:
        raise PasskeyError(f"The passkey was used on {data.get('origin')!r}, not {origin()}")


def _authenticator_data(data: bytes) -> tuple[int, int]:
    """Checks the relying party and the flags; returns (flags, signature counter)."""
    if len(data) < 37:
        raise PasskeyError("The passkey response is not readable")
    if data[:32] != hashlib.sha256(rp_id().encode()).digest():
        raise PasskeyError(f"This passkey is for a different site, not {rp_id()}")
    flags = data[32]
    if not flags & FLAG_USER_PRESENT:
        raise PasskeyError("The passkey did not confirm someone was present")
    if not flags & FLAG_USER_VERIFIED:
        raise PasskeyError("Unlock the passkey with its PIN, fingerprint or face; Fenrir requires it")
    return flags, int.from_bytes(data[33:37], "big")


# --------------------------------------------------------------------------- registration


def view(row: PasskeyCredential) -> dict:
    return {"id": row.id, "name": row.name, "createdAt": row.created_at.isoformat() + "Z",
            "lastUsedAt": row.last_used_at.isoformat() + "Z" if row.last_used_at else None}


def list_for(db: Session, user_id: str) -> list[PasskeyCredential]:
    return list(db.execute(select(PasskeyCredential).where(PasskeyCredential.user_id == user_id)
                           .order_by(PasskeyCredential.created_at)).scalars())


def registration_options(db: Session, user: User) -> dict:
    existing = list_for(db, user.id)
    if len(existing) >= MAX_PER_USER:
        raise PasskeyError(f"You already have {MAX_PER_USER} passkeys; remove one first")
    challenge, token = _challenge("register", user.id)
    return {"token": token, "publicKey": {
        "challenge": challenge,
        "rp": {"id": rp_id(), "name": "Fenrir"},
        "user": {"id": b64url(user.id.encode()), "name": user.email, "displayName": user.name or user.email},
        "pubKeyCredParams": [{"type": "public-key", "alg": alg} for alg in (ES256, EDDSA, RS256)],
        "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"},
        "attestation": "none",
        "excludeCredentials": [{"type": "public-key", "id": row.credential_id} for row in existing],
        "timeout": CHALLENGE_MINUTES * 60 * 1000}}


def register(db: Session, user: User, token, credential, name: str) -> PasskeyCredential:
    challenge = _redeem(token, "register", user.id)
    response = (credential or {}).get("response") if isinstance(credential, dict) else None
    if not isinstance(response, dict):
        raise PasskeyError("The passkey response is not readable")
    _client_data(b64url_decode(response.get("clientDataJSON")), "webauthn.create", challenge)
    attestation, _ = cbor_decode(b64url_decode(response.get("attestationObject")))
    auth_data = attestation.get("authData") if isinstance(attestation, dict) else None
    if not isinstance(auth_data, bytes):
        raise PasskeyError("The passkey response is not readable")
    flags, count = _authenticator_data(auth_data)
    if not flags & FLAG_ATTESTED or len(auth_data) < 55:
        raise PasskeyError("The passkey response did not include a new credential")
    length = int.from_bytes(auth_data[53:55], "big")
    raw_id = auth_data[55:55 + length]
    if len(raw_id) != length or not 16 <= length <= 1023:
        raise PasskeyError("The passkey response is not readable")
    cose, _ = cbor_decode(auth_data, 55 + length)
    alg, spki = public_key_from_cose(cose)
    credential_id = b64url(raw_id)
    if db.execute(select(PasskeyCredential.id).where(PasskeyCredential.credential_id == credential_id)).first():
        raise PasskeyError("This passkey is already registered")
    transports = response.get("transports")
    row = PasskeyCredential(
        user_id=user.id, credential_id=credential_id, public_key=base64.b64encode(spki).decode(), algorithm=alg,
        sign_count=count, name=(str(name or "").strip() or "Passkey")[:100],
        transports=[str(t)[:20] for t in transports][:8] if isinstance(transports, list) else None)
    db.add(row)
    db.flush()
    return row


# --------------------------------------------------------------------------- signing in and confirming identity


def assertion_options() -> dict:
    """For any sign-in or confirmation: the browser offers the passkeys it holds for this site."""
    challenge, token = _challenge("get")
    return {"token": token, "publicKey": {"challenge": challenge, "rpId": rp_id(), "userVerification": "required",
                                          "allowCredentials": [], "timeout": CHALLENGE_MINUTES * 60 * 1000}}


def verify_assertion(db: Session, token, credential) -> tuple[User, PasskeyCredential]:
    """Checks a passkey response and returns whose it is. The caller decides whether that person may sign in."""
    challenge = _redeem(token, "get")
    if not isinstance(credential, dict) or not isinstance(credential.get("response"), dict):
        raise PasskeyError("The passkey response is not readable")
    response = credential["response"]
    credential_id = b64url(b64url_decode(credential.get("rawId") or credential.get("id")))
    row = db.execute(select(PasskeyCredential).where(PasskeyCredential.credential_id == credential_id)).scalar_one_or_none()
    if row is None:
        raise PasskeyError("This passkey is not registered with Fenrir (it may have been removed)")
    client_data = b64url_decode(response.get("clientDataJSON"))
    _client_data(client_data, "webauthn.get", challenge)
    auth_data = b64url_decode(response.get("authenticatorData"))
    _, count = _authenticator_data(auth_data)
    verify_signature(row.algorithm, base64.b64decode(row.public_key), b64url_decode(response.get("signature")),
                     auth_data + hashlib.sha256(client_data).digest())
    user = db.get(User, row.user_id)
    if response.get("userHandle") and user is not None and b64url_decode(response["userHandle"]) != user.id.encode():
        raise PasskeyError("The passkey does not belong to this account")
    # Synced passkeys always report 0; a key that counts must only ever count up, or it has been copied.
    if (count or row.sign_count) and count <= row.sign_count:
        raise PasskeyError("This passkey's counter went backwards, which suggests it was copied. Remove it and add it again.")
    if user is None or not user.active or user.role == "service":
        raise PasskeyError("This account cannot sign in")
    row.sign_count, row.last_used_at = count, utcnow()
    return user, row
