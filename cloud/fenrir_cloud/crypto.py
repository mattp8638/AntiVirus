"""Envelope encryption for secrets at rest (credential vault, integration secrets, MFA seeds).

Each value gets its own random 256-bit data key. The value is encrypted with
AES-256-GCM under that data key, and the data key is encrypted (wrapped) with
AES-256-GCM under the master key. Both steps use the ``cryptography``
library; nothing here is a home-made algorithm.

The associated data binds a ciphertext to where it belongs (for example
``vault:<tenant>:<secret id>``): a ciphertext copied into another tenant's
row fails to decrypt instead of leaking.

Master keys:

* ``FENRIR_VAULT_KEY`` - base64 of 32 random bytes (``openssl rand -base64 32``), or
* ``FENRIR_VAULT_KEY_FILE`` - a file holding that value (Docker/Kubernetes secrets, a KMS-synced file).
* ``FENRIR_VAULT_OLD_KEYS`` - comma-separated old keys still accepted for decryption during rotation.

Without a configured key the master key is derived from ``FENRIR_SECRET_KEY``
with HKDF. That keeps development setups working but ties the vault to the
session-signing secret, so production deployments should set a vault key
(``key_status()`` reports which mode is active).
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import get_settings

FORMAT_VERSION = 1


class VaultError(Exception):
    """Raised when a value cannot be decrypted (wrong key, tampering, wrong owner)."""


@dataclass(frozen=True)
class MasterKey:
    kid: str
    key: bytes
    source: str


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode(), validate=True)


def _kid(key: bytes) -> str:
    return hashlib.sha256(b"fenrir-kid" + key).hexdigest()[:12]


def _parse_key(raw: str) -> bytes:
    key = _b64d(raw.strip())
    if len(key) != 32:
        raise ValueError("Vault keys must be 32 bytes, base64-encoded (openssl rand -base64 32)")
    return key


def _keys() -> tuple[MasterKey, dict[str, MasterKey]]:
    settings = get_settings()
    require_explicit = os.getenv("FENRIR_VAULT_REQUIRE_EXPLICIT_KEY", "").lower() in {"1", "true", "yes"}
    raw = os.getenv("FENRIR_VAULT_KEY", "").strip()
    source = "env"
    key_file = os.getenv("FENRIR_VAULT_KEY_FILE", "").strip()
    if not raw and key_file:
        with open(key_file, encoding="utf-8") as handle:
            raw = handle.read().strip()
        source = "file"
    if require_explicit and not raw:
        raise ValueError("An explicit FENRIR_VAULT_KEY or FENRIR_VAULT_KEY_FILE is required")
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"fenrir-vault", info=b"fenrir-vault-master-v1").derive(
        settings.secret_key.encode())
    if raw:
        key = _parse_key(raw)
    else:
        key, source = derived, "derived"
    active = MasterKey(_kid(key), key, source)
    every = {active.kid: active}
    # Values stored before a vault key was configured stay readable, so they can be re-encrypted (rotate()).
    if os.getenv("FENRIR_VAULT_ALLOW_DERIVED_LEGACY", "true").lower() in {"1", "true", "yes"}:
        every.setdefault(_kid(derived), MasterKey(_kid(derived), derived, "derived-legacy"))
    for old in filter(None, (item.strip() for item in os.getenv("FENRIR_VAULT_OLD_KEYS", "").split(","))):
        old_key = _parse_key(old)
        every.setdefault(_kid(old_key), MasterKey(_kid(old_key), old_key, "old"))
    return active, every


def key_status() -> dict:
    active, every = _keys()
    return {
        "keyId": active.kid,
        "source": active.source,
        "productionReady": active.source in {"env", "file"},
        "decryptOnlyKeys": sum(1 for k in every.values() if k.source == "old"),
        "legacyDerivedKeyAccepted": any(k.source == "derived-legacy" for k in every.values()),
        "algorithm": "AES-256-GCM envelope encryption",
    }


def encrypt(plaintext: str | bytes, aad: str) -> dict:
    """Encrypt ``plaintext``; returns a JSON-safe envelope to store in a JSON column."""
    data = plaintext.encode() if isinstance(plaintext, str) else plaintext
    active, _ = _keys()
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, data, aad.encode())
    wrap_nonce = os.urandom(12)
    wrapped = AESGCM(active.key).encrypt(wrap_nonce, data_key, b"fenrir-dek:" + aad.encode())
    return {"v": FORMAT_VERSION, "kid": active.kid, "wn": _b64e(wrap_nonce), "wk": _b64e(wrapped), "n": _b64e(nonce),
            "ct": _b64e(ciphertext)}


def decrypt_bytes(envelope: dict, aad: str) -> bytes:
    if not isinstance(envelope, dict) or envelope.get("v") != FORMAT_VERSION:
        raise VaultError("Unsupported or missing ciphertext")
    _, every = _keys()
    master = every.get(envelope.get("kid", ""))
    if master is None:
        raise VaultError("This value was encrypted with a key that is not configured (check FENRIR_VAULT_KEY / FENRIR_VAULT_OLD_KEYS)")
    try:
        data_key = AESGCM(master.key).decrypt(_b64d(envelope["wn"]), _b64d(envelope["wk"]), b"fenrir-dek:" + aad.encode())
        return AESGCM(data_key).decrypt(_b64d(envelope["n"]), _b64d(envelope["ct"]), aad.encode())
    except (InvalidTag, KeyError, ValueError) as exc:
        raise VaultError("The value could not be decrypted (tampered, moved, or wrong key)") from exc


def decrypt(envelope: dict, aad: str) -> str:
    return decrypt_bytes(envelope, aad).decode()


def needs_rewrap(envelope: dict | None) -> bool:
    if not envelope:
        return False
    active, _ = _keys()
    return envelope.get("kid") != active.kid


def rewrap(envelope: dict, aad: str) -> dict:
    """Re-encrypt under the active master key (key rotation)."""
    return encrypt(decrypt_bytes(envelope, aad), aad)


# --------------------------------------------------------------------------- rotation

# (model, column, aad builder) for every encrypted column; modules register theirs at import time.
_ENCRYPTED: list[tuple[type, str, object]] = []


def register_encrypted(model: type, column: str, aad) -> None:
    if all(m is not model or c != column for m, c, _ in _ENCRYPTED):
        _ENCRYPTED.append((model, column, aad))


def rotate(db) -> dict:
    """Re-encrypt every stored envelope under the active key. Safe to run repeatedly."""
    from sqlalchemy import select

    rewrapped = failed = 0
    for model, column, aad in _ENCRYPTED:
        for row in db.execute(select(model)).scalars():
            envelope = getattr(row, column)
            if not envelope or not needs_rewrap(envelope):
                continue
            try:
                setattr(row, column, rewrap(envelope, aad(row)))
                rewrapped += 1
            except VaultError:
                failed += 1
    return {"rewrapped": rewrapped, "failed": failed, "keyId": _keys()[0].kid}
