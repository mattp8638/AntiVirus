"""Push notifications to the console app (Web Push: RFC 8030 delivery, RFC 8291 encryption, RFC 8292 VAPID).

A user turns notifications on in the console (Settings → Account) on each phone or computer they want them on; the
browser gives us a subscription (a push-service URL and two keys), stored in ``push_subscriptions``. ``notify_users``
queues one message per subscription in the durable outbox, so a push service that is down is retried, and a
subscription the push service says is gone (404/410) is removed.

The server's VAPID key pair is made on first use and kept in ``platform_state`` (the private key encrypted with the
vault key). Works with Chrome and Edge (Android and desktop), Firefox, and Safari on iPhone and iPad (iOS 16.4+, when
the console has been added to the home screen).
"""
from __future__ import annotations

import base64
import json
import os
import time
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import events
from .models import PlatformState, PushSubscription, utcnow

STATE_KEY = "webpush.vapid"
TTL_SECONDS = 24 * 3600
MAX_FAILURES = 5


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _hkdf(salt: bytes, info: bytes, length: int, key: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(key)


def _public_bytes(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


# --------------------------------------------------------------------------- keys


def _vapid_private(db: Session) -> ec.EllipticCurvePrivateKey:
    from . import crypto

    row = db.get(PlatformState, STATE_KEY)
    if row is not None and row.value.get("private"):
        pem = crypto.decrypt(row.value["private"], aad=STATE_KEY)
        return serialization.load_pem_private_key(pem.encode(), password=None)  # type: ignore[return-value]
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    value = {"private": crypto.encrypt(pem, aad=STATE_KEY), "public": b64url(_public_bytes(key.public_key()))}
    if row is None:
        db.add(PlatformState(key=STATE_KEY, value=value, updated_at=utcnow()))
    else:
        row.value, row.updated_at = value, utcnow()
    db.flush()
    return key


def public_key(db: Session) -> str:
    """The application server key browsers subscribe with (base64url, uncompressed P-256 point)."""
    return b64url(_public_bytes(_vapid_private(db).public_key()))


def vapid_header(key: ec.EllipticCurvePrivateKey, endpoint: str, subject: str) -> str:
    parsed = urlparse(endpoint)
    header = b64url(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    claims = b64url(json.dumps({"aud": f"{parsed.scheme}://{parsed.netloc}", "exp": int(time.time()) + 12 * 3600, "sub": subject},
                               separators=(",", ":")).encode())
    signing_input = f"{header}.{claims}".encode()
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    token = f"{header}.{claims}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
    return f"vapid t={token}, k={b64url(_public_bytes(key.public_key()))}"


# --------------------------------------------------------------------------- encryption (RFC 8291, aes128gcm)


def encrypt(p256dh: str, auth: str, plaintext: bytes, *, salt: bytes | None = None,
            server_key: ec.EllipticCurvePrivateKey | None = None) -> bytes:
    receiver_bytes = unb64url(p256dh)
    receiver = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), receiver_bytes)
    server_key = server_key or ec.generate_private_key(ec.SECP256R1())
    server_bytes = _public_bytes(server_key.public_key())
    shared = server_key.exchange(ec.ECDH(), receiver)
    ikm = _hkdf(unb64url(auth), b"WebPush: info\x00" + receiver_bytes + server_bytes, 32, shared)
    salt = salt or os.urandom(16)
    cek = _hkdf(salt, b"Content-Encoding: aes128gcm\x00", 16, ikm)
    nonce = _hkdf(salt, b"Content-Encoding: nonce\x00", 12, ikm)
    ciphertext = AESGCM(cek).encrypt(nonce, plaintext + b"\x02", None)  # 0x02: last (and only) record
    return salt + (4096).to_bytes(4, "big") + bytes([len(server_bytes)]) + server_bytes + ciphertext


# --------------------------------------------------------------------------- sending


def subscribe(db: Session, user_id: str, body: dict, label: str = "") -> PushSubscription:
    endpoint = str(body.get("endpoint") or "")
    keys = body.get("keys") or {}
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.netloc or len(endpoint) > 1000:
        raise ValueError("endpoint must be the browser's https push URL")
    p256dh, auth = str(keys.get("p256dh") or ""), str(keys.get("auth") or "")
    try:
        if len(unb64url(p256dh)) != 65 or len(unb64url(auth)) != 16:
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("keys.p256dh and keys.auth are not a browser push subscription") from None
    row = db.execute(select(PushSubscription).where(PushSubscription.endpoint == endpoint)).scalar_one_or_none()
    if row is None:
        row = PushSubscription(user_id=user_id, endpoint=endpoint, p256dh=p256dh, auth=auth, label=label[:200])
        db.add(row)
    else:  # the same browser signed in as someone else now gets that person's notifications
        row.user_id, row.p256dh, row.auth, row.label, row.failures = user_id, p256dh, auth, label[:200] or row.label, 0
    db.flush()
    return row


def notify_users(db: Session, user_ids: list[str], title: str, body: str, url: str = "/", tag: str = "", tenant_id: str | None = None) -> int:
    """Queue a notification to every device each user turned notifications on for. Returns how many were queued."""
    if not user_ids:
        return 0
    rows = db.execute(select(PushSubscription).where(PushSubscription.user_id.in_(set(user_ids)))).scalars().all()
    message = {"title": title[:120], "body": body[:400], "url": url, "tag": tag[:80]}
    for row in rows:
        events.publish(db, "push.delivery", {"subscriptionId": row.id, "message": message}, tenant_id)
    return len(rows)


def send(db: Session, row: PushSubscription, message: dict) -> int:
    """Deliver one message now. Returns the push service's HTTP status."""
    from .config import get_settings

    subject = get_settings().public_base_url.rstrip("/") or "mailto:admin@fenrir.local"
    key = _vapid_private(db)
    payload = encrypt(row.p256dh, row.auth, json.dumps(message, separators=(",", ":")).encode())
    response = httpx.post(row.endpoint, content=payload, timeout=10.0, headers={
        "Authorization": vapid_header(key, row.endpoint, subject), "Content-Encoding": "aes128gcm",
        "Content-Type": "application/octet-stream", "TTL": str(TTL_SECONDS), "Urgency": "high",
        **({"Topic": message["tag"].replace(":", "-")[:32]} if message.get("tag") else {})})
    return response.status_code


@events.handler("push.delivery", name="webpush.deliver")
def _deliver(db: Session, event) -> None:
    row = db.get(PushSubscription, event.payload.get("subscriptionId"))
    if row is None:
        return
    status = send(db, row, event.payload.get("message") or {})
    if status in (404, 410):  # unsubscribed or expired: forget it
        db.delete(row)
        return
    if status >= 500 or status == 429:  # the push service is busy or down: the outbox retries with back-off
        raise RuntimeError(f"push service answered HTTP {status}")
    if status >= 300:  # refused this message; a subscription refused repeatedly is dropped
        row.failures = (row.failures or 0) + 1
        if row.failures >= MAX_FAILURES:
            db.delete(row)
        return
    row.failures, row.last_success_at = 0, utcnow()
