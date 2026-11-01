"""Device API key rotation (CORE-04).

Two steps, so a device can never lock itself out:

1. The agent calls POST /api/v1/devices/{id}/rotate-key with its current key. The server keeps the current key
   working and stores the new one as pending.
2. The agent saves the new key, then uses it. The first request with the pending key promotes it, and from then on
   the old key is refused.

An agent that crashes between the two still has its old key and simply asks again, which replaces the pending key.
Rotation is asked for in the heartbeat reply (``rotateKey``) when the key is older than FENRIR_DEVICE_KEY_MAX_AGE_DAYS
or a technician requested it. Agents that predate rotation ignore the flag. Compromise response is still
decommissioning, which revokes every key at once.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .config import Settings
from .models import Device, utcnow
from .security import digest, new_secret


def _retired(device: Device) -> bool:
    return device.api_key_hash == f"retired-{device.id}" or device.api_key_hash.startswith("profile-")


def find(db: Session, raw_key: str | None) -> Device | None:
    """The device a key belongs to. A pending key's first use completes its rotation."""
    if not raw_key:
        return None
    key_hash = digest(raw_key)
    device = db.execute(select(Device).where(Device.api_key_hash == key_hash)).scalar_one_or_none()
    if device is not None:
        return device
    device = db.execute(select(Device).where(Device.pending_api_key_hash == key_hash)).scalar_one_or_none()
    if device is None or _retired(device):
        return None
    promote(db, device)
    return device


def matches(db: Session, device: Device, raw_key: str) -> bool:
    """Whether ``raw_key`` is this device's key (promoting a pending key on first use)."""
    import hmac

    key_hash = digest(raw_key)
    if hmac.compare_digest(device.api_key_hash, key_hash):
        return True
    if device.pending_api_key_hash and hmac.compare_digest(device.pending_api_key_hash, key_hash) and not _retired(device):
        promote(db, device)
        return True
    return False


def promote(db: Session, device: Device) -> None:
    device.api_key_hash, device.pending_api_key_hash = device.pending_api_key_hash, None
    device.api_key_rotated_at, device.key_rotation_requested = utcnow(), False
    audit.record(db, f"device:{device.hostname}", "device.key_rotated", device.id, device.tenant_id)
    db.commit()  # the old key stops working now, whatever the rest of this request does


def start(db: Session, device: Device) -> str:
    """Issue a new key as pending; the current key keeps working until the new one is used."""
    if _retired(device):
        raise ValueError("decommissioned devices have no key to rotate")
    key = new_secret("fdk", 32)
    device.pending_api_key_hash = digest(key)
    db.commit()
    return key


def due(device: Device, settings: Settings) -> bool:
    if _retired(device):
        return False
    if device.key_rotation_requested:
        return True
    if settings.device_key_max_age_days <= 0:
        return False
    since = device.api_key_rotated_at or device.enrolled_at
    return since is not None and utcnow() - since > timedelta(days=settings.device_key_max_age_days)
