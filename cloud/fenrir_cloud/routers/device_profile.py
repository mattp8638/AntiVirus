"""The full system profile agents report (every 6 hours and on demand), and disk-encryption recovery keys.

Agent side: POST /api/v1/devices/{id}/profile with {"profile": {...}, "recoveryKeys": [...]}.
Console side: the profile with a list of findings worth a technician's attention, the escrowed recovery keys
(without the secrets), and a reveal endpoint that needs re-authentication and is audited.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crypto, ratelimit, services
from ..db import get_db
from ..deps import Principal, current_device, current_principal, require_reauth
from ..models import Device, DeviceProfile, RecoveryKey, utcnow

agent = APIRouter(prefix="/api/v1/devices/{device_id}", tags=["Agent"])
console = APIRouter(prefix="/api/console/devices/{device_id}", tags=["Devices"])

MAX_PROFILE_BYTES = 2_000_000
_SECRET_WORDS = ("password", "recoverykey", "secret")


def _scrub(value, depth: int = 0):
    """Drop anything that looks like a secret; the profile is shown to every technician with read access."""
    if depth > 12:
        return None
    if isinstance(value, dict):
        return {str(k)[:80]: _scrub(v, depth + 1) for k, v in value.items()
                if not any(word in str(k).lower().replace("_", "") for word in _SECRET_WORDS)
                or str(k).lower() in {"passwordlastset", "passwordexpires", "passwordrequired", "passwordneverexpires"}}
    if isinstance(value, list):
        return [_scrub(v, depth + 1) for v in value[:2000]]
    if isinstance(value, str):
        return value[:4000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:4000]


def _aad(row: RecoveryKey) -> str:
    return f"recovery-key:{row.tenant_id}:{row.device_id}:{row.id}"


@agent.post("/profile")
def report_profile(request: Request, body: dict = Body(...), device: Device = Depends(current_device),
                   db: Session = Depends(get_db)):
    length = int(request.headers.get("content-length") or 0)
    if length > MAX_PROFILE_BYTES:
        raise HTTPException(413, "Profile too large")
    ratelimit.check(f"profile:{device.id}", 30, 3600)
    profile = body.get("profile")
    if not isinstance(profile, dict):
        raise HTTPException(422, "profile must be an object")
    clean = _scrub(profile)
    row = db.get(DeviceProfile, device.id)
    if row is None:
        row = DeviceProfile(device_id=device.id, tenant_id=device.tenant_id)
        db.add(row)
    row.profile, row.collected_at = clean, utcnow()
    # Keep the device summary used by lists and search in step with the profile.
    hardware, os_info = clean.get("hardware") or {}, clean.get("os") or {}
    summary = {k: v for k, v in {"manufacturer": hardware.get("manufacturer"), "model": hardware.get("model"),
                                 "serial": hardware.get("serial"), "cpu": (hardware.get("cpu") or {}).get("name"),
                                 "osName": os_info.get("name"), "osBuild": os_info.get("build"),
                                 "domain": os_info.get("domain")}.items() if v}
    if summary:
        device.inventory = {**(device.inventory or {}), **summary}
    if hardware.get("serial") and not device.serial_number:
        device.serial_number = str(hardware["serial"])[:255]

    keys = body.get("recoveryKeys")
    stored = 0
    if isinstance(keys, list):
        existing = {(k.volume, k.key_id): k for k in db.execute(select(RecoveryKey).where(RecoveryKey.device_id == device.id)).scalars()}
        seen = set()
        for item in keys[:64]:
            if not isinstance(item, dict):
                continue
            volume = str(item.get("volume") or "")[:64]
            key_id = str(item.get("keyId") or "")[:64]
            secret = str(item.get("recoveryPassword") or "")
            if not volume or not key_id or not 20 <= len(secret) <= 200:
                continue
            seen.add((volume, key_id))
            key = existing.get((volume, key_id))
            if key is None:
                key = RecoveryKey(tenant_id=device.tenant_id, device_id=device.id, volume=volume, key_id=key_id,
                                  kind=str(item.get("kind") or "bitlocker")[:32])
                db.add(key)
                db.flush()
                key.ciphertext = crypto.encrypt(secret, _aad(key))
                audit.record(db, f"device:{device.hostname}", "recovery_key.escrowed", f"{volume} {key_id}", device.tenant_id)
            key.status, key.last_seen = "active", utcnow()
            stored += 1
        # Protectors that disappeared from the device are kept (for recovery) but marked removed.
        for ident, key in existing.items():
            if ident not in seen and key.status == "active":
                key.status = "removed"
    db.commit()
    return {"stored": True, "recoveryKeys": stored}


def _owned_device(db: Session, principal: Principal, device_id: str) -> Device:
    device = db.get(Device, device_id)
    if device is None or device.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Device not found")
    return device


def _num(value) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _parse_time(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is None else parsed.astimezone(timezone.utc).replace(tzinfo=None)


def findings(profile: dict, now: datetime | None = None) -> list[dict]:
    """Things a technician should look at, worst first."""
    now = now or utcnow()
    out: list[dict] = []

    def add(severity: str, area: str, title: str, detail: str = "") -> None:
        out.append({"severity": severity, "area": area, "title": title, "detail": detail})

    for disk in profile.get("disks") or []:
        name = disk.get("model") or disk.get("name") or "Disk"
        health = str(disk.get("health") or "").lower()
        if health and health not in {"healthy", "ok", "passed", "verified"}:
            add("high", "disks", f"{name}: health {disk.get('health')}", "Back up the data and plan a replacement.")
        if disk.get("smartOk") is False:
            add("high", "disks", f"{name}: SMART reports a failure", "The drive predicts it will fail.")
        wear = _num(disk.get("wearPercent"))
        if wear is not None and wear >= 80:
            add("medium" if wear < 95 else "high", "disks", f"{name}: {wear:.0f}% worn", "SSD endurance is nearly used up.")
        temperature = _num(disk.get("temperatureC"))
        if temperature is not None and temperature >= 60:
            add("medium", "disks", f"{name}: {temperature:.0f} °C", "Running hot; check cooling.")
        errors = (_num(disk.get("readErrors")) or 0) + (_num(disk.get("writeErrors")) or 0)
        if errors > 0:
            add("medium", "disks", f"{name}: {errors:.0f} read/write errors", "")
    for volume in profile.get("volumes") or []:
        size, free = _num(volume.get("sizeGb")), _num(volume.get("freeGb"))
        mount = volume.get("mount") or volume.get("label") or "Volume"
        if size and free is not None and size >= 1:
            percent = 100 * free / size
            if percent < 5 or free < 2:
                add("high", "disks", f"{mount} is nearly full", f"{free:.1f} GB free of {size:.0f} GB ({percent:.0f}%).")
            elif percent < 15:
                add("medium", "disks", f"{mount} is running low on space", f"{free:.1f} GB free of {size:.0f} GB ({percent:.0f}%).")
        encryption = volume.get("encryption") or {}
        if volume.get("system") and encryption and str(encryption.get("protection") or "").lower() in {"off", "unprotected", "0"}:
            add("high", "security", f"{mount} (system drive) is not encrypted",
                "Turn on BitLocker / FileVault so a lost device does not expose data.")
    battery = profile.get("battery") or {}
    health_percent = _num(battery.get("healthPercent"))
    if battery.get("present") and health_percent is not None and health_percent < 60:
        add("medium" if health_percent >= 40 else "high", "hardware", f"Battery at {health_percent:.0f}% of its design capacity",
            "Consider a battery replacement.")
    os_info = profile.get("os") or {}
    last_boot = _parse_time(os_info.get("lastBoot"))
    if last_boot and now - last_boot > timedelta(days=30):
        add("medium", "os", f"Not restarted for {(now - last_boot).days} days", "Updates may be waiting on a restart.")
    if os_info.get("rebootPending"):
        add("low", "os", "A restart is pending", ", ".join(os_info.get("rebootReasons") or []))
    if os_info.get("activation") and str(os_info["activation"]).lower() not in {"licensed", "activated", "n/a"}:
        add("medium", "os", f"Windows is not activated ({os_info['activation']})", "")
    security = profile.get("security") or {}
    for product in security.get("antivirus") or []:
        if product.get("enabled") is False:
            add("medium", "security", f"{product.get('name')} is turned off", "")
        elif product.get("upToDate") is False:
            add("low", "security", f"{product.get('name')} definitions are out of date", "")
    for profile_fw in security.get("firewall") or []:
        if profile_fw.get("enabled") is False:
            add("medium", "security", f"Firewall off for the {profile_fw.get('profile')} profile", "")
    hardware = profile.get("hardware") or {}
    if hardware.get("secureBoot") is False:
        add("low", "security", "Secure Boot is off", "")
    tpm = hardware.get("tpm") or {}
    if tpm and tpm.get("present") is False:
        add("low", "security", "No TPM found", "BitLocker and Windows 11 need a TPM.")
    if security.get("smb1") is True:
        add("medium", "security", "SMBv1 is enabled", "An old protocol used by worms; disable it.")
    if security.get("uac") is False:
        add("medium", "security", "User Account Control is off", "")
    users = (profile.get("users") or {}).get("local") or []
    admins = [u for u in users if u.get("admin") and u.get("enabled")]
    if len(admins) > 2:
        add("low", "users", f"{len(admins)} enabled local administrator accounts", ", ".join(u.get("name", "") for u in admins[:8]))
    for user in users:
        if user.get("enabled") and user.get("passwordRequired") is False:
            add("medium", "users", f"Local account {user.get('name')} has no password requirement", "")
    events = profile.get("events") or {}
    shutdowns = _num(events.get("unexpectedShutdowns7d"))
    if shutdowns and shutdowns >= 2:
        add("medium", "os", f"{shutdowns:.0f} unexpected shutdowns in the last 7 days", "Check power, overheating or crashes.")
    bluescreens = _num(events.get("bluescreens7d"))
    if bluescreens and bluescreens > 0:
        add("high" if bluescreens >= 3 else "medium", "os", f"{bluescreens:.0f} blue screen(s) in the last 7 days",
            "Check drivers, memory and the minidump files.")
    disk_errors = _num(events.get("diskErrors7d"))
    if disk_errors and disk_errors > 0:
        add("high" if disk_errors >= 10 else "medium", "disks", f"{disk_errors:.0f} disk errors in the event log (7 days)", "")
    stopped = (profile.get("services") or {}).get("autoStopped") or []
    if stopped:
        add("low", "os", f"{len(stopped)} automatic service{'s are' if len(stopped) != 1 else ' is'} not running", ", ".join(stopped[:6]))
    order = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda f: order.get(f["severity"], 3))
    return out


@console.get("/profile")
def get_profile(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    device = _owned_device(db, principal, device_id)
    row = db.get(DeviceProfile, device.id)
    keys = db.execute(select(RecoveryKey).where(RecoveryKey.device_id == device.id)
                      .order_by(RecoveryKey.status, RecoveryKey.last_seen.desc())).scalars().all()
    profile = row.profile if row else {}
    return {
        "collectedAt": row.collected_at.isoformat() + "Z" if row else None,
        "profile": profile,
        "findings": findings(profile) if row else [],
        "recoveryKeys": [{"id": k.id, "volume": k.volume, "keyId": k.key_id, "kind": k.kind, "status": k.status,
                          "firstSeen": k.first_seen.isoformat() + "Z", "lastSeen": k.last_seen.isoformat() + "Z"} for k in keys],
    }


@console.post("/recovery-keys/{key_id}/reveal")
def reveal_recovery_key(device_id: str, key_id: str, request: Request, response: Response,
                        principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    device = _owned_device(db, principal, device_id)
    key = db.get(RecoveryKey, key_id)
    if key is None or key.device_id != device.id:
        raise HTTPException(404, "Recovery key not found")
    require_reauth(request, principal)
    ratelimit.check(f"recovery-reveal:{principal.user.id}", 20, 300)
    secret = crypto.decrypt(key.ciphertext, _aad(key))
    audit.record(db, principal.actor, "recovery_key.revealed", f"{device.hostname}:{key.volume}", device.tenant_id, key=key.key_id)
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return {"volume": key.volume, "keyId": key.key_id, "recoveryPassword": secret}


@console.post("/profile/refresh")
def refresh_profile(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    device = _owned_device(db, principal, device_id)
    try:
        command = services.enqueue_command(db, device, "inventory.refresh", principal.actor, reason="Refresh the system profile")
    except services.CommandError as exc:
        raise HTTPException(409, str(exc)) from None
    db.commit()
    return {"commandId": command.id}
