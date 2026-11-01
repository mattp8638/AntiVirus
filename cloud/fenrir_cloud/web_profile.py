"""Web protection for iPhone, iPad and Mac without an agent, an app, Intune or an Apple MDM.

Apple lets anyone install a configuration profile that sets the device's encrypted DNS resolver
(``com.apple.dnsSettings.managed``, iOS/iPadOS 14+ and macOS 11+). Fenrir hands out a profile that points the device
at its own per-device DNS-over-HTTPS resolver, so the same DNS protection agents get (threat intelligence, blocklists,
categories) blocks malware and phishing sites on the device, and every blocked lookup is logged against it.

There is no agent, so there are no commands. Fenrir knows the profile is working because the device keeps asking it to
resolve names; when it stops (the profile was removed, or never installed) an alert says so.

Limits worth knowing: the user can remove the profile (only a supervised device can be stopped from doing that), a VPN
app or iCloud Private Relay can send lookups around it, and while the Fenrir server is unreachable the device cannot
look names up at all, because encrypted DNS does not fall back to the network's resolver.
"""

from __future__ import annotations

import os
import plistlib
import re
import secrets
import uuid
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Alert, Device, DnsQueryLog, Tenant, utcnow

PROFILE_ID = "uk.co.fenrirsecurity.webprotection"  # one Fenrir profile per device: a new one replaces the old
PROFILE_NAMESPACE = uuid.UUID("2f3c7a52-6a51-4b0e-9a8e-6f1f8d3b9c11")
MEDIA_TYPE = "application/x-apple-aspen-config"
FILENAME = "Fenrir-web-protection.mobileconfig"
KINDS = {"iphone": ("ios", "iPhone", "phone"), "ipad": ("ios", "iPad", "tablet"), "mac": ("macos", "Mac", "computer")}
SILENT_RULE = "webprofile:silent"
NEVER_USED_AFTER = timedelta(hours=24)  # a profile that was made but never installed
SILENT_AFTER = timedelta(hours=72)  # long enough for a phone left off over a weekend
TOUCH_EVERY = timedelta(seconds=60)


class ProfileError(Exception):
    pass


def agentless(device: Device) -> bool:
    """Protected by the web protection profile only: nothing on the device can run a command."""
    return bool((device.metrics or {}).get("agentless"))


def retired(device: Device) -> bool:
    return device.api_key_hash == f"retired-{device.id}"


def os_version(kind: str, user_agent: str) -> str:
    """What the browser that installed the profile says it is (Macs report a frozen 10.15.7, so it is left out)."""
    if kind == "mac":
        return "macOS"
    match = re.search(r"(?:iPhone|CPU) OS (\d+)[_.](\d+)(?:[_.](\d+))?", user_agent or "")
    name = "iPadOS" if kind == "ipad" else "iOS"
    if not match:
        return name
    return f"{name} {'.'.join(p for p in match.groups() if p)}"


def enrol(db: Session, tenant: Tenant, token, name: str, kind: str, user_agent: str, ip: str) -> Device:
    """A device record for a profile-only device. The caller has checked the enrolment code."""
    if kind not in KINDS:
        raise ProfileError("kind must be iphone, ipad or mac")
    platform, label, role = KINDS[kind]
    hostname = (name or "").strip()[:255] or label
    device = Device(tenant_id=tenant.id, hostname=hostname, platform=platform, os_version=os_version(kind, user_agent),
                    dns_token=secrets.token_urlsafe(24), api_key_hash=f"profile-{secrets.token_hex(24)}",
                    group_id=token.group_id if token is not None and token.group_id else None, approved=True,
                    ip_address=ip[:64], agent_version="", health_state="unknown",
                    inventory={"role": role, "roleLabel": "Web protection profile", "model": label},
                    metrics={"agentless": True, "protection": "dns-profile", "kind": kind})
    db.add(device)
    db.flush()
    return device


def _signing_material() -> tuple[object, object, list] | None:
    """FENRIR_PROFILE_SIGNING_CERT (PEM, the leaf first then its chain) and FENRIR_PROFILE_SIGNING_KEY (PEM)."""
    cert_path, key_path = os.getenv("FENRIR_PROFILE_SIGNING_CERT", ""), os.getenv("FENRIR_PROFILE_SIGNING_KEY", "")
    if not cert_path or not key_path:
        return None
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    try:
        with open(cert_path, "rb") as handle:
            certificates = x509.load_pem_x509_certificates(handle.read())
        with open(key_path, "rb") as handle:
            key = serialization.load_pem_private_key(handle.read(), password=None)
    except (OSError, ValueError) as exc:
        raise ProfileError(f"The profile signing certificate or key could not be read: {exc}") from exc
    return certificates[0], key, certificates[1:]


def signing_configured() -> bool:
    return bool(os.getenv("FENRIR_PROFILE_SIGNING_CERT") and os.getenv("FENRIR_PROFILE_SIGNING_KEY"))


def resolver_url(base_url: str, device: Device) -> str:
    return f"{base_url.rstrip('/')}/dns/{device.dns_token}/dns-query"


def profile_xml(device: Device, tenant: Tenant | None, base_url: str) -> bytes:
    """The configuration profile as a property list. Apple only accepts an https resolver."""
    if not base_url.lower().startswith("https://"):
        raise ProfileError("Fenrir's public address (FENRIR_PUBLIC_URL) must start with https:// for Apple devices to use it")
    owner = (tenant.name if tenant else "") or "your IT team"
    dns_payload = {
        "PayloadType": "com.apple.dnsSettings.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{PROFILE_ID}.dns",
        "PayloadUUID": str(uuid.uuid5(PROFILE_NAMESPACE, f"{device.id}:dns")).upper(),
        "PayloadDisplayName": "Fenrir web protection",
        "PayloadDescription": "Encrypted DNS through Fenrir: malware and phishing sites are blocked.",
        "DNSSettings": {"DNSProtocol": "HTTPS", "ServerURL": resolver_url(base_url, device)},
    }
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": PROFILE_ID,
        "PayloadUUID": str(uuid.uuid5(PROFILE_NAMESPACE, device.id)).upper(),
        "PayloadDisplayName": "Fenrir web protection",
        "PayloadDescription": (f"Set up by {owner}. Sends this device's website lookups through Fenrir over encrypted DNS, "
                               "so malware and phishing sites are blocked. Nothing else on the device is read or changed."),
        "PayloadOrganization": owner[:100],
        "PayloadScope": "System",
        "PayloadRemovalDisallowed": False,
        "PayloadContent": [dns_payload],
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=True)


def profile_bytes(device: Device, tenant: Tenant | None, base_url: str) -> bytes:
    """The profile, signed (shown as Verified on the device) when a signing certificate is configured."""
    xml = profile_xml(device, tenant, base_url)
    material = _signing_material()
    if material is None:
        return xml
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

    certificate, key, chain = material
    builder = pkcs7.PKCS7SignatureBuilder().set_data(xml).add_signer(certificate, key, hashes.SHA256())
    for extra in chain:
        builder = builder.add_certificate(extra)
    return builder.sign(Encoding.DER, [])


def resolver_settings(device: Device, dns_settings: dict) -> dict:
    """A decommissioned profile device still gets plain answers: its phone loses every website otherwise, until someone
    removes the profile from it. Nothing is filtered or logged for it."""
    if retired(device):
        return {**dns_settings, "enabled": False, "blockedCategories": [], "blockDomains": [], "mode": "observe",
                "logQueries": "none"}
    return dns_settings


def touch(db: Session, device: Device, ip: str, now: datetime | None = None) -> None:
    """A lookup from a profile device: it is alive (even if the upstream resolver then fails). Written at most once a
    minute, in its own commit."""
    now = now or utcnow()
    if retired(device) or (device.last_seen_at and now - device.last_seen_at < TOUCH_EVERY):
        return
    device.last_seen_at = now
    if ip:
        device.ip_address = ip[:64]
    metrics = dict(device.metrics or {})
    if not metrics.get("firstLookupAt"):
        metrics["firstLookupAt"] = now.isoformat(timespec="seconds") + "Z"
        device.metrics = metrics
    resolve_silent(db, device, now, "The device is using Fenrir's DNS again.")
    db.commit()


def _open_silent(db: Session, device: Device) -> Alert | None:
    return db.execute(select(Alert).where(Alert.device_id == device.id, Alert.rule_id == SILENT_RULE,
                                          Alert.status.in_(("new", "triaged")))).scalars().first()


def resolve_silent(db: Session, device: Device, now: datetime, why: str) -> None:
    alert = _open_silent(db, device)
    if alert is not None:
        alert.status, alert.updated_at = "resolved", now
        alert.details = {**(alert.details or {}), "autoResolved": why}


def status(device: Device, now: datetime | None = None) -> str:
    """active | quiet (a day without lookups) | silent (alerting) | waiting (not installed yet) | never | retired"""
    now = now or utcnow()
    if retired(device):
        return "retired"
    if not (device.metrics or {}).get("firstLookupAt"):
        return "never" if device.enrolled_at and now - device.enrolled_at > NEVER_USED_AFTER else "waiting"
    if device.last_seen_at is None or now - device.last_seen_at > SILENT_AFTER:
        return "silent"
    return "quiet" if now - device.last_seen_at > timedelta(hours=24) else "active"


def tick(db: Session, now: datetime | None = None) -> dict:
    """Hourly: alert on profile devices that never started or stopped using Fenrir's DNS."""
    now = now or utcnow()
    raised = 0
    for device in db.execute(select(Device).where(Device.approved.is_(True), Device.api_key_hash.like("profile-%"))).scalars():
        state = status(device, now)
        if state not in ("never", "silent") or _open_silent(db, device) is not None:
            continue
        if state == "never":
            title = f"Web protection was never installed on {device.hostname}"
            why = (f"The profile was made {device.enrolled_at:%d %b %Y %H:%M} UTC but the device has not used Fenrir's DNS since. "
                   "It was not installed, or was removed straight away.")
        else:
            title = f"Web protection has stopped on {device.hostname}"
            why = (f"No lookups through Fenrir since {device.last_seen_at:%d %b %Y %H:%M} UTC. The profile may have been removed, "
                   "a VPN may be in use, or the device has been off.")
        db.add(Alert(tenant_id=device.tenant_id, device_id=device.id, rule_id=SILENT_RULE, severity="medium", mitre=["T1562"],
                     title=title[:300], event_ids=[],
                     details={"category": "protection", "source": "Fenrir web protection", "description": why,
                              "remediation": "Check the profile is still installed (Settings > General > VPN & Device Management). "
                                             "If it is gone, make a new code and install it again."}))
        raised += 1
    db.commit()
    return {"raised": raised}


def view(db: Session, device: Device, base_url: str, can_configure: bool, dns_settings: dict, now: datetime | None = None) -> dict:
    now = now or utcnow()
    metrics = device.metrics or {}
    since = now - timedelta(days=7)
    blocked = db.execute(select(func.count()).where(DnsQueryLog.device_id == device.id, DnsQueryLog.at >= since,
                                                    DnsQueryLog.action == "block")).scalar() or 0
    recent = db.execute(select(DnsQueryLog).where(DnsQueryLog.device_id == device.id, DnsQueryLog.action.in_(("block", "observe")))
                        .order_by(DnsQueryLog.at.desc()).limit(15)).scalars().all()
    filtering = bool(dns_settings.get("enabled")) and dns_settings.get("mode") != "observe"
    out = {
        "status": status(device, now),
        "kind": metrics.get("kind") or ("mac" if device.platform == "macos" else "iphone"),
        "firstLookupAt": metrics.get("firstLookupAt"),
        "lastLookupAt": device.last_seen_at.isoformat(timespec="seconds") + "Z" if device.last_seen_at else None,
        "blocked7d": blocked,
        "recent": [{"domain": r.qname, "action": r.action, "reason": r.reason, "category": r.category,
                    "at": r.at.isoformat(timespec="seconds") + "Z"} for r in recent],
        "filtering": filtering,
        "filteringNote": None if filtering else ("DNS protection is off in this device's policy, so nothing is blocked."
                                                if not dns_settings.get("enabled") else
                                                "DNS protection is in observe mode in this device's policy: lookups are logged, not blocked."),
        "signed": signing_configured(),
        "silentAfterHours": int(SILENT_AFTER.total_seconds() // 3600),
    }
    if can_configure and not retired(device):
        out["profileUrl"] = f"{base_url.rstrip('/')}/dns/{device.dns_token}/apple.mobileconfig"
    return out
