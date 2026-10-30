"""Install-wide controls on who can sign in and what can reach devices, set once by the MSP's platform administrators.

- requireMfa: staff must use multi-factor authentication: an authenticator app, a passkey sign-in, or (if trusted)
  Microsoft sign-in. A staff account without it can only reach its own profile, MFA setup and sign-out until it enrols. Client portal users and API credentials are not affected.
- consoleAllowedNetworks: staff sign-in and console use only from these networks (CIDRs). Agents, the client portal,
  the DNS resolver and API credentials (which have their own allow-lists) are not affected.
- scriptReview: library scripts and remediation packages run only in a version a second person reviewed
  (script_review.py).
- emergencyStop: while on, no new script, command or remote session reaches any device, except isolating or
  releasing one. For when an account, a script or the server itself may be compromised.

Stored on the MSP tenant; the environment gives the defaults for an install that has never saved them.
"""

from __future__ import annotations

import ipaddress
import threading
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import Tenant, utcnow

_lock = threading.Lock()
_cache: tuple[float, dict] | None = None
CACHE_SECONDS = 10.0

# During an emergency stop these still go: they contain an incident rather than spread one.
STOP_EXEMPT_COMMANDS = frozenset({"device.isolate", "device.release", "remote.session.end"})


def _msp(db: Session) -> Tenant | None:
    return db.execute(select(Tenant).where(Tenant.kind == "msp").order_by(Tenant.created_at)).scalars().first()


def defaults() -> dict:
    return {"requireMfa": get_settings().require_mfa, "consoleAllowedNetworks": [], "emergencyStop": {"active": False},
            "scriptReview": get_settings().script_review}


def get(db: Session) -> dict:
    global _cache
    with _lock:
        if _cache is not None and _cache[0] > time.monotonic():
            return _cache[1]
    msp = _msp(db)
    stored = ((msp.settings or {}) if msp else {}).get("security") or {}
    value = {**defaults(), **stored}
    with _lock:
        _cache = (time.monotonic() + CACHE_SECONDS, value)
    return value


def invalidate() -> None:
    global _cache
    with _lock:
        _cache = None


def save(db: Session, updates: dict) -> dict:
    msp = _msp(db)
    if msp is None:
        raise ValueError("No MSP tenant")
    current = {**defaults(), **((msp.settings or {}).get("security") or {})}
    msp.settings = {**(msp.settings or {}), "security": {**current, **updates}}
    db.flush()
    invalidate()
    return get(db)


def validate_networks(values) -> list[str]:
    if not isinstance(values, list) or len(values) > 100:
        raise ValueError("consoleAllowedNetworks must be a list of at most 100 networks")
    networks = []
    for value in values:
        try:
            networks.append(str(ipaddress.ip_network(str(value).strip(), strict=False)))
        except ValueError:
            raise ValueError(f"{value!r} is not an IP address or network (for example 203.0.113.0/24)") from None
    return sorted(set(networks))


def ip_allowed(networks: list[str], ip: str) -> bool:
    if not networks:
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(network, strict=False) for network in networks)


def mfa_required(db: Session, user, session_method: str | None = None) -> bool:
    if user.role in ("client", "service") or user.mfa_enabled or not get(db).get("requireMfa"):
        return False
    if session_method == "passkey":  # the device plus its PIN, fingerprint or face: multi-factor by itself
        return False
    sso = get(db).get("sso") or {}
    # Signed in through Entra, whose conditional access the MSP has said enforces MFA.
    return not (session_method == "sso" and sso.get("enabled") and sso.get("trustMfa"))


def stopped(db: Session, command_type: str = "") -> dict | None:
    """The active emergency stop, unless this command is one that may still run during it."""
    stop = get(db).get("emergencyStop") or {}
    if not stop.get("active") or command_type in STOP_EXEMPT_COMMANDS:
        return None
    return stop


def stop_record(active: bool, actor: str, reason: str) -> dict:
    return {"active": active, "by": actor, "reason": reason[:500], "at": utcnow().isoformat(timespec="seconds") + "Z"}
