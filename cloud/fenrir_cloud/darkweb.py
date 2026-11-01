"""Dark-web credential exposure: customer accounts found in public data breaches, correlated with identity.

Source: Have I Been Pwned's domain search (``/api/v3/breacheddomain/{domain}``), which needs an HIBP
subscription key (``FENRIR_HIBP_API_KEY``) and each domain verified in the HIBP dashboard. Breach details
(dates, data classes) come from the public ``/api/v3/breaches`` list.

Each exposed address is correlated with:

- the customer's Microsoft 365 directory (last sync): is the account enabled, an admin, registered for MFA?
- Fenrir console users with that email;
- managed devices whose logged-on user matches the address (``DOMAIN\\name`` or ``name@domain``).

Risk: **high** when the breach included passwords and the account is enabled without MFA or is an
admin; **medium** when passwords were exposed; **low** otherwise. Open high-risk exposures mark the
user's devices ``breached-user`` (raising their vulnerability priority) and can open a ticket.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, services
from .config import get_settings
from .models import BreachExposure, Device, M365Connection, Tenant, User, utcnow

log = logging.getLogger("fenrir.darkweb")

HIBP = "https://haveibeenpwned.com/api/v3"
SYNC_EVERY = timedelta(hours=24)
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class DarkWebError(RuntimeError):
    pass


def settings_for(tenant: Tenant) -> dict:
    return {"enabled": False, "domains": [], "autoTicket": True, "lastSyncAt": None, "lastError": "",
            **((tenant.settings or {}).get("darkWeb") or {})}


def clean_domains(values) -> list[str]:
    domains = sorted({str(v).strip().lower().rstrip(".") for v in values or [] if str(v).strip()})
    bad = [d for d in domains if not _DOMAIN.fullmatch(d)]
    if bad:
        raise DarkWebError(f"Not a domain name: {', '.join(bad[:3])}")
    return domains[:20]


def _get(client: httpx.Client, path: str, key: str = "") -> httpx.Response:
    headers = {"user-agent": "Fenrir-MSP-Platform"}
    if key:
        headers["hibp-api-key"] = key
    return client.get(HIBP + path, headers=headers, timeout=30)


def fetch_breach_catalogue(client: httpx.Client) -> dict[str, dict]:
    response = _get(client, "/breaches")
    response.raise_for_status()
    return {b["Name"]: b for b in response.json() if isinstance(b, dict) and b.get("Name")}


def fetch_domain(client: httpx.Client, domain: str, key: str) -> dict[str, list[str]]:
    response = _get(client, f"/breacheddomain/{domain}", key)
    if response.status_code == 404:
        return {}  # no breached accounts on this domain
    if response.status_code in (401, 403):
        raise DarkWebError(f"HIBP refused {domain}: check the subscription key and that the domain is verified in HIBP")
    response.raise_for_status()
    data = response.json()
    return {str(alias).lower(): [str(b) for b in breaches] for alias, breaches in data.items() if isinstance(breaches, list)}


def _directory(db: Session, tenant_id: str) -> tuple[dict[str, dict], dict[str, dict]]:
    users, mfa = {}, {}
    for connection in db.execute(select(M365Connection).where(M365Connection.tenant_id == tenant_id)).scalars():
        snapshot = connection.snapshot or {}
        for user in snapshot.get("users") or []:
            upn = str(user.get("userPrincipalName") or "").lower()
            if upn:
                users[upn] = user
        for row in snapshot.get("mfaRegistration") or []:
            upn = str(row.get("userPrincipalName") or "").lower()
            if upn:
                mfa[upn] = row
    return users, mfa


def _devices_for(devices: list[Device], email: str) -> list[Device]:
    """Devices whose logged-on user is this address, or DOMAIN\\name / AzureAD\\name with the same name."""
    local = email.partition("@")[0]
    matches = []
    for device in devices:
        user = str(((device.metrics or {}).get("loggedOnUser")) or (device.inventory or {}).get("loggedOnUser") or "").lower()
        if user and (user == email or ("\\" in user and user.rsplit("\\", 1)[1] == local)):
            matches.append(device)
    return matches


def correlate(db: Session, tenant_id: str, row: BreachExposure, catalogue: dict[str, dict], users: dict, mfa: dict,
              devices: list[Device]) -> None:
    passwords = "Passwords" in (row.data_classes or [])
    directory = users.get(row.email)
    registration = mfa.get(row.email)
    console_user = db.execute(select(User).where(User.email == row.email)).scalar_one_or_none()
    matched = _devices_for(devices, row.email)
    enabled = bool(directory.get("accountEnabled", True)) if directory else None
    has_mfa = bool(registration.get("isMfaRegistered")) if registration else None
    admin = bool(registration.get("isAdmin")) if registration else False
    row.correlation = {"m365User": bool(directory), "accountEnabled": enabled, "mfaRegistered": has_mfa, "admin": admin,
                       "consoleUser": console_user is not None, "deviceIds": [d.id for d in matched],
                       "hostnames": [d.hostname for d in matched]}
    if passwords and (admin or (enabled is not False and has_mfa is False) or (console_user is not None and not console_user.mfa_enabled)):
        row.risk = "high"
    elif passwords:
        row.risk = "medium"
    else:
        row.risk = "low"


def _refresh_device_flags(db: Session, tenant_id: str) -> None:
    exposed = set()
    for row in db.execute(select(BreachExposure).where(BreachExposure.tenant_id == tenant_id, BreachExposure.status == "open",
                                                       BreachExposure.risk == "high")).scalars():
        exposed.update((row.correlation or {}).get("deviceIds") or [])
    for device in db.execute(select(Device).where(Device.tenant_id == tenant_id)).scalars():
        flags = [f for f in (device.exposure_flags or []) if f != "breached-user"]
        if device.id in exposed:
            flags.append("breached-user")
        if flags != (device.exposure_flags or []):
            device.exposure_flags = flags


def sync_tenant(db: Session, tenant: Tenant, client: httpx.Client | None = None, key: str | None = None) -> dict:
    config = settings_for(tenant)
    key = key if key is not None else get_settings().hibp_api_key
    if not key:
        raise DarkWebError("Set FENRIR_HIBP_API_KEY (a Have I Been Pwned subscription key) to monitor breached accounts")
    if not config["domains"]:
        raise DarkWebError("Add at least one monitored domain")
    own = client is None
    client = client or httpx.Client()
    found, new = 0, 0
    try:
        catalogue = fetch_breach_catalogue(client)
        users, mfa = _directory(db, tenant.id)
        devices = db.execute(select(Device).where(Device.tenant_id == tenant.id)).scalars().all()
        for domain in config["domains"]:
            for alias, breaches in fetch_domain(client, domain, key).items():
                email = f"{alias}@{domain}"
                for name in breaches:
                    meta = catalogue.get(name, {})
                    row = db.execute(select(BreachExposure).where(BreachExposure.tenant_id == tenant.id, BreachExposure.email == email,
                                                                  BreachExposure.breach == name)).scalar_one_or_none()
                    if row is None:
                        row = BreachExposure(tenant_id=tenant.id, email=email, breach=name)
                        db.add(row)
                        new += 1
                    row.breach_title = str(meta.get("Title") or name)[:300]
                    row.breach_date = str(meta.get("BreachDate") or "")[:20]
                    row.data_classes = [str(c) for c in meta.get("DataClasses") or []][:40]
                    row.last_seen = utcnow()
                    correlate(db, tenant.id, row, catalogue, users, mfa, devices)
                    if row.risk == "high" and row.status == "open" and row.ticket_id is None and config.get("autoTicket"):
                        ticket = services.open_ticket(
                            db, tenant.id, f"Breached credentials: {email} ({row.breach_title})",
                            f"{email} appears in the {row.breach_title} breach ({row.breach_date}), which exposed "
                            f"{', '.join(row.data_classes) or 'account data'}. Reset the password, revoke sessions and enforce MFA.",
                            priority="P2", source="dark-web", queue="Security Operations")
                        row.ticket_id = ticket.id
                    found += 1
        db.flush()
        _refresh_device_flags(db, tenant.id)
        config.update(lastSyncAt=utcnow().isoformat() + "Z", lastError="")
    except (httpx.HTTPError, DarkWebError, ValueError) as exc:
        config.update(lastSyncAt=utcnow().isoformat() + "Z", lastError=str(exc)[:300])
        tenant.settings = {**(tenant.settings or {}), "darkWeb": config}
        raise DarkWebError(str(exc)) from exc
    finally:
        if own:
            client.close()
    tenant.settings = {**(tenant.settings or {}), "darkWeb": config}
    audit.record(db, "system:dark-web", "darkweb.synced", tenant.name, tenant.id, exposures=found, new=new)
    return {"exposures": found, "new": new}


def tick(db: Session) -> None:
    """Daily refresh for customers with monitoring on (called hourly by the maintenance loop)."""
    if not get_settings().hibp_api_key:
        return
    for tenant in db.execute(select(Tenant)).scalars():
        config = settings_for(tenant)
        if not config["enabled"] or not config["domains"]:
            continue
        last = config.get("lastSyncAt")
        if last and utcnow() - datetime.fromisoformat(last.rstrip("Z")) < SYNC_EVERY:
            continue
        try:
            sync_tenant(db, tenant)
        except DarkWebError as exc:
            log.warning("dark-web sync for %s failed: %s", tenant.name, exc)
        db.commit()


def set_status(db: Session, row: BreachExposure, status: str, actor: str) -> None:
    if status not in {"open", "remediated", "dismissed"}:
        raise DarkWebError("status must be open, remediated or dismissed")
    row.status = status
    _refresh_device_flags(db, row.tenant_id)
    audit.record(db, actor, "darkweb.exposure.status", row.email, row.tenant_id, breach=row.breach, status=status)


def view(row: BreachExposure) -> dict:
    return {"id": row.id, "tenantId": row.tenant_id, "email": row.email, "breach": row.breach, "breachTitle": row.breach_title,
            "breachDate": row.breach_date, "dataClasses": row.data_classes or [], "status": row.status, "risk": row.risk,
            "correlation": row.correlation or {}, "ticketId": row.ticket_id,
            "firstSeen": row.first_seen.isoformat() + "Z" if row.first_seen else None,
            "lastSeen": row.last_seen.isoformat() + "Z" if row.last_seen else None}
