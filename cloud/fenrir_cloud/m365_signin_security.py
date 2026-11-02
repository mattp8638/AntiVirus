"""Sign-in security for Microsoft 365, done in Fenrir from the sign-in logs it already keeps (m365_workspace.py).

Microsoft offers impossible-travel detection only with Entra ID P2 / Defender for Cloud Apps licences most small
customers do not have, so Fenrir works it out itself from each successful sign-in's place and time:

``impossible-travel``  Two successful sign-ins by the same user from places further apart than anyone could travel in
                       the time between them (default: over 900 km/h, at least 500 km apart). London at 09:00 and New
                       York at 11:00 is 5,570 km in 2 hours: 2,785 km/h.
``new-country``        A successful sign-in from a country the user has not signed in from in the last 90 days, once
                       Fenrir has at least 14 days of their history (so a new starter does not trigger it).
``spray-success``      A successful sign-in straight after many failed ones (default 10 in an hour): password guessing
                       that worked.

Per customer (``Tenant.settings["signinProtection"]``): on or off, the thresholds, countries to trust (their sign-ins
never count as unusual), IP ranges to ignore (the office, a VPN's exit addresses), and the playbook. The playbook
runs on every finding: always an alert (in the inbox with everything else), and as chosen, sign the user out
everywhere, block their sign-in, open a ticket and email someone. Blocking is not possible in the cloud for a user
synced from Active Directory; the playbook then signs them out, says so on the ticket and leaves the block to AD.

While protection is on, sign-in logs are collected every 10 minutes for that customer instead of hourly.
"""
from __future__ import annotations

import ipaddress
import logging
import math
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, services
from .models import Alert, M365Connection, M365LogEntry, Tenant, utcnow

log = logging.getLogger("fenrir.m365.signin")

DEFAULTS = {"enabled": False, "maxSpeedKmh": 900, "minDistanceKm": 500, "newCountry": True, "sprayFailures": 10,
            "trustedCountries": [], "ignoreNetworks": [],
            "playbook": {"revokeSessions": True, "blockSignIn": False, "openTicket": True, "notifyEmail": ""}}
KINDS = {"impossible-travel": ("Impossible travel", "high"), "new-country": ("Sign-in from a new country", "medium"),
         "spray-success": ("Successful sign-in after many failures", "high")}
LOOKBACK = timedelta(hours=48)
HISTORY = timedelta(days=90)
MIN_HISTORY = timedelta(days=14)


def settings_for(tenant: Tenant | None) -> dict:
    raw = ((tenant.settings or {}).get("signinProtection") or {}) if tenant else {}
    merged = {**DEFAULTS, **{k: v for k, v in raw.items() if k != "playbook"}}
    merged["playbook"] = {**DEFAULTS["playbook"], **(raw.get("playbook") or {})}
    return merged


def distance_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Great-circle distance (haversine)."""
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371.0 * 2 * math.asin(min(1.0, math.sqrt(h)))


def _coords(entry: M365LogEntry) -> tuple[float, float] | None:
    d = entry.details or {}
    try:
        lat, lon = float(d["lat"]), float(d["lon"])
    except (KeyError, TypeError, ValueError):
        return None
    if lat == 0 and lon == 0:
        return None
    return lat, lon


def _ignored(ip: str, networks: list) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in networks:
        try:
            if address in ipaddress.ip_network(str(net), strict=False):
                return True
        except ValueError:
            continue
    return False


def _country(entry: M365LogEntry) -> str:
    return str((entry.details or {}).get("country") or "").upper()


def detect(db: Session, connection: M365Connection, settings: dict, now: datetime | None = None) -> list[dict]:
    """Findings among the sign-ins collected since the last check. Each: kind, user, the sign-ins and a summary."""
    now = now or utcnow()
    state = dict((connection.log_state or {}).get("signinSecurity") or {})
    # Microsoft's sign-in log can lag by minutes: look back two hours past the last check; findings are never raised twice.
    checked = datetime.fromisoformat(state["checkedUntil"]) - timedelta(hours=2) if state.get("checkedUntil") else now - LOOKBACK
    since = max(now - LOOKBACK, checked)
    entries = db.execute(select(M365LogEntry).where(M365LogEntry.connection_id == connection.id, M365LogEntry.kind == "signin",
                                                    M365LogEntry.at >= now - LOOKBACK).order_by(M365LogEntry.at)).scalars().all()
    networks = settings.get("ignoreNetworks") or []
    trusted = {str(c).upper() for c in settings.get("trustedCountries") or []}
    findings: list[dict] = []
    by_user: dict[str, list[M365LogEntry]] = {}
    for entry in entries:
        by_user.setdefault(entry.actor.lower(), []).append(entry)
    for user, rows in by_user.items():
        good = [r for r in rows if r.result == "success" and not _ignored(r.ip, networks)]
        # Impossible travel: consecutive successful sign-ins with places, the later one new since the last check.
        located = [r for r in good if _coords(r)]
        for previous, current in zip(located, located[1:]):
            if current.at < since or previous.ip == current.ip:
                continue
            km = distance_km(_coords(previous), _coords(current))
            hours = max((current.at - previous.at).total_seconds() / 3600, 1 / 60)
            speed = km / hours
            if km >= float(settings["minDistanceKm"]) and speed > float(settings["maxSpeedKmh"]):
                if trusted and _country(previous) in trusted and _country(current) in trusted:
                    continue
                findings.append({"kind": "impossible-travel", "user": current.actor, "userId": (current.details or {}).get("userId"),
                                 "entries": [previous.id, current.id], "at": current.at,
                                 "summary": (f"{current.actor} signed in from {previous.location or previous.ip} at "
                                             f"{previous.at:%H:%M} and from {current.location or current.ip} at {current.at:%H:%M} "
                                             f"UTC: {km:,.0f} km in {hours:.1f} h ({speed:,.0f} km/h)."),
                                 "details": {"distanceKm": round(km), "hours": round(hours, 2), "speedKmh": round(speed),
                                             "from": {"location": previous.location, "ip": previous.ip, "at": previous.at.isoformat() + "Z"},
                                             "to": {"location": current.location, "ip": current.ip, "at": current.at.isoformat() + "Z",
                                                    "app": current.app}}})
        # New country, against the user's 90-day history of successful sign-ins.
        if settings.get("newCountry", True):
            fresh = [r for r in good if r.at >= since and _country(r) and _country(r) not in trusted]
            if fresh:
                history = db.execute(select(M365LogEntry).where(M365LogEntry.connection_id == connection.id, M365LogEntry.kind == "signin",
                                                                M365LogEntry.result == "success", M365LogEntry.actor == rows[0].actor,
                                                                M365LogEntry.at >= now - HISTORY, M365LogEntry.at < since)).scalars().all()
                first_seen = min((h.at for h in history), default=None)
                if first_seen and now - first_seen >= MIN_HISTORY:
                    known = {_country(h) for h in history if _country(h)}
                    reported: set[str] = set()
                    for row in fresh:
                        country = _country(row)
                        if known and country not in known and country not in reported:
                            reported.add(country)
                            findings.append({"kind": "new-country", "user": row.actor, "userId": (row.details or {}).get("userId"),
                                             "entries": [row.id], "at": row.at,
                                             "summary": f"{row.actor} signed in from {row.location or country} ({row.ip}), a country "
                                                        f"they have not signed in from in 90 days (usually {', '.join(sorted(known))}).",
                                             "details": {"country": country, "usual": sorted(known), "ip": row.ip, "app": row.app}})
        # Password guessing that worked: a success right after many failures within an hour.
        threshold = int(settings.get("sprayFailures") or 10)
        for row in [r for r in rows if r.result == "success" and r.at >= since]:
            failures = [r for r in rows if r.result == "failure" and row.at - timedelta(hours=1) <= r.at < row.at]
            if len(failures) >= threshold:
                findings.append({"kind": "spray-success", "user": row.actor, "userId": (row.details or {}).get("userId"),
                                 "entries": [row.id], "at": row.at,
                                 "summary": f"{row.actor} signed in from {row.location or row.ip} after {len(failures)} failed "
                                            f"sign-ins in the hour before.",
                                 "details": {"failures": len(failures), "ip": row.ip, "failedFrom": sorted({f.ip for f in failures})[:10]}})
                break
    state["checkedUntil"] = now.isoformat()
    connection.log_state = {**(connection.log_state or {}), "signinSecurity": state}
    return findings


# --- the playbook ---------------------------------------------------------------------------------------------------


def _already(db: Session, tenant_id: str, kind: str, entries: list[str]) -> bool:
    key = ":".join([kind, *entries])
    rows = db.execute(select(Alert.details).where(Alert.tenant_id == tenant_id, Alert.rule_id == f"m365:{kind}")).scalars()
    return any((d or {}).get("key") == key for d in rows)


def respond(db: Session, connection: M365Connection, finding: dict, settings: dict) -> Alert | None:
    """Raise the alert and run the playbook for one finding (once: a finding seen before is skipped)."""
    from . import m365_admin

    if _already(db, connection.tenant_id, finding["kind"], finding["entries"]):
        return None
    title, severity = KINDS[finding["kind"]]
    playbook = settings["playbook"]
    actions: list[str] = []
    user_id = finding.get("userId")
    if user_id and playbook.get("revokeSessions"):
        try:
            m365_admin.execute(connection, "user.revoke_sessions", user_id, {})
            actions.append("signed out everywhere")
        except Exception as exc:  # noqa: BLE001 - the alert still matters
            actions.append(f"sign-out failed: {str(exc)[:150]}")
    if user_id and playbook.get("blockSignIn"):
        try:
            with m365_admin.session(connection) as (client, headers):
                person = m365_admin.user(client, headers, user_id)
            if person.get("onPremisesSyncEnabled"):
                actions.append("not blocked: the user is synced from Active Directory, block them there")
            else:
                m365_admin.execute(connection, "user.signin", user_id, {"accountEnabled": False})
                actions.append("sign-in blocked")
        except Exception as exc:  # noqa: BLE001
            actions.append(f"block failed: {str(exc)[:150]}")
    alert = Alert(tenant_id=connection.tenant_id, device_id=None, rule_id=f"m365:{finding['kind']}",
                  title=f"{title}: {finding['user']}"[:300], severity=severity, status="new", mitre=["T1078"],
                  details={"category": "identity", "key": ":".join([finding["kind"], *finding["entries"]]),
                           "summary": finding["summary"], "user": finding["user"], "userId": user_id, "connectionId": connection.id,
                           "actions": actions, **finding["details"]})
    db.add(alert)
    db.flush()
    text = finding["summary"] + ("\n\nDone automatically: " + "; ".join(actions) if actions else "\n\nNothing was done automatically.")
    text += ("\n\nCheck with the user. If it was not them: reset their password, check their MFA methods and inbox rules "
             "(Microsoft 365 > Exchange), and review the sign-in logs.")
    if playbook.get("openTicket"):
        services.open_ticket(db, connection.tenant_id, f"{title}: {finding['user']}"[:300], text,
                             priority="P1" if severity == "high" else "P2", source="m365-signin", queue="Security Operations")
    if playbook.get("notifyEmail"):
        from . import mailer

        try:
            mailer.send(str(playbook["notifyEmail"]), f"[Fenrir] {title}: {finding['user']}", text)
        except Exception as exc:  # noqa: BLE001
            log.warning("sign-in alert email failed: %s", exc)
    audit.record(db, "system:m365-signin", f"m365.signin.{finding['kind']}", finding["user"], connection.tenant_id,
                 actions=actions, alert=alert.id)
    return alert


def run_connection(db: Session, connection: M365Connection, collect: bool = True, now: datetime | None = None) -> int:
    from . import m365_workspace

    settings = settings_for(db.get(Tenant, connection.tenant_id))
    if not settings.get("enabled"):
        return 0
    if collect:
        m365_workspace.collect_logs(db, connection, kinds=("signin",))
    raised = 0
    for finding in detect(db, connection, settings, now):
        if respond(db, connection, finding, settings) is not None:
            raised += 1
    return raised


def tick(db: Session) -> None:
    """Every 10 minutes: collect sign-ins and check them, for customers with sign-in protection on."""
    for connection in db.execute(select(M365Connection)).scalars().all():
        if not settings_for(db.get(Tenant, connection.tenant_id)).get("enabled"):
            continue
        try:
            run_connection(db, connection)
            db.commit()
        except Exception as exc:  # noqa: BLE001 - one customer must not stop the others
            db.rollback()
            log.warning("sign-in protection for %s failed: %s", connection.id, exc)
