"""Phone app protection: Android phones assess every installed app, and Fenrir decides what to do about each.

The phone (agent/android: AppScanner, core/AppRisk) reports, for each app, where it came from (an app store or
sideloaded), its APK and signing-certificate SHA-256, what it can do (control the screen through accessibility, read
text messages, draw over other apps, act as device administrator, read notifications, hide its icon) and a risk score
with reasons. New installs and updates are reported as they happen; every app once a day.

Here each app gets a verdict:

- threat intelligence first: an indicator on its APK hash, its signer, or its package (written android:com.x.y)
  makes it malicious, suspicious or trusted (an allow indicator, in the customer's scope or everywhere);
- otherwise the phone's assessment: high risk (banking-trojan or stalkerware patterns) is risky, medium is worth a
  review, low is clean.

Policy (Phone app protection) decides which verdicts raise an alert, and may suspend malicious apps at once on
company-owned phones (Fenrir as device owner). An app's alert resolves itself when the app is removed or trusted.
"""

from __future__ import annotations

import re

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .models import Alert, Device, Indicator, MobileApp, Tenant, utcnow

PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
LEVELS = ("low", "medium", "high")
# Verdict -> alert severity; and the least severe verdict each alertOn setting raises an alert for.
SEVERITY = {"malicious": "critical", "suspicious": "high", "risky": "high", "review": "medium"}
ALERTING = {"off": set(), "malicious": {"malicious", "suspicious"}, "high": {"malicious", "suspicious", "risky"},
            "medium": {"malicious", "suspicious", "risky", "review"}}
MAX_APPS = 3000


def settings_for(db: Session, device: Device) -> dict:
    from . import policy_schema, services

    tenant = db.get(Tenant, device.tenant_id)
    return policy_schema.resolve(services.policy_layers(db, tenant, device=device))["settings"].get("mobile") or {}


def rule_id(package: str) -> str:
    return f"mobile:{package}"[:64]


def _hex(value) -> str | None:
    text = str(value or "").strip().lower()
    return text if HEX64.fullmatch(text) else None


def verdict(db: Session, tenant_id: str, row: MobileApp) -> tuple[str, str]:
    """(verdict, why)."""
    from .intel import _not_expired

    hashes = [h for h in (row.sha256, row.signer) if h]
    match = [Indicator.value.in_(hashes)] if hashes else []
    rows = db.execute(select(Indicator).where(
        or_(*match, (Indicator.type == "package") & (Indicator.value == row.package.lower())), _not_expired(),
        or_(Indicator.tenant_id.is_(None), Indicator.tenant_id == tenant_id))).scalars().all()
    # Customer entries beat global ones; allow beats malicious within the same scope.
    rows.sort(key=lambda r: (r.tenant_id is None, r.verdict != "allow", -r.confidence))
    if rows:
        top = rows[0]
        what = "app" if top.type == "package" else ("signer" if top.value == row.signer else "file")
        name = {"allow": "trusted", "malicious": "malicious", "suspicious": "suspicious"}.get(top.verdict, "suspicious")
        return name, f"Threat intelligence marks this {what} {top.verdict}" + (f" ({top.source})" if top.source else "")
    return {"high": "risky", "medium": "review"}.get(row.risk_level, "clean"), "; ".join(row.reasons[:3])


def _open_alert(db: Session, device: Device, package: str) -> Alert | None:
    return db.execute(select(Alert).where(Alert.device_id == device.id, Alert.rule_id == rule_id(package),
                                          Alert.status.in_(("new", "triaged")))).scalars().first()


def _resolve(db: Session, device: Device, package: str, why: str) -> None:
    alert = _open_alert(db, device, package)
    if alert is not None:
        alert.status, alert.updated_at = "resolved", utcnow()
        alert.details = {**(alert.details or {}), "autoResolved": why}


def _alert(db: Session, device: Device, row: MobileApp, alert_on: str) -> None:
    alert = _open_alert(db, device, row.package)
    if row.verdict not in ALERTING.get(alert_on, ALERTING["high"]):
        if alert is not None and row.verdict in ("trusted", "clean"):
            _resolve(db, device, row.package, "The app is now " + row.verdict + ".")
        return
    title = f"{'Malicious' if row.verdict == 'malicious' else 'Risky'} app on {device.hostname}: {row.label or row.package}"[:300]
    details = {"category": "mobile", "package": row.package, "label": row.label, "version": row.version, "installer": row.installer,
               "sideloaded": row.sideloaded, "sha256": row.sha256, "signer": row.signer, "reasons": row.reasons,
               "verdict": row.verdict, "verdictReason": row.verdict_reason, "abilities": row.abilities,
               "description": row.verdict_reason or "; ".join(row.reasons)}
    if alert is None:
        db.add(Alert(tenant_id=device.tenant_id, device_id=device.id, rule_id=rule_id(row.package), title=title,
                     severity=SEVERITY[row.verdict], mitre=[], event_ids=[], details=details))
    elif SEVERITY[row.verdict] != alert.severity:  # e.g. threat intelligence has since marked a risky app malicious
        alert.severity, alert.title, alert.details, alert.updated_at = SEVERITY[row.verdict], title, {**(alert.details or {}), **details}, utcnow()


def _suspend(db: Session, device: Device, row: MobileApp) -> None:
    from . import services

    try:
        services.enqueue_command(db, device, "app.suspend", "system:mobile-protection",
                                 payload={"package": row.package, "suspended": True},
                                 reason=f"Malicious app suspended by policy: {row.label or row.package}")
    except services.CommandError:
        pass


def ingest(db: Session, device: Device, fields: dict) -> dict:
    """A phone's mobile.apps.assessed event: every app (full) or the ones just installed or updated."""
    apps = [a for a in (fields.get("apps") or []) if isinstance(a, dict)][:MAX_APPS]
    full = bool(fields.get("full"))
    settings = settings_for(db, device)
    alert_on = str(settings.get("alertOn") or "high")
    now = utcnow()
    rows = {r.package: r for r in db.execute(select(MobileApp).where(MobileApp.device_id == device.id)).scalars()}
    seen: set[str] = set()
    for item in apps:
        package = str(item.get("package") or "")
        if not PACKAGE.fullmatch(package) or len(package) > 255:
            continue
        seen.add(package)
        row = rows.get(package)
        if row is None:
            row = MobileApp(device_id=device.id, tenant_id=device.tenant_id, package=package, first_seen=now)
            db.add(row)
            rows[package] = row
        risk = item.get("risk") if isinstance(item.get("risk"), dict) else {}
        row.label = str(item.get("label") or "")[:200]
        row.version = str(item.get("version") or "")[:100]
        row.installer = (str(item.get("installer"))[:255] if item.get("installer") else None)
        row.sideloaded, row.system = bool(item.get("sideloaded")), bool(item.get("system"))
        row.sha256, row.signer = _hex(item.get("sha256")), _hex(item.get("signer"))
        row.permissions = [str(p)[:100] for p in (item.get("permissions") or [])][:40]
        row.abilities = {k: bool(item.get(k)) for k in ("accessibility", "deviceAdmin", "notificationAccess", "hidden")}
        row.risk_level = str(risk.get("level") or "low") if str(risk.get("level") or "low") in LEVELS else "low"
        row.risk_score = max(0, min(100, int(risk.get("score") or 0)))
        row.reasons = [str(r)[:200] for r in (risk.get("reasons") or [])][:12]
        row.last_seen, row.removed_at = now, None
        before = row.verdict
        row.verdict, row.verdict_reason = verdict(db, device.tenant_id, row)
        row.verdict_reason = row.verdict_reason[:300]
        _alert(db, device, row, alert_on)
        if row.verdict == "malicious" and before != "malicious" and settings.get("suspendMalicious") \
                and (device.metrics or {}).get("deviceOwner") and not row.suspended:
            _suspend(db, device, row)
    if full:  # anything not in a full list has been removed
        for package, row in rows.items():
            if package not in seen and row.removed_at is None:
                row.removed_at = now
                _resolve(db, device, package, "The app was removed from the phone.")
    return {"apps": len(seen), "full": full}


def removed(db: Session, device: Device, fields: dict) -> None:
    package = str(fields.get("package") or "")
    row = db.execute(select(MobileApp).where(MobileApp.device_id == device.id, MobileApp.package == package)).scalars().first()
    if row is not None and row.removed_at is None:
        row.removed_at = utcnow()
    _resolve(db, device, package, "The app was removed from the phone.")


def reassess(db: Session, tenant_id: str | None, device: Device | None = None) -> int:
    """Re-run verdicts after threat intelligence changed (a trust, a new indicator)."""
    query = select(MobileApp).where(MobileApp.removed_at.is_(None))
    query = query.where(MobileApp.device_id == device.id) if device else (query.where(MobileApp.tenant_id == tenant_id) if tenant_id else query)
    changed = 0
    devices: dict[str, Device] = {}
    for row in db.execute(query).scalars():
        new, why = verdict(db, row.tenant_id, row)
        if new == row.verdict:
            continue
        row.verdict, row.verdict_reason = new, why[:300]
        target = devices.setdefault(row.device_id, db.get(Device, row.device_id))
        if target is not None:
            _alert(db, target, row, str(settings_for(db, target).get("alertOn") or "high"))
        changed += 1
    return changed


def on_command_complete(db: Session, device: Device, command) -> None:
    package = str((command.payload or {}).get("package") or "")
    row = db.execute(select(MobileApp).where(MobileApp.device_id == device.id, MobileApp.package == package)).scalars().first()
    if row is None or command.status != "completed":
        return
    if command.type == "app.suspend":
        row.suspended = bool((command.payload or {}).get("suspended", True))
    elif command.type == "app.uninstall" and (command.result or {}).get("removed"):
        row.removed_at = utcnow()
        _resolve(db, device, package, "The app was removed from the phone.")


def view(row: MobileApp) -> dict:
    iso = lambda d: d.isoformat() + "Z" if d else None  # noqa: E731
    return {"package": row.package, "label": row.label, "version": row.version, "installer": row.installer,
            "sideloaded": row.sideloaded, "system": row.system, "sha256": row.sha256, "signer": row.signer,
            "permissions": row.permissions, "abilities": row.abilities, "risk": {"score": row.risk_score, "level": row.risk_level,
                                                                                 "reasons": row.reasons},
            "verdict": row.verdict, "verdictReason": row.verdict_reason, "suspended": row.suspended,
            "firstSeen": iso(row.first_seen), "lastSeen": iso(row.last_seen), "removedAt": iso(row.removed_at)}
