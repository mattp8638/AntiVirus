"""Endpoint baselines: hardening standards checked on every device and, in enforce mode, put right automatically.

A baseline is a set of condition packages (detection + remediation scripts from condition_remediation.BUILTIN) and the
Fenrir policy settings it expects. Assigning one to a customer enables its packages there: in ``audit`` mode they only
detect; in ``enforce`` mode drift is remediated silently, verified, and a ticket opens if the fix does not hold.
Results feed the compliance signals (``baseline:<common control>``) and so the automated evidence.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, condition_remediation as engine, policy_schema, services
from .models import ConditionPackage, ConditionResult, Device, Tenant, utcnow

BASELINES: dict[str, dict] = {
    "windows-workstation": {
        "name": "Windows endpoint baseline",
        "description": "Cyber Essentials and CIS IG1 hardening for Windows workstations and servers: firewall on, SMBv1, LLMNR, "
                       "PowerShell 2.0 and AutoRun off, Guest disabled, Remote Desktop with NLA, a 15-minute lock, BitLocker "
                       "reported, and Windows Update working.",
        "platforms": ["windows"],
        "packages": ["win-firewall", "win-smb1", "win-llmnr", "win-ps2", "win-autorun", "win-guest", "win-rdp-nla", "win-screenlock",
                     "win-bitlocker", "win-wuauserv"],
        "policy": {"antimalware.realtimeProtection": True, "tamper.enabled": True, "firewall.enabled": True,
                   "web.webProtectionEnabled": True},
    },
    "linux-server": {
        "name": "Linux server baseline",
        "description": "SSH root password login off, a host firewall active, time synchronised and disk space healthy.",
        "platforms": ["linux"],
        "packages": ["linux-ssh-root", "linux-firewall", "linux-ntp", "linux-disk"],
        "policy": {"antimalware.realtimeProtection": True},
    },
    "macos-workstation": {
        "name": "macOS endpoint baseline",
        "description": "FileVault reported, Gatekeeper and the application firewall on.",
        "platforms": ["macos"],
        "packages": ["mac-filevault", "mac-gatekeeper", "mac-firewall"],
        "policy": {"antimalware.realtimeProtection": True, "tamper.enabled": True},
    },
}
GOOD, BAD = ("compliant", "remediated"), ("noncompliant", "failed")


def package_control(builtin_key: str | None) -> str | None:
    return next((b.get("control") for b in engine.BUILTIN if b["key"] == builtin_key), None)


def catalogue() -> list[dict]:
    names = {b["key"]: b["name"] for b in engine.BUILTIN}
    return [{"key": key, "name": b["name"], "description": b["description"], "platforms": b["platforms"],
             "items": [{"package": k, "name": names.get(k, k), "control": package_control(k)} for k in b["packages"]],
             "policy": [{"path": path, "expected": value, "label": policy_schema.FIELDS[path].label if path in policy_schema.FIELDS else path}
                        for path, value in b["policy"].items()]}
            for key, b in BASELINES.items()]


def assigned(tenant: Tenant) -> dict:
    return dict((tenant.settings or {}).get("baselines") or {})


def assign(db: Session, tenant: Tenant, key: str, mode: str, actor: str) -> dict:
    if key not in BASELINES:
        raise KeyError(key)
    if mode not in ("audit", "enforce"):
        raise ValueError("mode must be audit or enforce")
    engine.seed(db)
    db.flush()
    enforce = mode == "enforce"
    for package_key in BASELINES[key]["packages"]:
        copy = db.execute(select(ConditionPackage).where(ConditionPackage.tenant_id == tenant.id,
                                                         ConditionPackage.builtin_key == package_key)).scalars().first()
        if copy is None:
            template = db.execute(select(ConditionPackage).where(ConditionPackage.tenant_id.is_(None),
                                                                 ConditionPackage.builtin_key == package_key)).scalars().first()
            if template is None:
                continue
            copy = engine.enable_for(db, template, tenant.id, actor)
        copy.enabled, copy.auto_remediate, copy.ticket_on_failure = True, enforce, True
    record = {"mode": mode, "assignedBy": actor, "assignedAt": utcnow().isoformat() + "Z"}
    tenant.settings = {**(tenant.settings or {}), "baselines": {**assigned(tenant), key: record}}
    audit.record(db, actor, "grc.baseline.assigned", BASELINES[key]["name"], tenant.id, baseline=key, mode=mode)
    return record


def unassign(db: Session, tenant: Tenant, key: str, actor: str) -> None:
    current = assigned(tenant)
    if key not in current:
        return
    still_needed = {p for other in current if other != key for p in BASELINES.get(other, {}).get("packages", [])}
    for package_key in BASELINES[key]["packages"]:
        if package_key in still_needed:
            continue
        for copy in db.execute(select(ConditionPackage).where(ConditionPackage.tenant_id == tenant.id,
                                                              ConditionPackage.builtin_key == package_key)).scalars():
            copy.enabled = False
    current.pop(key)
    tenant.settings = {**(tenant.settings or {}), "baselines": current}
    audit.record(db, actor, "grc.baseline.removed", BASELINES[key]["name"], tenant.id, baseline=key)


def report(db: Session, tenant: Tenant) -> list[dict]:
    """Per assigned baseline: each device's result for each item, the policy settings, and overall compliance."""
    current = assigned(tenant)
    if not current:
        return []
    settings = policy_schema.resolve(services.policy_layers(db, tenant))["settings"]
    packages = {p.builtin_key: p for p in db.execute(select(ConditionPackage).where(ConditionPackage.tenant_id == tenant.id)).scalars()}
    results: dict[str, dict[str, ConditionResult]] = {}
    for r in db.execute(select(ConditionResult).where(ConditionResult.tenant_id == tenant.id)).scalars():
        results.setdefault(r.package_id, {})[r.device_id] = r
    out = []
    for key, record in current.items():
        baseline = BASELINES.get(key)
        if baseline is None:
            continue
        devices = db.execute(select(Device).where(Device.tenant_id == tenant.id, Device.approved.is_(True),
                                                  Device.platform.in_(baseline["platforms"])).order_by(Device.hostname)).scalars().all()
        rows, compliant_devices = [], 0
        for device in devices:
            items = {}
            for package_key in baseline["packages"]:
                package = packages.get(package_key)
                result = results.get(package.id, {}).get(device.id) if package else None
                items[package_key] = result.status if result else "pending"
            known = [s for s in items.values() if s != "pending"]
            ok = bool(known) and all(s in GOOD for s in known)
            compliant_devices += ok
            rows.append({"deviceId": device.id, "hostname": device.hostname, "items": items, "compliant": ok,
                         "failing": sum(1 for s in items.values() if s in BAD)})
        policy = []
        for path, expected in baseline["policy"].items():
            section, field = path.split(".", 1)
            actual = (settings.get(section) or {}).get(field)
            policy.append({"path": path, "expected": expected, "actual": actual, "passed": actual == expected})
        out.append({"key": key, "name": baseline["name"], "mode": record.get("mode"), "assignedAt": record.get("assignedAt"),
                    "devices": rows, "policy": policy, "deviceCount": len(devices), "compliantDevices": compliant_devices,
                    "compliance": round(100 * compliant_devices / len(devices)) if devices else None,
                    "policyCompliant": all(p["passed"] for p in policy)})
    return out


def signal(db: Session, tenant: Tenant, control_id: str) -> dict:
    """Live signal for one common control from the baseline checks tagged with it."""
    keys = {b["key"] for b in engine.BUILTIN if b.get("control") == control_id}
    packages = db.execute(select(ConditionPackage).where(ConditionPackage.tenant_id == tenant.id, ConditionPackage.enabled.is_(True),
                                                         ConditionPackage.builtin_key.in_(keys))).scalars().all() if keys else []
    if not packages:
        return {"passed": None, "evidence": ["No endpoint baseline check for this control is enabled"]}
    evidence, ok = [], True
    seen = False
    for package in packages:
        rows = db.execute(select(ConditionResult).where(ConditionResult.package_id == package.id)).scalars().all()
        good = sum(1 for r in rows if r.status in GOOD)
        bad = sum(1 for r in rows if r.status in BAD)
        if good + bad == 0:
            continue
        seen = True
        ok &= bad == 0
        evidence.append(f"{package.name}: {good} of {good + bad} devices compliant")
    if not seen:
        return {"passed": None, "evidence": ["Baseline checks have not reported yet"]}
    return {"passed": ok, "evidence": evidence}
