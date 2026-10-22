"""Continuous compliance scoring against common frameworks.

Each control maps to checks over the tenant's effective policy and live fleet
state. Scores are evidence-backed: every result says what was checked.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import policy_schema, services
from .models import Device, Tenant, Vulnerability, utcnow


@dataclass
class Context:
    settings: dict
    devices: int
    online: int
    stale: int
    outdated_agents: int
    critical_vulns: int
    kev_vulns: int
    isolated: int


Check = Callable[[Context], tuple[bool, str]]


def _s(path: str) -> Check:
    section, key = path.split(".")
    spec = policy_schema.FIELDS[path]

    def check(ctx: Context) -> tuple[bool, str]:
        value = ctx.settings[section][key]
        ok = value not in (False, "off", "none", "allow", "audit") if spec.kind in {"bool", "enum"} else bool(value)
        return ok, f"{spec.label}: {value}"

    return check


def _fleet_reporting(ctx: Context) -> tuple[bool, str]:
    if ctx.devices == 0:
        return False, "No devices enrolled"
    ratio = (ctx.devices - ctx.stale) / ctx.devices
    return ratio >= 0.95, f"{ctx.devices - ctx.stale}/{ctx.devices} devices reported in the last 7 days"


def _no_kev(ctx: Context) -> tuple[bool, str]:
    return ctx.kev_vulns == 0, f"{ctx.kev_vulns} known-exploited vulnerabilities open"


def _no_critical(ctx: Context) -> tuple[bool, str]:
    return ctx.critical_vulns == 0, f"{ctx.critical_vulns} critical vulnerabilities open"


def _patch_auto(ctx: Context) -> tuple[bool, str]:
    patch = ctx.settings["patch"]
    ok = patch["enabled"] and patch["autoApprove"] in {"critical", "security", "all"} and patch["deferralDaysCritical"] <= 14
    return ok, f"auto-approve={patch['autoApprove']}, critical deferral={patch['deferralDaysCritical']}d"


def _asr_majority(ctx: Context) -> tuple[bool, str]:
    rules = ctx.settings["attackSurface"]
    blocking = sum(1 for value in rules.values() if value == "block")
    return blocking >= len(rules) * 0.7, f"{blocking}/{len(rules)} attack surface rules blocking"


def _usb(ctx: Context) -> tuple[bool, str]:
    mode = ctx.settings["deviceControl"]["usbStorage"]
    return mode in {"read-only", "block", "audit"} or ctx.settings["antimalware"]["scanRemovableMedia"], f"USB storage: {mode}"


def _app_control(ctx: Context) -> tuple[bool, str]:
    mode = ctx.settings["applicationControl"]["mode"]
    return mode.startswith("enforce"), f"Application control: {mode}"


def _least_privilege(ctx: Context) -> tuple[bool, str]:
    priv = ctx.settings["privilege"]
    return priv["enabled"] and priv["removeLocalAdmins"], f"PAM enabled={priv['enabled']}, remove admins={priv['removeLocalAdmins']}"


def _agents_current(ctx: Context) -> tuple[bool, str]:
    return ctx.outdated_agents == 0, f"{ctx.outdated_agents} devices on an outdated agent"


FRAMEWORKS: dict[str, dict] = {
    "cyber-essentials": {
        "name": "UK Cyber Essentials (v3.1)",
        "controls": [
            ("CE-1", "Firewalls", [_s("firewall.enabled"), _s("firewall.defaultInbound")]),
            ("CE-2", "Secure configuration", [_asr_majority, _s("tamper.enabled")]),
            ("CE-3", "User access control", [_least_privilege]),
            ("CE-4", "Malware protection", [_s("antimalware.realtimeProtection"), _s("web.webProtectionEnabled"), _fleet_reporting]),
            ("CE-5", "Security update management", [_patch_auto, _no_critical]),
        ],
    },
    "cis-v8-ig1": {
        "name": "CIS Controls v8 (IG1)",
        "controls": [
            ("CIS-1", "Inventory of enterprise assets", [_fleet_reporting]),
            ("CIS-2", "Inventory and control of software", [_app_control]),
            ("CIS-4", "Secure configuration", [_asr_majority, _s("firewall.enabled")]),
            ("CIS-5", "Account management", [_least_privilege]),
            ("CIS-7", "Continuous vulnerability management", [_patch_auto, _no_kev]),
            ("CIS-8", "Audit log management", [_s("edr.enabled"), _s("edr.collectProcessEvents")]),
            ("CIS-9", "Email and web browser protections", [_s("web.antiPhishingEnabled"), _s("dns.enabled")]),
            ("CIS-10", "Malware defenses", [_s("antimalware.realtimeProtection"), _s("antimalware.cloudLookup"), _usb]),
            ("CIS-11", "Data recovery", [_s("ransomware.rollbackSnapshots")]),
            ("CIS-17", "Incident response management", [_s("response.autoOpenTicket")]),
        ],
    },
    "nist-csf-2": {
        "name": "NIST Cybersecurity Framework 2.0",
        "controls": [
            ("ID.AM", "Asset management", [_fleet_reporting]),
            ("ID.RA", "Risk assessment", [_no_kev, _no_critical]),
            ("PR.AA", "Identity and access control", [_least_privilege]),
            ("PR.PS", "Platform security", [_patch_auto, _asr_majority, _s("tamper.enabled"), _agents_current]),
            ("PR.DS", "Data security", [_usb, _s("ransomware.enabled")]),
            ("DE.CM", "Continuous monitoring", [_s("edr.enabled"), _s("dns.enabled"), _s("firewall.networkAttackProtection")]),
            ("RS.MI", "Incident mitigation", [_s("response.autoKillOnHigh"), _s("firewall.networkContainment")]),
            ("RC.RP", "Recovery plan execution", [_s("ransomware.rollbackSnapshots")]),
        ],
    },
    "essential-eight": {
        "name": "ACSC Essential Eight (Maturity Level 1)",
        "controls": [
            ("E8-1", "Application control", [_app_control]),
            ("E8-2", "Patch applications", [_patch_auto, _s("patch.thirdPartyApps")]),
            ("E8-3", "Configure Office macro settings", [_s("attackSurface.blockOfficeChildProcesses")]),
            ("E8-4", "User application hardening", [_s("attackSurface.blockScriptDownloadedPayloads"), _s("web.webProtectionEnabled")]),
            ("E8-5", "Restrict administrative privileges", [_least_privilege]),
            ("E8-6", "Patch operating systems", [_patch_auto, _no_kev]),
            ("E8-8", "Regular backups", [_s("ransomware.rollbackSnapshots")]),
        ],
    },
    "iso-27001": {
        "name": "ISO/IEC 27001:2022 Annex A (technical)",
        "controls": [
            ("A.8.1", "User endpoint devices", [_s("antimalware.realtimeProtection"), _s("tamper.enabled")]),
            ("A.8.2", "Privileged access rights", [_least_privilege]),
            ("A.8.7", "Protection against malware", [_s("antimalware.realtimeProtection"), _s("ransomware.enabled")]),
            ("A.8.8", "Management of technical vulnerabilities", [_patch_auto, _no_kev]),
            ("A.8.12", "Data leakage prevention", [_usb]),
            ("A.8.15", "Logging", [_s("edr.enabled")]),
            ("A.8.16", "Monitoring activities", [_s("edr.enabled"), _fleet_reporting]),
            ("A.8.20", "Network security", [_s("firewall.enabled"), _s("firewall.networkAttackProtection")]),
            ("A.8.23", "Web filtering", [_s("dns.enabled"), _s("web.webProtectionEnabled")]),
        ],
    },
}


def _context(db: Session, tenant: Tenant) -> Context:
    resolution = policy_schema.resolve(services.policy_layers(db, tenant))
    week_ago = utcnow() - timedelta(days=7)
    devices = db.execute(select(Device).where(Device.tenant_id == tenant.id)).scalars().all()
    versions = sorted({d.agent_version for d in devices if d.agent_version})
    newest = versions[-1] if versions else ""
    crit = db.execute(select(func.count()).where(Vulnerability.tenant_id == tenant.id, Vulnerability.status == "open",
                                                 Vulnerability.severity == "critical")).scalar() or 0
    kev = db.execute(select(func.count()).where(Vulnerability.tenant_id == tenant.id, Vulnerability.status == "open",
                                                Vulnerability.known_exploited.is_(True))).scalar() or 0
    return Context(
        settings=resolution["settings"], devices=len(devices),
        online=sum(1 for d in devices if d.last_seen_at and d.last_seen_at >= utcnow() - timedelta(minutes=15)),
        stale=sum(1 for d in devices if not d.last_seen_at or d.last_seen_at < week_ago),
        outdated_agents=sum(1 for d in devices if d.agent_version and d.agent_version != newest),
        critical_vulns=crit, kev_vulns=kev, isolated=sum(1 for d in devices if d.isolated),
    )


def evaluate(db: Session, tenant: Tenant, framework: str | None = None) -> list[dict]:
    ctx = _context(db, tenant)
    out = []
    for key, framework_def in FRAMEWORKS.items():
        if framework and key != framework:
            continue
        controls = []
        passed = 0
        for control_id, title, checks in framework_def["controls"]:
            results = [check(ctx) for check in checks]
            ok = all(r[0] for r in results)
            passed += ok
            controls.append({"id": control_id, "title": title, "passed": ok, "evidence": [r[1] for r in results]})
        out.append({"framework": key, "name": framework_def["name"], "score": round(100 * passed / len(controls)),
                    "passed": passed, "total": len(controls), "controls": controls})
    return out
