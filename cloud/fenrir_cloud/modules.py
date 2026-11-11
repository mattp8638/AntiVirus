"""Which parts of Fenrir the console shows: a short core menu plus the modules an MSP switches on (Settings > Modules).

New installations start with ``ESSENTIALS`` (the everyday RMM, service desk, protection and vulnerabilities), so the
menu stays short; existing installations keep everything on until someone changes it. Switching a module off hides its
pages from the menu and search; it does not delete data or stop background work, and its pages still open by link.
Kept on the MSP's root tenant (``Tenant.settings["modules"]``); customers' users see their MSP's choice.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

MODULES = {
    "service": ("Service desk", "Tickets, dispatch, workload and time"),
    "protection": ("Protection", "Antivirus and EDR policies, protection health, quarantine"),
    "vulnerabilities": ("Vulnerabilities", "Vulnerability scanning and remediation"),
    "security": ("Security operations", "Incidents, threat hunting, intel, detection and response rules, DNS protection, admin requests"),
    "documentation": ("Documentation", "Knowledge base, configurations and the credential vault"),
    "identity": ("Microsoft 365 and identity", "Microsoft 365, Active Directory, data and identity exposure"),
    "network": ("Network", "Network topology, attack surface and out-of-band (Intel AMT)"),
    "backup": ("Backup", "Backup oversight and recovery tests"),
    "business": ("Business", "CRM, onboarding, quotes, agreements and billing"),
    "care": ("Care", "Looked-after people's phones: safe zones and alerts"),
    "governance": ("Compliance and GRC", "Frameworks, policies, risks and evidence"),
}
ESSENTIALS = ["service", "protection", "vulnerabilities"]


def enabled(db: Session, tenant_id: str | None) -> list[str]:
    from . import branding
    from .config import get_settings

    if get_settings().demo_mode:
        return list(MODULES)  # a public demo shows everything (and nobody can change it there)

    msp = branding.msp_of(db, tenant_id) if tenant_id else branding.default_msp(db)
    stored = (msp.settings or {}).get("modules") if msp is not None else None
    if not isinstance(stored, list):
        return list(MODULES)  # never chosen: an existing installation keeps everything
    return [m for m in MODULES if m in stored]


def validate(value) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(m, str) for m in value):
        raise ValueError("Send the list of modules to show")
    unknown = sorted(set(value) - set(MODULES))
    if unknown:
        raise ValueError(f"Unknown module(s): {', '.join(unknown)}")
    return [m for m in MODULES if m in value]
