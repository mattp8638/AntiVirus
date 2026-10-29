"""Vulnerability remediation workflow on top of the scanner in ``exposure.py``.

* Risk score: CVSS (or a severity default), raised for known-exploited (CISA KEV) issues and
  for business-critical assets.
* Remediation due dates by priority (KEV within 14 days, as CISA BOD 22-01 asks of US agencies).
* Verification: only a completed rescan that no longer finds a vulnerability marks it fixed.
* Risk acceptance needs a reason, an approver and an expiry; expired acceptances reopen.
* Events: ``vulnerability.detected`` and ``vulnerability.verified_fixed`` drive ticketing and
  compliance evidence through ``events.py``.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, events, services
from .models import Device, Ticket, Vulnerability, utcnow

# Exposure is still present in every state except a verified fix. Starting remediation ("patching"), a compensating
# control ("mitigated") or a signed-off exception ("accepted") are treatments, not fixes: posture, compliance and risk
# keep counting them, and show the treatment alongside.
UNRESOLVED = ("open", "patching", "mitigated", "accepted")

SEVERITY_BASE = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5}
CRITICALITY_FACTOR = {"low": 0.8, "medium": 1.0, "high": 1.2, "critical": 1.4}
DUE_DAYS = {"P1": 14, "P2": 15, "P3": 30, "P4": 90}
STATUSES = {"open", "patching", "mitigated", "accepted", "fixed"}
MAX_ACCEPTANCE_DAYS = 365


def priority(vuln: Vulnerability) -> str:
    if vuln.known_exploited:
        return "P1"
    return {"critical": "P2", "high": "P3"}.get(vuln.severity, "P4")


def risk_score(vuln: Vulnerability, criticality: str | None) -> float:
    """0-10: how urgently this vulnerability on this device needs fixing.

    CVSS (or the severity) says how bad it is; CISA KEV and FIRST EPSS say how likely it is to be used against
    us; the device's business criticality says how much it matters here.
    """
    score = vuln.cvss if vuln.cvss is not None else SEVERITY_BASE.get(vuln.severity, 5.0)
    epss = vuln.epss
    if vuln.known_exploited:
        score = max(score, 9.0) + 1.0
    elif epss is not None:
        if epss >= 0.5:
            score += 1.5
        elif epss >= 0.1:
            score += 0.75
        elif epss >= 0.01:
            score += 0.25
        else:
            score -= 1.0  # scored, and very unlikely to be exploited
    score *= CRITICALITY_FACTOR.get(criticality or "medium", 1.0)
    return round(max(0.0, min(score, 10.0)), 1)


def risk_reasons(vuln: Vulnerability) -> list[str]:
    reasons = []
    if vuln.known_exploited:
        reasons.append("exploited in the wild (CISA KEV)")
    if vuln.epss is not None:
        reasons.append(f"{vuln.epss * 100:.1f}% chance of exploitation in 30 days (EPSS)")
    if vuln.cvss is not None:
        reasons.append(f"CVSS {vuln.cvss}")
    return reasons


def recommendation(vuln: Vulnerability) -> str:
    fix = vuln.fix or {}
    if vuln.source == "nvd-cpe":
        text = fix.get("title") or f"Update {vuln.package}"
        if fix.get("patchKey"):
            text += f". The device already offers this update ({fix.get('available') or 'newer version'}): use Install fix"
        elif fix.get("winget"):
            text += f" (winget upgrade --id {fix['winget']})"
        return text + ". It is verified fixed once the device reports the new version."
    if vuln.source == "windows-update":
        return (f"Install Windows update {vuln.fixed_version} (approve it under Patching or run Install now). "
                "It is verified fixed at the next patch scan.")
    if vuln.fixed_version:
        return f"Update {vuln.package} from {vuln.installed_version or 'the installed version'} to {vuln.fixed_version} or later, then rescan."
    return f"No fixed version is published for {vuln.package}. Apply vendor mitigations or remove the package, then rescan."


def ensure_due_date(vuln: Vulnerability) -> None:
    if vuln.due_at is None and vuln.status in {"open", "patching"}:
        vuln.due_at = (vuln.first_seen or utcnow()) + timedelta(days=DUE_DAYS[priority(vuln)])


def set_status(db: Session, vuln: Vulnerability, status: str, actor: str, *, reason: str = "", expires_at: datetime | None = None) -> None:
    """Validated manual status change. Raises ValueError with a user-facing message."""
    if status not in STATUSES:
        raise ValueError("Unknown status")
    if status == "fixed":
        raise ValueError("A vulnerability is marked fixed only when a rescan no longer finds it. Set it to "
                         "'patching' and run a scan.")
    if status == "accepted":
        if not reason.strip():
            raise ValueError("Accepting a risk needs a reason")
        now = utcnow()
        if expires_at is None or expires_at <= now or expires_at > now + timedelta(days=MAX_ACCEPTANCE_DAYS):
            raise ValueError(f"Accepting a risk needs a review date within {MAX_ACCEPTANCE_DAYS} days")
        vuln.exception_reason, vuln.exception_approved_by, vuln.exception_expires_at = reason.strip()[:2000], actor, expires_at
    elif vuln.status == "accepted":
        vuln.exception_reason = vuln.exception_approved_by = None
        vuln.exception_expires_at = None
    vuln.status = status
    vuln.status_changed_at = utcnow()
    ensure_due_date(vuln)
    audit.record(db, actor, "vulnerability.status", f"{vuln.vuln_id}@{vuln.device_id}", vuln.tenant_id, status=status,
                 reason=reason[:500], expires=expires_at.isoformat() if expires_at else None)


def record_detection(db: Session, vuln: Vulnerability, reopened: bool) -> None:
    ensure_due_date(vuln)
    stamp = utcnow().strftime("%Y%m%d%H%M%S") if reopened else "first"
    events.publish(db, "vulnerability.detected", {"vulnerabilityId": vuln.id, "vulnId": vuln.vuln_id, "deviceId": vuln.device_id,
                                                  "severity": vuln.severity, "knownExploited": vuln.known_exploited,
                                                  "reopened": reopened},
                   tenant_id=vuln.tenant_id, key=f"vuln.detected:{vuln.device_id}:{vuln.vuln_id}:{vuln.package}:{stamp}")


def verify_after_scan(db: Session, device: Device, scan_started: datetime, source: str = "osv",
                      assessed: set[str] | None = None) -> int:
    """After a rescan by one source, mark what it did not see again as fixed (verified). Returns how many.

    ``assessed`` is the coverage the scan actually completed: the package names it got a full answer for. A finding
    is only verified when its package was assessed and not matched again, or when the package is no longer installed
    according to a software inventory newer than the finding. Anything outside that coverage (a failed or truncated
    response, a package the source cannot assess, a stale inventory) stays as it is. ``assessed=None`` is for sources
    whose scan always covers everything they report (the device's own Windows Update scan).
    """
    from .models import SoftwareItem

    stale = db.execute(select(Vulnerability).where(Vulnerability.device_id == device.id, Vulnerability.last_seen < scan_started,
                                                   Vulnerability.source == source,
                                                   Vulnerability.status != "fixed")).scalars().all()
    if assessed is not None and stale:
        inventory = {name: seen for name, seen in db.execute(select(SoftwareItem.name, SoftwareItem.seen_at)
                                                            .where(SoftwareItem.device_id == device.id)).all()}
        newest = max(inventory.values(), default=None)

        def covered(vuln: Vulnerability) -> bool:
            if vuln.package in assessed:
                return True
            # Removed software fixes its vulnerabilities, but only a fresh inventory can show it is gone.
            return vuln.package not in inventory and newest is not None and vuln.last_seen is not None and newest > vuln.last_seen

        stale = [v for v in stale if covered(v)]
    now = utcnow()
    for vuln in stale:
        vuln.status, vuln.verified_at, vuln.status_changed_at = "fixed", now, now
        vuln.exception_reason = vuln.exception_approved_by = None
        vuln.exception_expires_at = None
        audit.record(db, "system:rescan", "vulnerability.verified_fixed", f"{vuln.vuln_id}@{vuln.device_id}", vuln.tenant_id)
        events.publish(db, "vulnerability.verified_fixed", {"vulnerabilityId": vuln.id, "vulnId": vuln.vuln_id,
                                                            "deviceId": vuln.device_id, "ticketId": vuln.ticket_id,
                                                            "verifiedAt": now.isoformat()},
                       tenant_id=vuln.tenant_id, key=f"vuln.fixed:{vuln.id}:{now.isoformat()}")
    return len(stale)


def expire_acceptances(db: Session, now: datetime | None = None) -> int:
    now = now or utcnow()
    rows = db.execute(select(Vulnerability).where(Vulnerability.status == "accepted",
                                                  Vulnerability.exception_expires_at.is_not(None),
                                                  Vulnerability.exception_expires_at <= now)).scalars().all()
    for vuln in rows:
        vuln.status, vuln.status_changed_at = "open", now
        audit.record(db, "system", "vulnerability.acceptance_expired", f"{vuln.vuln_id}@{vuln.device_id}", vuln.tenant_id,
                     approvedBy=vuln.exception_approved_by)
    return len(rows)


def open_remediation_ticket(db: Session, vulns: list[Vulnerability], actor: str) -> Ticket:
    """One ticket for one CVE across the given devices of a tenant; links every row to it."""
    first = vulns[0]
    hosts = dict(db.execute(select(Device.id, Device.hostname).where(Device.id.in_({v.device_id for v in vulns}))).all())
    lines = [f"- {hosts.get(v.device_id, v.device_id)}: {v.package} {v.installed_version}" for v in vulns]
    description = (f"{first.vuln_id} ({first.severity}{', known exploited' if first.known_exploited else ''}, CVSS {first.cvss or 'n/a'})\n\n"
                   f"{first.summary[:1000]}\n\nAffected:\n" + "\n".join(lines) + f"\n\nRecommendation: {recommendation(first)}\n\n"
                   "The ticket is updated automatically when a rescan confirms the fix.")
    ticket = services.open_ticket(db, first.tenant_id, f"Remediate {first.vuln_id} on {len(vulns)} device(s)", description,
                                  priority=priority(first), source="vulnerability", requester=actor,
                                  device_id=first.device_id if len(vulns) == 1 else None)
    for vuln in vulns:
        vuln.ticket_id = ticket.id
        if vuln.status == "open":
            vuln.status, vuln.status_changed_at = "patching", utcnow()
        ensure_due_date(vuln)
    audit.record(db, actor, "vulnerability.ticket_opened", first.vuln_id, first.tenant_id, ticket=ticket.number, devices=len(vulns))
    return ticket


# --------------------------------------------------------------------------- event handlers


@events.handler("vulnerability.detected", name="vulnmgmt.auto_ticket")
def _auto_ticket(db: Session, event) -> None:
    """Tenants with settings.vulnerabilityAutoTicket = "kev" | "critical" get tickets automatically."""
    from .models import Tenant

    vuln = db.get(Vulnerability, event.payload.get("vulnerabilityId"))
    if vuln is None or vuln.ticket_id or vuln.status not in {"open", "patching"}:
        return
    tenant = db.get(Tenant, vuln.tenant_id)
    mode = ((tenant.settings or {}) if tenant else {}).get("vulnerabilityAutoTicket", "off")
    if mode == "kev" and not vuln.known_exploited:
        return
    if mode == "critical" and not (vuln.known_exploited or vuln.severity == "critical"):
        return
    if mode not in {"kev", "critical"}:
        return
    siblings = db.execute(select(Vulnerability).where(Vulnerability.tenant_id == vuln.tenant_id, Vulnerability.vuln_id == vuln.vuln_id,
                                                      Vulnerability.ticket_id.is_not(None))).scalars().first()
    if siblings is not None:
        vuln.ticket_id = siblings.ticket_id  # one ticket per CVE per customer
        return
    open_remediation_ticket(db, [vuln], "system:auto-ticket")


@events.handler("vulnerability.verified_fixed", name="vulnmgmt.update_ticket")
def _update_ticket(db: Session, event) -> None:
    from . import psa

    ticket_id = event.payload.get("ticketId")
    ticket = db.get(Ticket, ticket_id) if ticket_id else None
    if ticket is None:
        return
    marker = f"verified:{event.payload.get('vulnerabilityId')}"
    if marker in (ticket.workflow_fired or []):
        return
    host = db.execute(select(Device.hostname).where(Device.id == event.payload.get("deviceId"))).scalar() or event.payload.get("deviceId")
    psa.add_note(db, ticket, "system:rescan", f"Rescan confirmed {event.payload.get('vulnId')} is no longer present on {host}.", kind="internal")
    ticket.workflow_fired = (ticket.workflow_fired or []) + [marker]
    remaining = db.execute(select(Vulnerability).where(Vulnerability.ticket_id == ticket.id, Vulnerability.status != "fixed")).scalars().first()
    if remaining is None and not psa.is_closed(db, ticket):
        psa.set_status(db, ticket, "Resolved", "system:rescan")



# ---------------------------------------------------------------------------
# Automated "Cyber Heal" Zero-Interaction Remediation Engine
# ---------------------------------------------------------------------------


def cyber_heal_remediate(db: Session, vuln_id: int) -> dict:
    """Automated "Cyber Heal" zero-interaction remediation.

    Generates and queues silent force-patch / mitigation commands for identified
    vulnerabilities. For applications, it utilizes package managers (e.g.
    winget upgrade --id <AppID> --silent). For OS vulnerabilities, it executes
    PowerShell hardening scripts.
    """
    vuln = db.get(Vulnerability, vuln_id)
    if vuln is None or vuln.status not in UNRESOLVED:
        return {"status": "skipped", "reason": "vulnerability not found or already fixed"}

    device = db.get(Device, vuln.device_id)
    if device is None:
        return {"status": "failed", "reason": "device not found"}

    fix = vuln.fix or {}
    fix_type = fix.get("kind", "")
    pkg_id = fix.get("ref") or vuln.package

    if device.platform == "windows":
        if fix_type == "winget" or pkg_id:
            script_body = f"winget upgrade --id '{pkg_id}' --silent --accept-package-agreements --accept-source-agreements"
            cmd_type = "script.run"
            payload = {"language": "powershell", "body": script_body}
        else:
            script_body = """
            Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -ErrorAction SilentlyContinue
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
            """
            cmd_type = "script.run"
            payload = {"language": "powershell", "body": script_body}
    else:
        script_body = f"apt-get update && apt-get install --only-upgrade -y '{pkg_id}' || yum update -y '{pkg_id}'"
        cmd_type = "script.run"
        payload = {"language": "bash", "body": script_body}

    from .models import Command
    cmd = Command(
        tenant_id=vuln.tenant_id,
        device_id=vuln.device_id,
        type=cmd_type,
        status="pending",
        issued_by="system:cyber-heal",
        payload=payload,
        reason=f"Cyber Heal automated remediation for {vuln.vuln_id}",
    )
    db.add(cmd)
    vuln.status = "patching"
    vuln.status_changed_at = utcnow()
    audit.record(
        db,
        "system:cyber-heal",
        "vulnerability.cyber_heal_triggered",
        str(vuln.id),
        vuln.tenant_id,
        cve=vuln.vuln_id,
        package=vuln.package,
    )
    return {"status": "queued", "commandId": cmd.id, "vulnerabilityId": vuln.id}
