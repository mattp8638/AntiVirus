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
    base = vuln.cvss if vuln.cvss is not None else SEVERITY_BASE.get(vuln.severity, 5.0)
    score = base * CRITICALITY_FACTOR.get(criticality or "medium", 1.0)
    if vuln.known_exploited:
        score = max(score, 9.0) + 1.5
    return round(min(score, 15.0), 1)


def recommendation(vuln: Vulnerability) -> str:
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


def verify_after_scan(db: Session, device: Device, scan_started: datetime) -> int:
    """After a complete rescan: anything not seen again is fixed (verified). Returns how many."""
    stale = db.execute(select(Vulnerability).where(Vulnerability.device_id == device.id, Vulnerability.last_seen < scan_started,
                                                   Vulnerability.status != "fixed")).scalars().all()
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
