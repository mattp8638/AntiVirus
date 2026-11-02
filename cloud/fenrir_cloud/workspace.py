"""The customer workspace (FLOW-09): everything a technician needs about one customer in one place, each part linked
to its module with the customer already chosen, so nothing is looked up or typed twice: open tickets, devices that
need attention, alerts and incidents, urgent vulnerabilities, Microsoft 365, backups, onboarding and recent actions."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import onboarding, presence, psa, vulnmgmt
from .models import Alert, AuditLog, Device, Incident, Tenant, Ticket, Vulnerability, utcnow

OPEN_ALERT = ("new", "triaged")
CLOSED_INCIDENT = ("resolved", "closed", "false_positive")


def _iso(value) -> str | None:
    return value.isoformat() + "Z" if value else None


def build(db: Session, tenant: Tenant) -> dict:
    tid, now = tenant.id, utcnow()
    tickets = [t for t in db.execute(select(Ticket).where(Ticket.account_tenant_id == tid).order_by(Ticket.created_at.desc())
                                     .limit(400)).scalars() if not psa.is_closed(db, t)]
    devices = [d for d in db.execute(select(Device).where(Device.tenant_id == tid, Device.approved.is_(True))).scalars()
               if d.api_key_hash != f"retired-{d.id}"]
    hosts = {d.id: d.hostname for d in devices}
    attention = []
    for device in devices:
        reasons = []
        if device.last_seen_at and now - device.last_seen_at > timedelta(days=7):
            reasons.append(f"not seen for {(now - device.last_seen_at).days} days")
        if device.health_state not in ("healthy", "unknown", None):
            reasons.append(f"agent health {device.health_state}")
        if device.isolated:
            reasons.append("isolated from the network")
        if (device.metrics or {}).get("rebootPending"):
            reasons.append("restart pending")
        if reasons:
            attention.append({"deviceId": device.id, "hostname": device.hostname, "reasons": reasons})
    alerts = db.execute(select(Alert).where(Alert.tenant_id == tid, Alert.status.in_(OPEN_ALERT))
                        .order_by(Alert.created_at.desc()).limit(200)).scalars().all()
    incidents = db.execute(select(Incident).where(Incident.tenant_id == tid, Incident.status.not_in(CLOSED_INCIDENT))
                           .order_by(Incident.created_at.desc()).limit(50)).scalars().all()
    vulns = db.execute(select(Vulnerability).where(Vulnerability.tenant_id == tid,
                                                   Vulnerability.status.in_(("open", "patching")))).scalars().all()
    by_priority: dict[str, int] = {}
    urgent = []
    for vuln in vulns:
        p = vulnmgmt.priority(vuln)
        by_priority[p] = by_priority.get(p, 0) + 1
        if p == "P1":
            urgent.append(vuln)
    urgent_cves: dict[str, dict] = {}
    for vuln in urgent:
        row = urgent_cves.setdefault(vuln.vuln_id, {"vulnId": vuln.vuln_id, "package": vuln.package, "devices": 0,
                                                    "knownExploited": bool(vuln.known_exploited), "ticketId": vuln.ticket_id})
        row["devices"] += 1
    recent = db.execute(select(AuditLog).where(AuditLog.tenant_id == tid).order_by(AuditLog.at.desc()).limit(25)).scalars().all()
    progress = onboarding.checklist(db, tenant)
    steps = {s["key"]: s for s in progress["steps"]}
    return {
        "tenantId": tid, "name": tenant.name,
        "tickets": {"open": len(tickets), "overdue": sum(1 for t in tickets if t.sla_due_at and t.sla_due_at < now),
                    "items": [{"id": t.id, "number": t.number, "subject": t.subject, "priority": t.priority, "status": t.status,
                               "assignee": t.assignee or None, "slaDueAt": _iso(t.sla_due_at),
                               "device": hosts.get(t.device_id) if t.device_id else None} for t in tickets[:12]]},
        "devices": {"total": len(devices), "online": sum(1 for d in devices if presence.is_up(d, now)),
                    "attention": attention[:15], "attentionCount": len(attention)},
        "alerts": {"open": len(alerts), "items": [{"id": a.id, "title": a.title, "severity": a.severity, "at": _iso(a.created_at),
                                                    "device": hosts.get(a.device_id)} for a in alerts[:8]]},
        "incidents": [{"id": i.id, "title": i.title, "severity": i.severity, "status": i.status, "at": _iso(i.created_at)} for i in incidents[:8]],
        "vulnerabilities": {"open": len(vulns), "byPriority": by_priority,
                            "urgent": sorted(urgent_cves.values(), key=lambda r: (-r["knownExploited"], -r["devices"]))[:8]},
        "microsoft365": steps.get("m365"), "backup": steps.get("backup"),
        "onboarding": {k: v for k, v in progress.items() if k in ("done", "total", "failed", "ready")},
        "recent": [{"at": _iso(r.at), "actor": r.actor, "action": r.action, "target": r.target} for r in recent],
    }

