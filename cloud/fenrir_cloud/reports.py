"""Customer reports: what each one contains, as a structured document (report_render), branded with the MSP's brand.

Kinds:
    executive      security and service summary for a period (7, 30 or 90 days), with recommended next steps
    monthly        "what we did for you" last month (or a given month) and where the customer's health stands
    quarterly      quarterly business review: health and its trend, the work done, and what to do next
    vulnerability  technical: every open vulnerability by risk, ageing, overdue fixes, accepted risks, worst devices

Each is available as HTML and PDF, can be kept as sent (client_reports), and emailed on a schedule (schedules.py-style
settings on the customer: ``Tenant.settings["reportSchedules"]``, see send_schedules).
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import branding, compliance, report_render
from .models import (Alert, Device, DnsQueryLog, Event, Incident, Tenant, Ticket, TimeEntry, Vulnerability, utcnow)

KINDS = {
    "executive": "Executive summary: protection delivered, risk outstanding, compliance and service levels",
    "monthly": "What we did for you: last month's work and your IT health",
    "quarterly": "Quarterly business review: health trend, work done and recommended next steps",
    "vulnerability": "Vulnerability report: every open vulnerability by risk, with ageing and overdue fixes",
}
SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_STATUS = {"critical": "bad", "high": "bad", "medium": "warn", "low": "none"}


# --------------------------------------------------------------------------- executive data


def _hours(deltas: list[timedelta]) -> float | None:
    return round(sum(d.total_seconds() for d in deltas) / 3600 / len(deltas), 1) if deltas else None


def service_summary(db: Session, tenant: Tenant, tickets: list[Ticket], since) -> dict:
    """Service-desk section of the customer report: volume, SLA, speed, effort and change activity."""
    resolved = [t for t in tickets if t.resolved_at]
    within_sla = [t for t in resolved if t.sla_due_at and t.resolved_at <= t.sla_due_at]
    by_priority = {}
    for priority in ("P1", "P2", "P3", "P4"):
        group = [t for t in tickets if t.priority == priority]
        done = [t for t in group if t.resolved_at]
        met = [t for t in done if t.sla_due_at and t.resolved_at <= t.sla_due_at]
        if group:
            by_priority[priority] = {"tickets": len(group), "resolved": len(done),
                                     "slaMet": round(100 * len(met) / len(done)) if done else None}
    hours = db.execute(select(func.sum(TimeEntry.hours)).where(TimeEntry.account_tenant_id == tenant.id,
                                                               TimeEntry.started_at >= since)).scalar() or 0
    changes = db.execute(select(Ticket).where(Ticket.account_tenant_id == tenant.id, Ticket.record_type == "change",
                                              Ticket.updated_at >= since)).scalars().all()
    open_now = db.execute(select(func.count()).select_from(Ticket).where(
        Ticket.account_tenant_id == tenant.id, Ticket.resolved_at.is_(None))).scalar() or 0
    return {
        "tickets": len(tickets), "resolved": len(resolved), "openNow": open_now,
        "slaMet": round(100 * len(within_sla) / len(resolved)) if resolved else None,
        "byPriority": by_priority,
        "avgFirstResponseHours": _hours([t.responded_at - t.created_at for t in tickets if t.responded_at]),
        "avgResolutionHours": _hours([t.resolved_at - t.created_at for t in resolved]),
        "hoursWorked": round(hours, 1),
        "topCategories": [{"name": name, "tickets": count} for name, count in
                          Counter(t.type or t.queue or "General" for t in tickets).most_common(5)],
        "changesImplemented": sum(1 for c in changes if c.change_state in ("Implemented", "Closed")),
        "changesFailed": sum(1 for c in changes if c.change_state == "Failed"),
        "problemsOpen": db.execute(select(func.count()).select_from(Ticket).where(
            Ticket.account_tenant_id == tenant.id, Ticket.record_type == "problem", Ticket.resolved_at.is_(None))).scalar() or 0,
    }


def executive_data(db: Session, tenant: Tenant, days: int) -> dict:
    """The executive report's figures (also served as JSON at /api/console/reports/executive)."""
    from . import rmm
    from .vulnmgmt import UNRESOLVED

    since = utcnow() - timedelta(days=days)
    devices = db.execute(select(Device).where(Device.tenant_id == tenant.id)).scalars().all()
    alerts = dict(db.execute(select(Alert.severity, func.count()).where(Alert.tenant_id == tenant.id, Alert.created_at >= since)
                             .group_by(Alert.severity)).all())
    incidents = db.execute(select(Incident).where(Incident.tenant_id == tenant.id, Incident.created_at >= since)).scalars().all()
    threats = db.execute(select(func.count()).where(Event.tenant_id == tenant.id, Event.occurred_at >= since,
                                                    Event.category == "malware")).scalar() or 0
    dns_blocked = db.execute(select(func.count()).where(DnsQueryLog.tenant_id == tenant.id, DnsQueryLog.at >= since,
                                                        DnsQueryLog.action == "block")).scalar() or 0
    vulns = dict(db.execute(select(Vulnerability.severity, func.count()).where(Vulnerability.tenant_id == tenant.id,
                                                                               Vulnerability.status.in_(UNRESOLVED))
                            .group_by(Vulnerability.severity)).all())
    treatment = dict(db.execute(select(Vulnerability.status, func.count()).where(Vulnerability.tenant_id == tenant.id,
                                                                                 Vulnerability.status.in_(UNRESOLVED))
                                .group_by(Vulnerability.status)).all())
    actionable = dict(db.execute(select(Vulnerability.severity, func.count()).where(
        Vulnerability.tenant_id == tenant.id, Vulnerability.status.in_(UNRESOLVED), Vulnerability.status != "accepted")
        .group_by(Vulnerability.severity)).all())
    exploited = db.execute(select(func.count()).select_from(Vulnerability).where(
        Vulnerability.tenant_id == tenant.id, Vulnerability.status.in_(UNRESOLVED), Vulnerability.status != "accepted",
        Vulnerability.known_exploited.is_(True))).scalar() or 0
    frameworks = compliance.evaluate(db, tenant)
    tickets = db.execute(select(Ticket).where(Ticket.account_tenant_id == tenant.id, Ticket.created_at >= since)).scalars().all()
    patches = rmm.patch_compliance(db, [tenant.id])
    return {
        "tenant": tenant.name, "periodDays": days, "generatedAt": utcnow().isoformat() + "Z",
        "devices": {"total": len(devices), "isolatedNow": sum(d.isolated for d in devices),
                    "highRisk": sum(1 for d in devices if d.risk_score >= 40)},
        "alerts": alerts, "incidents": {"total": len(incidents), "resolved": sum(i.status in ("resolved", "closed") for i in incidents)},
        "threatEvents": threats, "dnsBlocked": dns_blocked, "openVulnerabilities": vulns, "vulnerabilityTreatment": treatment,
        "knownExploited": exploited, "actionableVulnerabilities": actionable,
        "patching": {k: patches[k] for k in ("devices", "scanned", "fullyPatched", "missingCriticalOrSecurity", "pendingReboot",
                                             "failedPatches", "compliancePercent")},
        "compliance": [{"name": f["name"], "score": f["score"]} for f in frameworks],
        "service": service_summary(db, tenant, tickets, since),
    }


def recommendations(data: dict, health: dict | None = None) -> list[str]:
    """Plain next steps from the figures, most important first."""
    out: list[str] = []
    vulns = data.get("actionableVulnerabilities", data.get("openVulnerabilities")) or {}  # accepted risks need no fix
    critical, high, exploited = vulns.get("critical", 0), vulns.get("high", 0), data.get("knownExploited", 0)
    if exploited:
        out.append(f"Fix the {exploited} vulnerabilit{'y' if exploited == 1 else 'ies'} known to be exploited by attackers first.")
    if critical or high:
        out.append(f"Remediate {critical} critical and {high} high-severity vulnerabilities.")
    patching = data.get("patching") or {}
    if patching.get("missingCriticalOrSecurity"):
        n = patching["missingCriticalOrSecurity"]
        out.append(f"Install the outstanding security updates on {n} device{'s' if n != 1 else ''}.")
    if patching.get("pendingReboot"):
        n = patching["pendingReboot"]
        out.append(f"Restart {n} device{'s' if n != 1 else ''} to finish installing updates.")
    if (data.get("devices") or {}).get("highRisk"):
        n = data["devices"]["highRisk"]
        out.append(f"Review the {n} high-risk device{'s' if n != 1 else ''} with your account manager.")
    for framework in data.get("compliance") or []:
        if framework["score"] < 70:
            out.append(f"Raise {framework['name']} compliance (now {framework['score']}%).")
    sla = (data.get("service") or {}).get("slaMet")
    if sla is not None and sla < 90:
        out.append(f"Agree how to bring service-desk SLA performance ({sla}%) back above 90%.")
    for part in sorted((p for p in (health or {}).get("parts", []) if p["score"] is not None and p["status"] != "good"),
                       key=lambda p: p["score"]):
        line = f"{part['label']}: {part['value']}."
        if line not in out and len(out) < 8:
            out.append(line)
    return out[:8] or ["Everything measured is in good shape. Keep it that way."]


# --------------------------------------------------------------------------- documents


def _when(value: datetime | None) -> str:
    return value.strftime("%d %b %Y") if value else ""


def executive_doc(db: Session, tenant: Tenant, days: int) -> tuple[str, dict]:
    from . import client360

    data = executive_data(db, tenant, days)
    health = client360.health(db, tenant, client360.cost_rate_for(db, tenant), finance=False)
    svc = data["service"]
    sla = "n/a" if svc["slaMet"] is None else f"{svc['slaMet']}%"

    def hours(value) -> str:
        return "n/a" if value is None else f"{value} h"

    vulns = data["openVulnerabilities"]
    blocks = [
        {"type": "score", "label": "IT health", "value": health["score"], "status": health["status"]},
        {"type": "kpis", "items": [
            {"value": data["devices"]["total"], "label": "protected devices"},
            {"value": data["threatEvents"], "label": "threat events stopped"},
            {"value": data["dnsBlocked"], "label": "malicious domains blocked"},
            {"value": f"{data['incidents']['total']} ({data['incidents']['resolved']} resolved)", "label": "incidents"},
            {"value": f"{data['patching']['compliancePercent']}%", "label": "devices fully patched"},
            {"value": vulns.get("critical", 0) + vulns.get("high", 0), "label": "critical and high vulnerabilities open"},
            {"value": data["knownExploited"], "label": "known-exploited vulnerabilities to fix"},
            {"value": sla, "label": "tickets resolved within SLA"},
        ]},
        {"type": "heading", "text": "Recommended next steps"},
        {"type": "list", "ordered": True, "items": recommendations(data, health)},
        {"type": "heading", "text": "IT health by area"},
        {"type": "table", "columns": ["Area", "Score", "Now", "Detail"], "widths": [2.2, 0.9, 2.4, 3.5], "rows": [
            [p["label"], {"text": "not set up" if p["score"] is None else str(round(p["score"])), "status": p["status"]},
             p["value"], p["detail"]] for p in health["parts"]]},
        {"type": "heading", "text": "Alerts by severity"},
        {"type": "table", "columns": ["Severity", "Alerts"], "rows": [
            [{"text": s.title(), "status": SEVERITY_STATUS.get(s)}, n] for s, n in sorted(
                data["alerts"].items(), key=lambda kv: SEVERITIES.index(kv[0]) if kv[0] in SEVERITIES else 9)]},
        {"type": "heading", "text": "Open vulnerabilities"},
        {"type": "table", "columns": ["Severity", "Open"], "rows": [
            [{"text": s.title(), "status": SEVERITY_STATUS.get(s)}, vulns.get(s, 0)] for s in SEVERITIES if vulns.get(s)]},
        {"type": "heading", "text": "Patching"},
        {"type": "table", "columns": ["Measure", "Devices"], "rows": [
            ["Managed devices", data["patching"]["devices"]], ["Fully patched", data["patching"]["fullyPatched"]],
            ["Missing security or critical updates", data["patching"]["missingCriticalOrSecurity"]],
            ["Waiting for a restart", data["patching"]["pendingReboot"]], ["Failed updates", data["patching"]["failedPatches"]]]},
        {"type": "heading", "text": "Compliance posture"},
        {"type": "table", "columns": ["Framework", "Score"], "rows": [
            [c["name"], {"text": f"{c['score']}%", "status": "good" if c["score"] >= 80 else "warn" if c["score"] >= 60 else "bad"}]
            for c in data["compliance"]]},
        {"type": "heading", "text": "Service desk"},
        {"type": "table", "columns": ["Measure", "Value"], "widths": [2, 3], "rows": [
            ["Tickets raised", f"{svc['tickets']} ({svc['resolved']} resolved, {svc['openNow']} open now)"],
            ["Resolved within SLA", sla], ["Average first response", hours(svc["avgFirstResponseHours"])],
            ["Average time to resolve", hours(svc["avgResolutionHours"])], ["Engineer time", f"{svc['hoursWorked']} hours"],
            ["Changes implemented", f"{svc['changesImplemented']} ({svc['changesFailed']} failed)"],
            ["Open problems under investigation", svc["problemsOpen"]]]},
        {"type": "heading", "text": "By priority"},
        {"type": "table", "columns": ["Priority", "Tickets", "Resolved", "Within SLA"], "rows": [
            [p, v["tickets"], v["resolved"], "n/a" if v["slaMet"] is None else f"{v['slaMet']}%"] for p, v in svc["byPriority"].items()]},
        {"type": "heading", "text": "Top categories"},
        {"type": "table", "columns": ["Category", "Tickets"], "rows": [[c["name"], c["tickets"]] for c in svc["topCategories"]]},
    ]
    now = utcnow()
    return now.strftime("%Y-%m-%d"), {"title": f"Security report: {tenant.name}",
                                      "subtitle": f"Last {days} days · generated {now:%d %B %Y}", "blocks": blocks}


def _parts_table(report: dict) -> dict:
    return {"type": "table", "columns": ["Area", "Score", "Now", "Detail"], "widths": [2.2, 0.9, 2.4, 3.5], "rows": [
        [p["label"], {"text": "not set up" if p["score"] is None else str(round(p["score"])), "status": p["status"]},
         p["value"], p["detail"]] for p in report["parts"]]}


def _activity_kpis(work: dict) -> list[dict]:
    from .client360 import ACTIVITY_LABELS

    return [{"value": work[key], "label": label} for key, label in ACTIVITY_LABELS if work.get(key)]


def monthly_doc(db: Session, tenant: Tenant, month: str | None = None) -> tuple[str, dict]:
    from . import client360

    start, end, label = client360.month_bounds(month)
    work = client360.activity(db, tenant, start, end)
    report = client360.health(db, tenant, client360.cost_rate_for(db, tenant), finance=False)
    sla = "" if work["slaMet"] is None else f" {work['slaMet']}% of them were resolved within the agreed time."
    kpis = _activity_kpis(work)
    blocks = [
        {"type": "kpis", "items": kpis} if kpis else {"type": "paragraph", "text": "A quiet month: nothing needed our attention."},
        {"type": "paragraph", "text": f"We resolved {work['ticketsResolved']} support requests ({work['ticketsOpened']} new ones came in).{sla}"},
        {"type": "score", "label": "Your IT health today", "value": report["score"], "status": report["status"]},
        _parts_table(report),
        {"type": "paragraph", "muted": True, "text": 'Areas marked "not set up" are not measured yet and do not count towards the score.'},
    ]
    return start.strftime("%Y-%m"), {"title": f"What we did for you in {label}",
                                     "subtitle": f"{tenant.name} · prepared by {branding.get(db, tenant.id)['companyName']}",
                                     "blocks": blocks}


def quarterly_doc(db: Session, tenant: Tenant, quarter: str | None = None) -> tuple[str, dict]:
    from . import client360

    start, end, label = client360.quarter_bounds(quarter)
    work = client360.activity(db, tenant, start, end)
    report = client360.health(db, tenant, client360.cost_rate_for(db, tenant), finance=False)
    points = [p for p in client360.trend(db, tenant.id, 400) if start.isoformat() <= p["at"] < end.isoformat() + "Z"]
    blocks: list[dict] = [{"type": "score", "label": "IT health", "value": report["score"], "status": report["status"]}]
    if len(points) >= 2:
        blocks.append({"type": "paragraph", "text": f"Health moved from {points[0]['score']} to {points[-1]['score']} over the quarter."})
    blocks.append(_parts_table(report))
    missing = [p["label"] for p in report["parts"] if p["score"] is None]
    if missing:
        blocks.append({"type": "paragraph", "muted": True,
                       "text": f"Not measured yet: {', '.join(missing)}. Setting these up gives a fuller picture."})
    kpis = _activity_kpis(work)
    blocks += [{"type": "heading", "text": "What we did this quarter"},
               {"type": "kpis", "items": kpis} if kpis else {"type": "paragraph", "text": "No recorded work."}]
    priorities = sorted((p for p in report["parts"] if p["score"] is not None and p["status"] != "good"), key=lambda p: p["score"])
    steps = [f"{p['label']}: {p['value']}. {p['detail']}".strip() for p in priorities[:5]] \
        or ["Everything measured is in good shape. Keep it that way."]
    blocks += [{"type": "heading", "text": "Recommended next steps"}, {"type": "list", "ordered": True, "items": steps}]
    return f"{start.year}-Q{(start.month - 1) // 3 + 1}", {
        "title": f"Quarterly review: {label}",
        "subtitle": f"{tenant.name} · prepared by {branding.get(db, tenant.id)['companyName']}", "blocks": blocks}


def vulnerability_doc(db: Session, tenant: Tenant) -> tuple[str, dict]:
    from .vulnmgmt import UNRESOLVED

    now = utcnow()
    rows = db.execute(select(Vulnerability).where(Vulnerability.tenant_id == tenant.id, Vulnerability.status.in_(UNRESOLVED))).scalars().all()
    names = dict(db.execute(select(Device.id, Device.hostname).where(Device.tenant_id == tenant.id)).all())
    accepted = [v for v in rows if v.status == "accepted"]
    active = [v for v in rows if v.status != "accepted"]
    overdue = [v for v in active if v.due_at and v.due_at < now]
    fixed = db.execute(select(func.count()).select_from(Vulnerability).where(
        Vulnerability.tenant_id == tenant.id, Vulnerability.status == "fixed", Vulnerability.verified_at >= now - timedelta(days=30))).scalar() or 0
    by_sev = Counter(v.severity for v in active)

    def risk(v: Vulnerability) -> tuple:
        return (v.known_exploited, SEVERITIES[::-1].index(v.severity) if v.severity in SEVERITIES else -1, v.cvss or 0, v.epss or 0)

    def age_bucket(v: Vulnerability) -> str:
        days = (now - v.first_seen).days if v.first_seen else 0
        return "0-30 days" if days <= 30 else "31-90 days" if days <= 90 else "over 90 days"

    ageing = {s: Counter(age_bucket(v) for v in active if v.severity == s) for s in SEVERITIES}
    top = sorted(active, key=risk, reverse=True)[:60]
    devices = Counter(v.device_id for v in active)
    blocks = [
        {"type": "kpis", "items": [
            {"value": len(active), "label": "open vulnerabilities"}, {"value": by_sev.get("critical", 0), "label": "critical"},
            {"value": by_sev.get("high", 0), "label": "high"},
            {"value": sum(v.known_exploited for v in active), "label": "known to be exploited (CISA KEV)"},
            {"value": len(overdue), "label": "past their fix-by date"}, {"value": fixed, "label": "fixed and verified in 30 days"},
            {"value": len(accepted), "label": "risks accepted"}, {"value": len(devices), "label": "devices affected"}]},
        {"type": "heading", "text": "Ageing"},
        {"type": "table", "columns": ["Severity", "0-30 days", "31-90 days", "over 90 days"], "rows": [
            [{"text": s.title(), "status": SEVERITY_STATUS[s]}, ageing[s].get("0-30 days", 0), ageing[s].get("31-90 days", 0),
             {"text": str(ageing[s].get("over 90 days", 0)), "status": "bad" if ageing[s].get("over 90 days") and s in ("critical", "high") else None}]
            for s in SEVERITIES]},
        {"type": "heading", "text": "Highest risk first"},
        {"type": "paragraph", "muted": True, "text": "Known-exploited first, then by severity, CVSS and the chance of exploitation (EPSS)."
                                                    + (f" Showing the top {len(top)} of {len(active)}." if len(active) > len(top) else "")},
        {"type": "table", "columns": ["Vulnerability", "Device", "Software", "Severity", "CVSS", "EPSS", "Fix by", "Status"],
         "widths": [2.1, 1.8, 2.6, 1.2, 0.8, 0.8, 1.4, 1.1], "rows": [
             [v.vuln_id + (" (KEV)" if v.known_exploited else ""), names.get(v.device_id, v.device_id),
              f"{v.package} {v.installed_version}".strip()[:60], {"text": v.severity, "status": SEVERITY_STATUS.get(v.severity)},
              "" if v.cvss is None else f"{v.cvss:.1f}", "" if v.epss is None else f"{v.epss * 100:.0f}%",
              {"text": _when(v.due_at), "status": "bad" if v.due_at and v.due_at < now else None}, v.status] for v in top]},
        {"type": "heading", "text": "Devices with the most open vulnerabilities"},
        {"type": "table", "columns": ["Device", "Open", "Critical", "Known exploited"], "rows": [
            [names.get(device_id, device_id), count, sum(1 for v in active if v.device_id == device_id and v.severity == "critical"),
             sum(1 for v in active if v.device_id == device_id and v.known_exploited)] for device_id, count in devices.most_common(10)]},
    ]
    if accepted:
        blocks += [{"type": "heading", "text": "Accepted risks"},
                   {"type": "table", "columns": ["Vulnerability", "Device", "Reason", "Approved by", "Expires"],
                    "widths": [2, 1.8, 3.5, 1.8, 1.3], "rows": [
                        [v.vuln_id, names.get(v.device_id, v.device_id), (v.exception_reason or "")[:200], v.exception_approved_by or "",
                         _when(v.exception_expires_at)] for v in accepted[:100]]}]
    return now.strftime("%Y-%m-%d"), {"title": f"Vulnerability report: {tenant.name}",
                                      "subtitle": f"Open vulnerabilities as of {now:%d %B %Y}", "blocks": blocks}


def build(db: Session, tenant: Tenant, kind: str, *, days: int = 30, period: str | None = None) -> tuple[str, dict]:
    """(period key, document) for a report kind. Raises ValueError for an unknown kind or a badly formed period."""
    if kind == "executive":
        if days not in (7, 30, 90):
            raise ValueError("days must be 7, 30 or 90")
        return executive_doc(db, tenant, days)
    if kind == "monthly":
        return monthly_doc(db, tenant, period)
    if kind == "quarterly":
        return quarterly_doc(db, tenant, period)
    if kind == "vulnerability":
        return vulnerability_doc(db, tenant)
    raise ValueError(f"kind must be one of {', '.join(KINDS)}")


def html(db: Session, tenant: Tenant, doc: dict) -> str:
    return report_render.render_html(doc, branding.get(db, tenant.id))


def pdf(db: Session, tenant: Tenant, doc: dict) -> bytes:
    return report_render.render_pdf(doc, branding.get(db, tenant.id), generated=utcnow())


def filename(tenant: Tenant, kind: str, period: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9]+", "-", tenant.name).strip("-")[:60] or "customer"
    return f"{safe}-{kind}-{period}.pdf"


# --------------------------------------------------------------------------- schedules

EVERY = {"weekly", "monthly", "quarterly"}
MAX_SCHEDULES = 10
MAX_RECIPIENTS = 20
_EMAIL = re.compile(r"[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+")


def period_key(every: str, now: datetime) -> str:
    """The delivery period a schedule is in: it sends once per period."""
    if every == "weekly":
        year, week, _ = now.isocalendar()
        return f"{year}-W{week:02d}"
    if every == "quarterly":
        return f"{now.year}-Q{(now.month - 1) // 3 + 1}"
    return now.strftime("%Y-%m")


def validate_schedules(value) -> list[dict]:
    if not isinstance(value, list) or len(value) > MAX_SCHEDULES:
        raise ValueError(f"Send a list of at most {MAX_SCHEDULES} schedules")
    out = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("Each schedule must be an object")
        kind, every = item.get("kind"), item.get("every")
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {', '.join(KINDS)}")
        if every not in EVERY:
            raise ValueError("every must be weekly, monthly or quarterly")
        recipients = item.get("to")
        if not isinstance(recipients, list) or not recipients or len(recipients) > MAX_RECIPIENTS:
            raise ValueError(f"Give between 1 and {MAX_RECIPIENTS} recipients")
        clean = []
        for address in recipients:
            if not isinstance(address, str) or not _EMAIL.fullmatch(address.strip()):
                raise ValueError(f"Not an email address: {str(address)[:80]}")
            clean.append(address.strip().lower())
        sid = str(item.get("id") or "")
        if not re.fullmatch(r"[a-z0-9]{8,32}", sid):
            import secrets

            sid = secrets.token_hex(6)
        out.append({"id": sid, "kind": kind, "every": every, "to": sorted(set(clean)),
                    "lastPeriod": item.get("lastPeriod") if isinstance(item.get("lastPeriod"), str) else None,
                    "lastSentAt": item.get("lastSentAt") if isinstance(item.get("lastSentAt"), str) else None,
                    "lastError": item.get("lastError") if isinstance(item.get("lastError"), str) else None})
    return out


def _scheduled_doc(db: Session, tenant: Tenant, schedule: dict) -> tuple[str, dict]:
    kind, every = schedule["kind"], schedule["every"]
    if kind == "executive":
        return build(db, tenant, kind, days={"weekly": 7, "monthly": 30, "quarterly": 90}[every])
    return build(db, tenant, kind)  # monthly: last month; quarterly: last complete quarter; vulnerability: now


def deliver(db: Session, tenant: Tenant, schedule: dict, now: datetime | None = None) -> str:
    """Email one schedule's report as a PDF to its recipients. Returns the period key of the report sent."""
    from . import mailer

    now = now or utcnow()
    period, doc = _scheduled_doc(db, tenant, schedule)
    data = pdf(db, tenant, doc)
    brand = branding.get(db, tenant.id)
    contact = branding.contact_line(brand)
    body = (f"{doc['title']}\n{doc.get('subtitle') or ''}\n\nThe report is attached as a PDF.\n\n"
            f"{brand['companyName']}" + (f"\n{contact}" if contact else ""))
    for recipient in schedule["to"][:MAX_RECIPIENTS]:
        mailer.send(recipient, f"{doc['title']} ({brand['companyName']})", body,
                    attachments=[(filename(tenant, schedule["kind"], period), "application/pdf", data)])
    return period


def send_schedules(db: Session, now: datetime | None = None) -> int:
    """Hourly: email every scheduled report not yet sent in its current period. One failure never stops the others."""
    from . import audit

    now = now or utcnow()
    sent = 0
    for tenant in db.execute(select(Tenant).where(Tenant.kind == "customer")).scalars().all():
        schedules = [dict(s) for s in (tenant.settings or {}).get("reportSchedules") or [] if isinstance(s, dict)]
        changed = False
        for schedule in schedules:
            if schedule.get("kind") not in KINDS or schedule.get("every") not in EVERY or not schedule.get("to"):
                continue
            current = period_key(schedule["every"], now)
            if schedule.get("lastPeriod") == current:
                continue
            try:
                deliver(db, tenant, schedule, now)
            except Exception as exc:  # a broken report must not block the rest, and must say why
                schedule["lastError"] = f"{type(exc).__name__}: {str(exc)[:200]}"
                schedule["lastPeriod"] = current  # retried next period, not every hour
                changed = True
                audit.record(db, "system:reports", "report.schedule_failed", tenant.name, tenant.id, kind=schedule["kind"],
                             error=schedule["lastError"])
                continue
            schedule.update(lastPeriod=current, lastSentAt=now.isoformat() + "Z", lastError=None)
            changed = True
            sent += 1
            audit.record(db, "system:reports", "report.sent", tenant.name, tenant.id, kind=schedule["kind"],
                         every=schedule["every"], recipients=len(schedule["to"]))
        if changed:
            tenant.settings = {**(tenant.settings or {}), "reportSchedules": schedules}
            db.commit()
    return sent
