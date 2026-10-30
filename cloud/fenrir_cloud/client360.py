"""Client 360: one health score per customer, and the monthly and quarterly reports built from the same data.

The score is a weighted average of the parts below that have data. A part with nothing to measure (no Microsoft 365
connection, no backup plan, no compliance framework, no invoices yet) is shown as not set up and left out, rather than
counted as perfect or as zero:

- devices: checked in within the last 7 days;
- patches: devices fully patched (rmm.patch_compliance);
- protection: devices whose protection is healthy, less open critical and high alerts;
- backup: plans protected within their RPO;
- identity: Microsoft 365 MFA registration and Secure Score;
- vulnerabilities: devices without a known-exploited (KEV) vulnerability, less those with critical ones;
- compliance: the average compliance framework score;
- service: tickets resolved within SLA over 90 days, less tickets past SLA now;
- account: margin over 90 days against a 30% target; the renewal date is shown, not scored.

A snapshot of the score is kept once a day (tick), so the client page and the quarterly review show the trend. On the
first run each month, last month's "what we did for you" report is archived for every customer.
"""

from __future__ import annotations

import html
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import (Alert, BackupPlan, BackupRun, ClientHealthSnapshot, ClientReport, Command, Contract, Device, DevicePatch,
                     DnsQueryLog, Event, Incident, Job, M365Connection, Tenant, Ticket, TimeEntry, Vulnerability, utcnow)

WEIGHTS = {"protection": 20, "patches": 15, "vulnerabilities": 15, "backup": 10, "identity": 10, "devices": 10,
           "service": 10, "compliance": 5, "account": 5}
LABELS = {"devices": "Devices checking in", "patches": "Patching", "protection": "Protection", "backup": "Backup",
          "identity": "Microsoft 365 identity", "vulnerabilities": "Known-exploited vulnerabilities", "compliance": "Compliance",
          "service": "Service desk", "account": "Account"}
LINKS = {"devices": "/devices", "patches": "/patching", "protection": "/alerts", "backup": "/backup", "identity": "/m365",
         "vulnerabilities": "/vulnerabilities", "compliance": "/governance", "service": "/service-board", "account": "/crm"}
STALE_DEVICE = timedelta(days=7)
MARGIN_TARGET = 30.0
SNAPSHOT_EVERY = timedelta(hours=20)


def _status(score: float | None) -> str:
    if score is None:
        return "none"
    return "good" if score >= 80 else "warn" if score >= 60 else "bad"


def _clamp(value: float) -> float:
    return round(max(0.0, min(100.0, value)), 1)


def _part(key: str, score: float | None, value: str, detail: str = "", **extra) -> dict:
    return {"key": key, "label": LABELS[key], "score": None if score is None else _clamp(score), "status": _status(score),
            "value": value, "detail": detail, "link": LINKS[key], "weight": WEIGHTS[key], **extra}


def _devices(db: Session, tenant: Tenant, now: datetime) -> tuple[dict, list[Device]]:
    devices = [d for d in db.execute(select(Device).where(Device.tenant_id == tenant.id, Device.approved.is_(True))).scalars()
               if d.api_key_hash != f"retired-{d.id}"]
    if not devices:
        return _part("devices", None, "No devices yet"), devices
    online = sum(1 for d in devices if d.last_seen_at and d.last_seen_at >= now - timedelta(minutes=10))
    stale = [d for d in devices if not d.last_seen_at or d.last_seen_at < now - STALE_DEVICE]
    return _part("devices", 100 * (len(devices) - len(stale)) / len(devices), f"{online} of {len(devices)} online now",
                 f"{len(stale)} not seen for 7 days or more" if stale else "All checked in this week",
                 stale=sorted(d.hostname for d in stale)[:20]), devices


def _patches(db: Session, tenant: Tenant, devices: list[Device]) -> dict:
    from .rmm import patch_compliance

    if not devices:
        return _part("patches", None, "No devices yet")
    data = patch_compliance(db, [tenant.id])
    if not data["scanned"]:
        return _part("patches", None, "No update scans yet")
    return _part("patches", data["compliancePercent"], f"{data['fullyPatched']} of {data['devices']} fully patched",
                 f"{data['missingCriticalOrSecurity']} missing security updates · {data['failedPatches']} failed installs · "
                 f"{data['pendingReboot']} waiting to restart")


def _protection(db: Session, tenant: Tenant, devices: list[Device]) -> dict:
    from .endpoint_health import UNHEALTHY

    if not devices:
        return _part("protection", None, "No devices yet")
    unhealthy = [d for d in devices if (d.health_state or "").lower() in UNHEALTHY]
    open_alerts = dict(db.execute(select(Alert.severity, func.count()).where(
        Alert.tenant_id == tenant.id, Alert.status.in_(("new", "triaged")), Alert.severity.in_(("critical", "high")))
        .group_by(Alert.severity)).all())
    critical, high = open_alerts.get("critical", 0), open_alerts.get("high", 0)
    score = 100 * (len(devices) - len(unhealthy)) / len(devices) - 10 * critical - 3 * high
    return _part("protection", score, f"{len(devices) - len(unhealthy)} of {len(devices)} fully protected",
                 f"{critical} critical and {high} high alerts open · {sum(1 for d in devices if d.isolated)} isolated")


def _backup(db: Session, tenant: Tenant, now: datetime) -> dict:
    plans = db.execute(select(BackupPlan).where(BackupPlan.tenant_id == tenant.id)).scalars().all()
    if not plans:
        return _part("backup", None, "No backup monitoring set up")
    protected, problems = 0, []
    for plan in plans:
        last = db.scalar(select(func.max(BackupRun.completed_at)).where(BackupRun.plan_id == plan.id, BackupRun.status == "success"))
        if last and last >= now - timedelta(hours=plan.rpo_hours):
            protected += 1
        else:
            problems.append(plan.name)
    return _part("backup", 100 * protected / len(plans), f"{protected} of {len(plans)} plans within their RPO",
                 ("Late or failing: " + ", ".join(problems[:5])) if problems else "Every plan backed up on time")


def _identity(db: Session, tenant: Tenant) -> dict:
    connection = db.execute(select(M365Connection).where(M365Connection.tenant_id == tenant.id)).scalars().first()
    insights = ((connection.snapshot or {}).get("insights") or {}) if connection else {}
    mfa, secure = insights.get("mfa") or {}, insights.get("secureScore") or {}
    parts = [p for p in (mfa.get("percent"), secure.get("percent")) if p is not None]
    if not parts:
        return _part("identity", None, "Microsoft 365 not connected" if connection is None else "Not synced yet")
    admins = len(mfa.get("adminsWithoutMfa") or [])
    score = sum(parts) / len(parts) - 15 * admins
    value = " · ".join(v for v in (f"MFA {mfa['percent']}%" if mfa.get("percent") is not None else "",
                                   f"Secure Score {secure['percent']}%" if secure.get("percent") is not None else "") if v)
    return _part("identity", score, value, f"{admins} administrators without MFA" if admins else
                 f"{mfa.get('notRegistered', 0)} users without MFA")


def _vulnerabilities(db: Session, tenant: Tenant, devices: list[Device]) -> dict:
    from .vulnmgmt import UNRESOLVED

    if not devices:
        return _part("vulnerabilities", None, "No devices yet")
    open_vulns = db.execute(select(Vulnerability.device_id, Vulnerability.severity, Vulnerability.known_exploited).where(
        Vulnerability.tenant_id == tenant.id, Vulnerability.status.in_(UNRESOLVED))).all()
    kev = {d for d, _, exploited in open_vulns if exploited}
    critical = {d for d, severity, _ in open_vulns if severity == "critical"} - kev
    score = 100 * (len(devices) - len(kev) - 0.5 * len(critical)) / len(devices)
    return _part("vulnerabilities", score, f"{len(kev)} devices with a known-exploited vulnerability",
                 f"{len(critical)} more with critical ones · {len(open_vulns)} open in total")


def _compliance(db: Session, tenant: Tenant) -> dict:
    from . import compliance

    frameworks = compliance.evaluate(db, tenant)
    scored = [f for f in frameworks if f.get("score") is not None]
    if not scored:
        return _part("compliance", None, "No framework assessed")
    score = sum(f["score"] for f in scored) / len(scored)
    return _part("compliance", score, f"{round(score)}% average", ", ".join(f"{f['name']} {f['score']}%" for f in scored[:4]))


def _service(db: Session, tenant: Tenant, now: datetime) -> dict:
    since = now - timedelta(days=90)
    resolved = db.execute(select(Ticket.resolved_at, Ticket.sla_due_at).where(
        Ticket.account_tenant_id == tenant.id, Ticket.resolved_at >= since)).all()
    timed = [(r, d) for r, d in resolved if d]
    met = sum(1 for r, d in timed if r <= d)
    open_rows = db.execute(select(Ticket.sla_due_at).where(Ticket.account_tenant_id == tenant.id, Ticket.resolved_at.is_(None))).all()
    breached = sum(1 for (due,) in open_rows if due and due < now)
    if not timed and not open_rows:
        return _part("service", None, "No tickets in 90 days")
    base = 100 * met / len(timed) if timed else 100.0
    return _part("service", base - 10 * breached, f"{round(base)}% within SLA" if timed else "No tickets resolved yet",
                 f"{len(open_rows)} open · {breached} past SLA now")


def _account(db: Session, tenant: Tenant, now: datetime, cost_rate: float, finance: bool) -> dict:
    from .routers.crm import contracted_mrr, profitability

    contracts = db.execute(select(Contract).where(Contract.account_tenant_id == tenant.id, Contract.active.is_(True))).scalars().all()
    ends = sorted(c.end_date for c in contracts if c.end_date)
    renewal = ends[0] if ends else None
    days_left = None
    if renewal:
        try:
            days_left = (datetime.fromisoformat(renewal[:10]) - now).days
        except ValueError:
            days_left = None
    money = profitability(db, tenant.id, 90, cost_rate)
    margin = money.get("marginPercent")
    if not contracts and margin is None:
        return _part("account", None, "No agreement")
    score = None if margin is None else 100 * margin / MARGIN_TARGET
    renewal_text = f"renews {renewal[:10]}" + (f" (in {days_left} days)" if days_left is not None and days_left <= 90 else "") if renewal else "no end date"
    if not finance:  # the score still counts; the money is only shown to finance and CRM staff
        return _part("account", score, renewal_text, "", renewalDate=renewal, renewalSoon=days_left is not None and days_left <= 60)
    return _part("account", score, f"{margin}% margin over 90 days" if margin is not None else "No invoices in 90 days",
                 f"MRR {contracted_mrr(db, tenant.id)} · {renewal_text}", renewalDate=renewal,
                 renewalSoon=days_left is not None and days_left <= 60, mrr=contracted_mrr(db, tenant.id), marginPercent=margin)


def health(db: Session, tenant: Tenant, cost_rate: float, finance: bool = True, now: datetime | None = None) -> dict:
    now = now or utcnow()
    devices_part, devices = _devices(db, tenant, now)
    parts = [devices_part, _patches(db, tenant, devices), _protection(db, tenant, devices), _backup(db, tenant, now),
             _identity(db, tenant), _vulnerabilities(db, tenant, devices), _compliance(db, tenant), _service(db, tenant, now),
             _account(db, tenant, now, cost_rate, finance)]
    scored = [p for p in parts if p["score"] is not None]
    weight = sum(p["weight"] for p in scored)
    score = round(sum(p["score"] * p["weight"] for p in scored) / weight) if weight else None
    return {"tenantId": tenant.id, "name": tenant.name, "score": score, "status": _status(score), "parts": parts,
            "measured": len(scored), "of": len(parts), "at": now.isoformat() + "Z"}


def trend(db: Session, tenant_id: str, days: int = 365) -> list[dict]:
    rows = db.execute(select(ClientHealthSnapshot.at, ClientHealthSnapshot.score).where(
        ClientHealthSnapshot.tenant_id == tenant_id, ClientHealthSnapshot.at >= utcnow() - timedelta(days=days))
        .order_by(ClientHealthSnapshot.at)).all()
    return [{"at": at.isoformat() + "Z", "score": score} for at, score in rows]


# --------------------------------------------------------------------------- what we did


def activity(db: Session, tenant: Tenant, start: datetime, end: datetime) -> dict:
    """The work done for the customer in a period, for the monthly report and the quarterly review."""
    def count(model, *where) -> int:
        return db.scalar(select(func.count()).select_from(model).where(*where)) or 0

    hours = db.scalar(select(func.sum(TimeEntry.hours)).where(TimeEntry.account_tenant_id == tenant.id,
                                                              TimeEntry.started_at >= start, TimeEntry.started_at < end)) or 0
    resolved = db.execute(select(Ticket).where(Ticket.account_tenant_id == tenant.id, Ticket.resolved_at >= start,
                                               Ticket.resolved_at < end)).scalars().all()
    timed = [t for t in resolved if t.sla_due_at]
    return {
        "ticketsOpened": count(Ticket, Ticket.account_tenant_id == tenant.id, Ticket.created_at >= start, Ticket.created_at < end),
        "ticketsResolved": len(resolved),
        "slaMet": round(100 * sum(1 for t in timed if t.resolved_at <= t.sla_due_at) / len(timed)) if timed else None,
        "hoursWorked": round(float(hours), 1),
        "updatesInstalled": count(DevicePatch, DevicePatch.tenant_id == tenant.id, DevicePatch.status == "installed",
                                  DevicePatch.installed_at >= start, DevicePatch.installed_at < end),
        "vulnerabilitiesFixed": count(Vulnerability, Vulnerability.tenant_id == tenant.id, Vulnerability.status == "fixed",
                                      Vulnerability.verified_at >= start, Vulnerability.verified_at < end),
        "alertsHandled": count(Alert, Alert.tenant_id == tenant.id, Alert.status.in_(("resolved", "false_positive")),
                               Alert.updated_at >= start, Alert.updated_at < end),
        "incidents": count(Incident, Incident.tenant_id == tenant.id, Incident.created_at >= start, Incident.created_at < end),
        "threatsBlocked": count(Event, Event.tenant_id == tenant.id, Event.category == "malware", Event.occurred_at >= start,
                                Event.occurred_at < end),
        "dnsBlocked": count(DnsQueryLog, DnsQueryLog.tenant_id == tenant.id, DnsQueryLog.action == "block", DnsQueryLog.at >= start,
                            DnsQueryLog.at < end),
        "scriptsAndJobs": count(Job, Job.tenant_id == tenant.id, Job.created_at >= start, Job.created_at < end),
        "actionsCompleted": count(Command, Command.tenant_id == tenant.id, Command.status == "completed",
                                  Command.completed_at >= start, Command.completed_at < end),
        "backupsSucceeded": count(BackupRun, BackupRun.tenant_id == tenant.id, BackupRun.status == "success",
                                  BackupRun.completed_at >= start, BackupRun.completed_at < end),
    }


ACTIVITY_LABELS = [
    ("ticketsResolved", "Support requests resolved"), ("hoursWorked", "Hours of work"), ("updatesInstalled", "Updates installed"),
    ("vulnerabilitiesFixed", "Vulnerabilities fixed and verified"), ("alertsHandled", "Security alerts investigated"),
    ("threatsBlocked", "Threats blocked"), ("dnsBlocked", "Dangerous websites blocked"), ("backupsSucceeded", "Successful backups"),
    ("scriptsAndJobs", "Maintenance jobs run"), ("actionsCompleted", "Device actions completed"),
]


def month_bounds(month: str | None, now: datetime | None = None) -> tuple[datetime, datetime, str]:
    """"2026-09" -> (1 Sep, 1 Oct, "September 2026"); no month means last month."""
    now = now or utcnow()
    if month:
        start = datetime.strptime(month, "%Y-%m")
    else:
        first = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        start = (first - timedelta(days=1)).replace(day=1)
    end = (start + timedelta(days=32)).replace(day=1)
    return start, end, start.strftime("%B %Y")


def quarter_bounds(quarter: str | None, now: datetime | None = None) -> tuple[datetime, datetime, str]:
    """"2026-Q3" -> (1 Jul, 1 Oct, "Q3 2026"); no quarter means the last complete one."""
    now = now or utcnow()
    if quarter:
        year, q = int(quarter[:4]), int(quarter[-1])
    else:
        current = (now.month - 1) // 3 + 1
        year, q = (now.year, current - 1) if current > 1 else (now.year - 1, 4)
    if not 1 <= q <= 4:
        raise ValueError("quarter must look like 2026-Q3")
    start = datetime(year, 3 * (q - 1) + 1, 1)
    end = datetime(year + (q == 4), 1 if q == 4 else 3 * q + 1, 1)
    return start, end, f"Q{q} {year}"


_STYLE = """body{font-family:system-ui,sans-serif;max-width:860px;margin:32px auto;color:#1b2430;padding:0 16px}
h1{margin-bottom:4px}.sub{color:#5b6675}.score{font-size:56px;font-weight:700}.good{color:#15803d}.warn{color:#b45309}
.bad{color:#b91c1c}.none{color:#6b7280}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}
.card{border:1px solid #dde3ea;border-radius:10px;padding:14px}.card b{display:block;font-size:26px}
table{width:100%;border-collapse:collapse;margin:8px 0 24px}td,th{border-bottom:1px solid #eef1f4;padding:6px 4px;text-align:left}
@media print{body{margin:0}}"""


def _parts_table(report: dict) -> str:
    e = html.escape
    rows = "".join(
        f"<tr><td>{e(p['label'])}</td><td class='{p['status']}'>{'not set up' if p['score'] is None else round(p['score'])}</td>"
        f"<td>{e(p['value'])}</td><td>{e(p['detail'])}</td></tr>" for p in report["parts"])
    return f"<table><tr><th>Area</th><th>Score</th><th>Now</th><th>Detail</th></tr>{rows}</table>"


def _activity_cards(work: dict) -> str:
    return "".join(f"<div class='card'><b>{work[key]}</b>{html.escape(label)}</div>" for key, label in ACTIVITY_LABELS if work.get(key))


def monthly_report(db: Session, tenant: Tenant, msp_name: str, cost_rate: float, month: str | None = None) -> tuple[str, str]:
    """("2026-09", HTML): what we did for the customer that month, and where their health stands."""
    start, end, label = month_bounds(month)
    work = activity(db, tenant, start, end)
    report = health(db, tenant, cost_rate, finance=False)
    e = html.escape
    score = "n/a" if report["score"] is None else report["score"]
    sla = "" if work["slaMet"] is None else f" {work['slaMet']}% of them were resolved within the agreed time."
    body = f"""<!doctype html><html><head><meta charset="utf-8"><title>What we did for you - {e(tenant.name)} - {e(label)}</title>
<style>{_STYLE}</style></head><body><h1>What we did for you in {e(label)}</h1>
<div class="sub">{e(tenant.name)} &middot; prepared by {e(msp_name)}</div>
<div class="grid">{_activity_cards(work) or "<div class='card'>A quiet month: nothing needed our attention.</div>"}</div>
<p>We resolved {work['ticketsResolved']} support requests ({work['ticketsOpened']} new ones came in).{sla}</p>
<h2>Your IT health today: <span class="score {report['status']}">{score}</span><span class="sub"> / 100</span></h2>
{_parts_table(report)}
<p class="sub">Areas marked "not set up" are not measured yet and do not count towards the score.</p></body></html>"""
    return start.strftime("%Y-%m"), body


def quarterly_review(db: Session, tenant: Tenant, msp_name: str, cost_rate: float, quarter: str | None = None) -> tuple[str, str]:
    """("2026-Q3", HTML): a quarterly business review: health and how it moved, the work done, and what to do next."""
    start, end, label = quarter_bounds(quarter)
    work = activity(db, tenant, start, end)
    report = health(db, tenant, cost_rate, finance=False)
    points = [p for p in trend(db, tenant.id, 400) if start.isoformat() <= p["at"] < end.isoformat() + "Z"]
    e = html.escape
    moved = ""
    if len(points) >= 2:
        moved = f"<p>Health moved from <b>{points[0]['score']}</b> to <b>{points[-1]['score']}</b> over the quarter.</p>"
    priorities = sorted((p for p in report["parts"] if p["score"] is not None and p["status"] != "good"), key=lambda p: p["score"])
    next_steps = "".join(f"<li><b>{e(p['label'])}</b>: {e(p['value'])}. {e(p['detail'])}</li>" for p in priorities[:5]) \
        or "<li>Everything measured is in good shape. Keep it that way.</li>"
    missing = [p["label"] for p in report["parts"] if p["score"] is None]
    gaps = f"<p class='sub'>Not measured yet: {e(', '.join(missing))}. Setting these up gives a fuller picture.</p>" if missing else ""
    score = "n/a" if report["score"] is None else report["score"]
    body = f"""<!doctype html><html><head><meta charset="utf-8"><title>Quarterly review - {e(tenant.name)} - {e(label)}</title>
<style>{_STYLE}</style></head><body><h1>Quarterly review: {e(label)}</h1>
<div class="sub">{e(tenant.name)} &middot; prepared by {e(msp_name)}</div>
<h2>IT health: <span class="score {report['status']}">{score}</span><span class="sub"> / 100</span></h2>{moved}
{_parts_table(report)}{gaps}
<h2>What we did this quarter</h2><div class="grid">{_activity_cards(work) or "<div class='card'>No recorded work.</div>"}</div>
<h2>Recommended next steps</h2><ol>{next_steps}</ol></body></html>"""
    return f"{start.year}-Q{(start.month - 1) // 3 + 1}", body


# --------------------------------------------------------------------------- daily snapshot and monthly archive


def _msp_name(db: Session, tenant: Tenant) -> str:
    from .services import msp_tenant_id

    msp = db.get(Tenant, msp_tenant_id(db, tenant.id))
    return msp.name if msp else ""


def cost_rate_for(db: Session, tenant: Tenant) -> float:
    from .routers.crm import DEFAULT_LABOUR_COST
    from .services import msp_tenant_id

    msp = db.get(Tenant, msp_tenant_id(db, tenant.id))
    try:
        return float(((msp.settings or {}).get("crm") or {}).get("labourCostPerHour") or DEFAULT_LABOUR_COST) if msp else DEFAULT_LABOUR_COST
    except (TypeError, ValueError):
        return DEFAULT_LABOUR_COST


def tick(db: Session, now: datetime | None = None) -> dict:
    """Hourly: today's health snapshot for each customer that has none, and last month's report once per month."""
    now = now or utcnow()
    snapshots = reports = 0
    period, _, _ = month_bounds(None, now)
    period_key = period.strftime("%Y-%m")
    for tenant in db.execute(select(Tenant).where(Tenant.kind == "customer")).scalars().all():
        last = db.scalar(select(func.max(ClientHealthSnapshot.at)).where(ClientHealthSnapshot.tenant_id == tenant.id))
        rate = cost_rate_for(db, tenant)
        if last is None or last < now - SNAPSHOT_EVERY:
            report = health(db, tenant, rate, now=now)
            db.add(ClientHealthSnapshot(tenant_id=tenant.id, at=now, score=report["score"],
                                        parts={p["key"]: p["score"] for p in report["parts"]}))
            snapshots += 1
        archived = db.scalar(select(func.count()).select_from(ClientReport).where(
            ClientReport.tenant_id == tenant.id, ClientReport.kind == "monthly", ClientReport.period == period_key))
        if not archived and tenant.created_at < period + timedelta(days=32):
            key, body = monthly_report(db, tenant, _msp_name(db, tenant), rate, period_key)
            db.add(ClientReport(tenant_id=tenant.id, kind="monthly", period=key, html=body, created_by="system"))
            reports += 1
        db.commit()
    return {"snapshots": snapshots, "reports": reports}
