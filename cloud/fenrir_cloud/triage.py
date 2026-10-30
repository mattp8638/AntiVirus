"""The triage inbox: everything someone has to act on, from every module, in one list.

Items are built on request from their sources, so the inbox can never disagree with the page an item came from:

- alerts (detections, monitors, backup staleness, endpoint health, network monitors), one item per customer and rule,
  so the same monitor failing on 40 devices is one item;
- open incidents; tickets nobody owns, past their SLA, or yours;
- updates that failed to install, one item per customer and update; jobs that failed in the last three days;
- admin-rights requests and two-person approvals waiting for a decision;
- Microsoft 365 standards that drifted or failed; compliance requirements past their due date; evidence about to expire.

Every item has an owner, an SLA due time, snooze and (where it makes sense) dismissal. Alerts, incidents and tickets
keep owner and snooze on themselves, so their own pages agree; the rest keep them in TriageState, under the item's key.
A dismissed item stays hidden only while it is unchanged: a new device failing the same update brings it back.

Item keys are "<kind>:<customer id>:<id within kind>", so every action can check the customer is in scope.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .models import (Alert, ApprovalRequest, Command, Device, DevicePatch, ElevationRequest, GrcEvidence, GrcRequirementState,
                     Incident, Job, M365StandardRun, MonitorCondition, Tenant, Ticket, TriageState, utcnow)

SEVERITIES = ("critical", "high", "medium", "low", "info")
RANK = {name: i for i, name in enumerate(SEVERITIES)}
DEFAULT_SLA_HOURS = {"critical": 1, "high": 4, "medium": 24, "low": 72, "info": 168}
KINDS = ("alert", "incident", "ticket", "patch", "job", "elevation", "approval", "m365", "grc", "evidence")
MAX_ROWS = 2000
JOB_WINDOW = timedelta(days=3)
EVIDENCE_NOTICE = timedelta(days=14)
# Owner and snooze live on the source item for these kinds; dismissal is only offered where it means something.
NATIVE_OWNER = {"alert", "incident", "ticket"}
DISMISSIBLE = {"alert", "patch", "job", "m365", "grc", "evidence"}
PRIORITY_SEVERITY = {"P1": "critical", "P2": "high", "P3": "medium", "P4": "low"}
SEVERITY_PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P4"}


@dataclass
class Item:
    key: str
    kind: str
    tenant_id: str
    title: str
    severity: str
    first_seen: datetime
    last_seen: datetime | None = None
    summary: str = ""
    device_ids: list[str] = field(default_factory=list)
    count: int = 1
    owner: str | None = None
    snoozed_until: datetime | None = None
    sla_due: datetime | None = None
    link: str = ""
    ticket_id: str | None = None
    marker: str = ""
    refs: list[str] = field(default_factory=list)  # the source rows' ids (alerts, patches...)
    dismissed: bool = False


def _severity(value: str | None) -> str:
    value = (value or "").lower()
    if value in RANK:
        return value
    return {"informational": "info", "important": "high", "moderate": "medium", "warning": "medium"}.get(value, "medium")


def _digest(values) -> str:
    return hashlib.sha256(json.dumps(values, sort_keys=True, default=str).encode()).hexdigest()[:32]


def _common_title(titles: list[str]) -> str:
    """"Endpoint protection degraded on PC-1" and "...stopped on PC-2" become "Endpoint protection"."""
    if len(set(titles)) == 1:
        return titles[0]
    prefix = os.path.commonprefix(titles).rsplit(" ", 1)[0].rstrip(" :-—")
    return prefix if len(prefix) >= 12 else titles[0]


def sla_hours(db: Session) -> dict[str, float]:
    from .platform_security import _msp

    msp = _msp(db)
    stored = (((msp.settings or {}) if msp else {}).get("triage") or {}).get("slaHours") or {}
    return {k: float(stored.get(k, v)) for k, v in DEFAULT_SLA_HOURS.items()}


# --------------------------------------------------------------------------- sources


def _alerts(db: Session, scope: list[str], now: datetime) -> list[Item]:
    rows = db.execute(select(Alert).where(Alert.tenant_id.in_(scope), Alert.status.in_(("new", "triaged")))
                      .order_by(Alert.created_at.desc()).limit(MAX_ROWS)).scalars().all()
    groups: dict[tuple[str, str], list[Alert]] = {}
    for alert in rows:
        groups.setdefault((alert.tenant_id, alert.rule_id), []).append(alert)
    monitor_names = dict(db.execute(select(MonitorCondition.id, MonitorCondition.name).where(MonitorCondition.id.in_(
        {rule.split(":", 1)[1] for _, rule in groups if rule.startswith("monitor:")}))).all())
    items = []
    for (tenant_id, rule_id), alerts in groups.items():
        title = monitor_names.get(rule_id.split(":", 1)[1]) if rule_id.startswith("monitor:") else None
        title = title or _common_title([a.title for a in alerts])
        owners = {a.assignee for a in alerts if a.assignee}
        snoozed = [a.snoozed_until for a in alerts if a.snoozed_until and a.snoozed_until > now]
        devices = sorted({a.device_id for a in alerts if a.device_id})
        latest = max(alerts, key=lambda a: a.created_at)
        items.append(Item(
            key=f"alert:{tenant_id}:{rule_id}", kind="alert", tenant_id=tenant_id, title=title,
            severity=min((_severity(a.severity) for a in alerts), key=RANK.get),
            first_seen=min(a.created_at for a in alerts), last_seen=latest.created_at,
            summary=latest.title if len(alerts) > 1 else str((latest.details or {}).get("description") or ""),
            device_ids=devices, count=len(alerts),
            owner=owners.pop() if len(owners) == 1 else (", ".join(sorted(owners)) if owners else None),
            snoozed_until=min(snoozed) if len(snoozed) == len(alerts) else None,
            link=f"/alerts?rule={rule_id}" if len(alerts) > 1 else f"/alerts?id={latest.id}", refs=[a.id for a in alerts]))
    return items


def _incidents(db: Session, scope: list[str], now: datetime) -> list[Item]:
    rows = db.execute(select(Incident).where(Incident.tenant_id.in_(scope), Incident.status.notin_(("resolved", "closed")))
                      .order_by(Incident.created_at.desc()).limit(MAX_ROWS)).scalars().all()
    return [Item(key=f"incident:{i.tenant_id}:{i.id}", kind="incident", tenant_id=i.tenant_id, title=i.title,
                 severity=_severity(i.severity), first_seen=i.created_at, last_seen=i.updated_at,
                 summary=f"{i.alert_count} alerts · {i.status}", device_ids=[i.device_id] if i.device_id else [],
                 owner=i.assignee or None, link=f"/incidents/{i.id}", ticket_id=i.ticket_id, refs=[i.id]) for i in rows]


def _tickets(db: Session, scope: list[str], now: datetime, actor: str) -> list[Item]:
    from . import psa
    from .models import Board

    rows = db.execute(select(Ticket).where(or_(Ticket.account_tenant_id.in_(scope), Ticket.tenant_id.in_(scope)),
                                           Ticket.status.notin_(tuple(psa.CLOSED_DEFAULT)))
                      .order_by(Ticket.sla_due_at.is_(None), Ticket.sla_due_at).limit(MAX_ROWS)).scalars().all()
    boards = {b.id: b for b in db.execute(select(Board).where(Board.id.in_({t.board_id for t in rows if t.board_id}))).scalars()}
    items = []
    for t in rows:
        if t.status in psa.closed_statuses(boards.get(t.board_id)):
            continue
        breached = bool(t.sla_due_at and t.sla_due_at < now)
        mine = (t.assignee or "").lower() == actor.lower()
        if t.assignee and not breached and not mine:
            continue  # someone has it and it is on time: the service board is its home
        tenant_id = t.account_tenant_id or t.tenant_id
        items.append(Item(key=f"ticket:{tenant_id}:{t.id}", kind="ticket", tenant_id=tenant_id, title=f"#{t.number} {t.subject}",
                          severity=PRIORITY_SEVERITY.get(t.priority, "medium"), first_seen=t.created_at,
                          summary=t.status, device_ids=[t.device_id] if t.device_id else [], owner=t.assignee or None,
                          sla_due=t.sla_due_at, link=f"/tickets/{t.id}", ticket_id=t.id, refs=[t.id]))
    return items


def _patches(db: Session, scope: list[str], now: datetime) -> list[Item]:
    rows = db.execute(select(DevicePatch).where(DevicePatch.tenant_id.in_(scope), DevicePatch.status == "failed")
                      .limit(MAX_ROWS)).scalars().all()
    groups: dict[tuple[str, str], list[DevicePatch]] = {}
    for row in rows:
        groups.setdefault((row.tenant_id, row.patch_key), []).append(row)
    items = []
    for (tenant_id, patch_key), patches in groups.items():
        devices = sorted({p.device_id for p in patches})
        security = any((p.classification or "").lower() in ("security", "critical") or _severity(p.severity) in ("critical", "high")
                       for p in patches)
        errors = sorted({p.error for p in patches if p.error})
        items.append(Item(key=f"patch:{tenant_id}:{patch_key}", kind="patch", tenant_id=tenant_id,
                          title=f"Update failed: {patches[0].title or patch_key}", severity="high" if security else "medium",
                          first_seen=min(p.first_seen_at for p in patches), last_seen=max(p.last_seen_at for p in patches),
                          summary="; ".join(errors)[:300], device_ids=devices, count=len(devices), link="/patching",
                          marker=_digest(devices), refs=[str(p.id) for p in patches]))
    return items


def _jobs(db: Session, scope: list[str], now: datetime) -> list[Item]:
    rows = db.execute(select(Job).where(Job.tenant_id.in_(scope), Job.status.in_(("failed", "partial")),
                                        Job.finished_at >= now - JOB_WINDOW).order_by(Job.finished_at.desc()).limit(500)).scalars().all()
    command_ids = [c for job in rows for c in (job.command_ids or {}).values()]
    failed = {c.id: c.device_id for c in db.execute(select(Command).where(
        Command.id.in_(command_ids), Command.status.in_(("failed", "expired")))).scalars()} if command_ids else {}
    items = []
    for job in rows:
        devices = sorted({failed[c] for c in (job.command_ids or {}).values() if c in failed})
        items.append(Item(key=f"job:{job.tenant_id}:{job.id}", kind="job", tenant_id=job.tenant_id, title=f"Job failed: {job.name}",
                          severity="medium", first_seen=job.finished_at, summary=f"{len(devices)} devices failed",
                          device_ids=devices, count=max(1, len(devices)), link=f"/automation?job={job.id}", refs=[job.id]))
    return items


def _elevations(db: Session, scope: list[str], now: datetime) -> list[Item]:
    rows = db.execute(select(ElevationRequest).where(ElevationRequest.tenant_id.in_(scope), ElevationRequest.status == "pending")
                      .order_by(ElevationRequest.created_at).limit(MAX_ROWS)).scalars().all()
    return [Item(key=f"elevation:{r.tenant_id}:{r.id}", kind="elevation", tenant_id=r.tenant_id,
                 title=f"Admin rights requested by {r.user}", severity="high", first_seen=r.created_at,
                 summary=(r.reason or r.target or "")[:300], device_ids=[r.device_id], link="/admin-requests", refs=[r.id]) for r in rows]


def _approvals(db: Session, scope: list[str], now: datetime, actor: str) -> list[Item]:
    rows = db.execute(select(ApprovalRequest).where(ApprovalRequest.tenant_id.in_(scope), ApprovalRequest.status == "pending",
                                                    ApprovalRequest.expires_at > now, ApprovalRequest.requested_by != actor)
                      .limit(MAX_ROWS)).scalars().all()
    return [Item(key=f"approval:{r.tenant_id}:{r.id}", kind="approval", tenant_id=r.tenant_id, title=f"Approval needed: {r.summary}",
                 severity="high", first_seen=r.requested_at, summary=f"Requested by {r.requested_by}",
                 device_ids=list(r.device_ids or [])[:500], count=max(1, len(r.device_ids or [])), sla_due=r.expires_at,
                 link="/settings?tab=Approvals", refs=[r.id]) for r in rows]


def _m365(db: Session, scope: list[str], now: datetime) -> list[Item]:
    rows = db.execute(select(M365StandardRun).where(M365StandardRun.tenant_id.in_(scope))
                      .order_by(M365StandardRun.at.desc()).limit(MAX_ROWS * 2)).scalars().all()
    latest: dict[tuple[str, str], M365StandardRun] = {}
    for run in rows:
        latest.setdefault((run.tenant_id, run.standard), run)
    items = []
    for (tenant_id, standard), run in latest.items():
        if run.status not in ("drifted", "failed"):
            continue
        items.append(Item(key=f"m365:{tenant_id}:{standard}", kind="m365", tenant_id=tenant_id,
                          title=f"Microsoft 365 standard {run.status}: {standard}", severity="medium", first_seen=run.at,
                          summary=str((run.details or {}).get("message") or (run.details or {}).get("error") or "")[:300],
                          link="/m365", marker=_digest([run.status, run.details]), refs=[run.id]))
    return items


def _grc(db: Session, scope: list[str], now: datetime) -> list[Item]:
    rows = db.execute(select(GrcRequirementState).where(
        GrcRequirementState.tenant_id.in_(scope), GrcRequirementState.due_date.is_not(None), GrcRequirementState.due_date < now,
        GrcRequirementState.status.notin_(("implemented", "not_applicable"))).limit(MAX_ROWS)).scalars().all()
    groups: dict[tuple[str, str], list[GrcRequirementState]] = {}
    for row in rows:
        groups.setdefault((row.tenant_id, row.framework_key), []).append(row)
    items = []
    for (tenant_id, framework), states in groups.items():
        owners = {s.owner for s in states if s.owner}
        items.append(Item(key=f"grc:{tenant_id}:{framework}", kind="grc", tenant_id=tenant_id,
                          title=f"{len(states)} {framework} requirements past their due date", severity="low",
                          first_seen=min(s.due_date for s in states), sla_due=min(s.due_date for s in states),
                          summary=", ".join(sorted(s.requirement_id for s in states)[:10]), count=len(states),
                          owner=owners.pop() if len(owners) == 1 else None, link=f"/governance/{tenant_id}/{framework}",
                          marker=_digest(sorted(s.requirement_id for s in states)), refs=[s.id for s in states]))
    return items


def _evidence(db: Session, scope: list[str], now: datetime) -> list[Item]:
    rows = db.execute(select(GrcEvidence).where(GrcEvidence.tenant_id.in_(scope), GrcEvidence.valid_until.is_not(None),
                                                GrcEvidence.valid_until < now + EVIDENCE_NOTICE).limit(MAX_ROWS)).scalars().all()
    groups: dict[str, list[GrcEvidence]] = {}
    for row in rows:
        groups.setdefault(row.tenant_id, []).append(row)
    items = []
    for tenant_id, evidence in groups.items():
        expired = [e for e in evidence if e.valid_until < now]
        items.append(Item(key=f"evidence:{tenant_id}:expiring", kind="evidence", tenant_id=tenant_id,
                          title=f"{len(expired)} evidence items expired" if expired else f"{len(evidence)} evidence items expire within 14 days",
                          severity="medium" if expired else "low", first_seen=min(e.created_at for e in evidence),
                          sla_due=min(e.valid_until for e in evidence), summary=", ".join(sorted(e.title for e in evidence)[:5]),
                          count=len(evidence), link="/governance", marker=_digest(sorted(e.id for e in evidence)),
                          refs=[e.id for e in evidence]))
    return items


def collect(db: Session, scope: list[str], actor: str, kinds: tuple[str, ...] = KINDS, now: datetime | None = None) -> list[Item]:
    now = now or utcnow()
    sources = {"alert": lambda: _alerts(db, scope, now), "incident": lambda: _incidents(db, scope, now),
               "ticket": lambda: _tickets(db, scope, now, actor), "patch": lambda: _patches(db, scope, now),
               "job": lambda: _jobs(db, scope, now), "elevation": lambda: _elevations(db, scope, now),
               "approval": lambda: _approvals(db, scope, now, actor), "m365": lambda: _m365(db, scope, now),
               "grc": lambda: _grc(db, scope, now), "evidence": lambda: _evidence(db, scope, now)}
    items = [item for kind in kinds if kind in sources for item in sources[kind]()]
    hours = sla_hours(db)
    states = {s.key: s for s in db.execute(select(TriageState).where(TriageState.key.in_([i.key for i in items]))).scalars()} if items else {}
    for item in items:
        if item.sla_due is None:
            item.sla_due = item.first_seen + timedelta(hours=hours[item.severity])
        state = states.get(item.key)
        if state is None:
            continue
        if item.kind not in NATIVE_OWNER:
            item.owner = state.owner or item.owner
            item.snoozed_until = state.snoozed_until if state.snoozed_until and state.snoozed_until > now else None
        item.ticket_id = item.ticket_id or state.ticket_id
        item.dismissed = item.kind in DISMISSIBLE and item.kind != "alert" and state.dismissed_marker is not None \
            and state.dismissed_marker == item.marker
    return items


def find_many(db: Session, principal, keys: list[str]) -> list[Item]:
    """The items behind these keys, if they still exist and their customers are in the caller's scope. Each source is
    rebuilt once per customer, however many of its items were picked."""
    from fastapi import HTTPException

    wanted: dict[tuple[str, str], set[str]] = {}
    for key in keys:
        parts = key.split(":", 2)
        if len(parts) != 3 or parts[0] not in KINDS or parts[1] not in principal.tenant_ids:
            raise HTTPException(404, "No such item")
        wanted.setdefault((parts[0], parts[1]), set()).add(key)
    found: dict[str, Item] = {}
    for (kind, tenant_id), group in wanted.items():
        found.update({i.key: i for i in collect(db, [tenant_id], principal.actor, (kind,)) if i.key in group})
    missing = [k for k in keys if k not in found]
    if missing:
        raise HTTPException(404, "This item is no longer open" if len(keys) == 1 else f"{len(missing)} of these items are no longer open")
    return [found[k] for k in keys]


def find(db: Session, principal, key: str) -> Item:
    return find_many(db, principal, [key])[0]


def state_for(db: Session, item: Item) -> TriageState:
    state = db.get(TriageState, item.key)
    if state is None:
        state = TriageState(key=item.key, tenant_id=item.tenant_id)
        db.add(state)
    state.updated_at = utcnow()
    return state


def order(items: list[Item], now: datetime) -> list[Item]:
    """Past SLA first, then the most severe, then the soonest due."""
    return sorted(items, key=lambda i: (not (i.sla_due and i.sla_due < now), RANK[i.severity], i.sla_due or now, i.title))


def view(item: Item, now: datetime, customers: dict[str, str], hosts: dict[str, str]) -> dict:
    iso = lambda d: d.isoformat() + "Z" if d else None  # noqa: E731
    return {"key": item.key, "kind": item.kind, "title": item.title, "summary": item.summary, "severity": item.severity,
            "tenantId": item.tenant_id, "customer": customers.get(item.tenant_id, ""), "count": item.count,
            "deviceIds": item.device_ids[:50], "deviceCount": len(item.device_ids),
            "hostnames": [hosts[d] for d in item.device_ids[:5] if d in hosts], "owner": item.owner,
            "snoozedUntil": iso(item.snoozed_until), "slaDueAt": iso(item.sla_due), "breached": bool(item.sla_due and item.sla_due < now),
            "firstSeenAt": iso(item.first_seen), "lastSeenAt": iso(item.last_seen), "link": item.link, "ticketId": item.ticket_id,
            "dismissed": item.dismissed, "canDismiss": item.kind in DISMISSIBLE, "ownerOnItem": item.kind in NATIVE_OWNER}


def names(db: Session, items: list[Item]) -> tuple[dict[str, str], dict[str, str]]:
    tenant_ids = {i.tenant_id for i in items}
    device_ids = {d for i in items for d in i.device_ids[:5]}
    customers = dict(db.execute(select(Tenant.id, Tenant.name).where(Tenant.id.in_(tenant_ids))).all()) if tenant_ids else {}
    hosts = dict(db.execute(select(Device.id, Device.hostname).where(Device.id.in_(device_ids))).all()) if device_ids else {}
    return customers, hosts
