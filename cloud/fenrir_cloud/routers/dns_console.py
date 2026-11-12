"""DNS protection console: overview, query explorer, per-device results, rules and lists, and the Fenrir ruleset.

Viewing needs ``read``; rules and lists for a customer need ``configure``; MSP-wide rules (on the MSP's own tenant),
the Fenrir ruleset and its settings need ``platform``. Customers only ever see their own devices, queries and rules,
plus the MSP-wide rules that apply to them (read-only).
"""
from __future__ import annotations

import csv
import io
import re
from collections import Counter
from datetime import datetime, timedelta

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import audit, blocklists, dns_rules, dns_ruleset, dnsfilter, services
from ..db import get_db, session_factory
from ..deps import Principal, current_principal, scoped_tenant
from ..models import Device, DeviceGroup, DnsDeviceDay, DnsQueryLog, DnsRule, DnsRuleset, Event, Tenant, utcnow

router = APIRouter(prefix="/api/console/dns", tags=["DNS protection"])


def _tenant(db: Session, principal: Principal, tenant_id: str | None) -> Tenant:
    tid = tenant_id or principal.user.tenant_id
    principal.check_tenant(tid)
    tenant = db.get(Tenant, tid)
    if tenant is None:
        raise HTTPException(404, "Customer not found")
    return tenant


def _require_write(principal: Principal, tenant: Tenant) -> None:
    principal.require("platform" if tenant.kind == "msp" else "configure")


def _names(db: Session, ids: list[str]) -> dict[str, str]:
    if not ids:
        return {}
    out = {d.id: d.hostname for d in db.execute(select(Device).where(Device.id.in_(ids))).scalars()}
    out.update({g.id: g.name for g in db.execute(select(DeviceGroup).where(DeviceGroup.id.in_(ids))).scalars()})
    return out


def _device_names(db: Session, ids: set[str]) -> dict[str, str]:
    ids = {i for i in ids if i}
    return {d.id: d.hostname for d in db.execute(select(Device).where(Device.id.in_(ids))).scalars()} if ids else {}


# --------------------------------------------------------------------------- overview


@router.get("/overview")
def overview(tenant_id: str | None = None, days: int = Query(7, ge=1, le=90), principal: Principal = Depends(current_principal),
             db: Session = Depends(get_db)):
    principal.require("read")
    scope = scoped_tenant(principal, tenant_id)
    dnsfilter.flush_counts(db, force=True)
    db.commit()
    since_day = (utcnow() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    daily = db.execute(select(DnsDeviceDay.day, func.sum(DnsDeviceDay.queries), func.sum(DnsDeviceDay.blocked))
                       .where(DnsDeviceDay.tenant_id.in_(scope), DnsDeviceDay.day >= since_day)
                       .group_by(DnsDeviceDay.day).order_by(DnsDeviceDay.day)).all()
    queries = sum(int(q or 0) for _, q, _ in daily)
    blocked = sum(int(b or 0) for _, _, b in daily)
    since = utcnow() - timedelta(days=days)
    logs = db.execute(select(DnsQueryLog.qname, DnsQueryLog.category, DnsQueryLog.device_id, DnsQueryLog.source, DnsQueryLog.action)
                      .where(DnsQueryLog.tenant_id.in_(scope), DnsQueryLog.at >= since).limit(200000)).all()
    blocks = [r for r in logs if r.action == "block"]
    top_devices = Counter(r.device_id for r in blocks if r.device_id).most_common(10)
    names = _device_names(db, {d for d, _ in top_devices})
    devices_total = db.execute(select(func.count()).select_from(Device).where(Device.tenant_id.in_(scope))).scalar() or 0
    devices_active = db.execute(select(func.count(func.distinct(DnsDeviceDay.device_id))).where(
        DnsDeviceDay.tenant_id.in_(scope), DnsDeviceDay.day >= (utcnow() - timedelta(days=1)).strftime("%Y-%m-%d"))).scalar() or 0
    rules_active = db.execute(select(func.count()).select_from(DnsRule).where(
        DnsRule.tenant_id.in_(scope), DnsRule.enabled.is_(True), DnsRule.kind == "rule")).scalar() or 0
    entries_active = db.execute(select(func.count()).select_from(DnsRule).where(
        DnsRule.tenant_id.in_(scope), DnsRule.enabled.is_(True), DnsRule.kind == "entry")).scalar() or 0
    active = db.execute(select(DnsRuleset).where(DnsRuleset.active.is_(True))).scalars().first()
    return {"days": days, "queries": queries, "blocked": blocked, "blockRate": round(100 * blocked / queries, 2) if queries else 0,
            "monitored": sum(1 for r in logs if r.action == "monitor"),
            "daily": [{"day": d, "queries": int(q or 0), "blocked": int(b or 0)} for d, q, b in daily],
            "topDomains": Counter(r.qname for r in blocks).most_common(10), "topCategories": Counter(r.category for r in blocks if r.category).most_common(10),
            "bySource": Counter(r.source or "other" for r in blocks).most_common(),
            "topDevices": [{"id": d, "hostname": names.get(d, d), "blocked": n} for d, n in top_devices],
            "devices": {"total": devices_total, "activeToday": devices_active}, "rules": rules_active, "entries": entries_active,
            "expiringSoon": dns_rules.expiring(db, scope),
            "ruleset": dns_ruleset.view(active) if active else None}


# --------------------------------------------------------------------------- query explorer


def _queries(db: Session, principal: Principal, tenant_id, device_id, q, action, category, source, rule_id, hours, limit):
    scope = scoped_tenant(principal, tenant_id)
    query = select(DnsQueryLog).where(DnsQueryLog.tenant_id.in_(scope), DnsQueryLog.at >= utcnow() - timedelta(hours=hours))
    if device_id:
        query = query.where(DnsQueryLog.device_id == device_id)
    if q:
        query = query.where(DnsQueryLog.qname.ilike(f"%{q.strip().lower()[:200]}%"))
    if action:
        query = query.where(DnsQueryLog.action == action)
    if category:
        query = query.where(DnsQueryLog.category == category)
    if source:
        query = query.where(DnsQueryLog.source == source)
    if rule_id:
        query = query.where(DnsQueryLog.rule_id == rule_id)
    return db.execute(query.order_by(DnsQueryLog.at.desc()).limit(limit)).scalars().all()


def _query_view(row: DnsQueryLog, names: dict[str, str]) -> dict:
    return {"id": row.id, "at": row.at.isoformat() + "Z", "tenantId": row.tenant_id, "deviceId": row.device_id,
            "hostname": names.get(row.device_id or "", ""), "qname": row.qname, "qtype": row.qtype, "action": row.action,
            "reason": row.reason, "category": row.category, "source": row.source or "", "ruleId": row.rule_id or "", "score": row.score}


@router.get("/queries")
def queries(tenant_id: str | None = None, device_id: str | None = None, q: str = "", action: str = "", category: str = "",
            source: str = "", rule_id: str = "", hours: int = Query(24, ge=1, le=24 * 90), limit: int = Query(500, ge=1, le=5000),
            principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    rows = _queries(db, principal, tenant_id, device_id, q, action, category, source, rule_id, hours, limit)
    names = _device_names(db, {r.device_id for r in rows})
    return [_query_view(r, names) for r in rows]


@router.get("/queries.csv")
def queries_csv(tenant_id: str | None = None, device_id: str | None = None, q: str = "", action: str = "", category: str = "",
                source: str = "", rule_id: str = "", hours: int = Query(24, ge=1, le=24 * 90),
                principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    rows = _queries(db, principal, tenant_id, device_id, q, action, category, source, rule_id, hours, 50000)
    names = _device_names(db, {r.device_id for r in rows})
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["time", "device", "domain", "type", "action", "category", "decided by", "reason", "score"])

    def safe(value) -> str:  # a cell starting with = + - @ would run as a formula in Excel
        text = "" if value is None else str(value)
        return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text
    for r in rows:
        writer.writerow([safe(v) for v in (r.at.isoformat() + "Z", names.get(r.device_id or "", r.device_id), r.qname, r.qtype,
                                            r.action, r.category, r.source, r.reason, r.score)])
    return Response(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="fenrir-dns.csv"'})


# --------------------------------------------------------------------------- per device


def _proxy_status(events: list[Event]) -> dict:
    """The device's local DNS proxy, from the agent's own events (newest first)."""
    state = {"state": "not reported", "detail": "", "at": None}
    for event in events:
        kind = event.event_type
        if kind in ("dns.proxy.rule_applied", "dns.proxy.started"):
            state = {"state": "on", "detail": event.summary, "at": event.occurred_at.isoformat() + "Z"}
        elif kind in ("dns.proxy.failed", "dns.proxy.rule_failed"):
            state = {"state": "problem", "detail": event.summary, "at": event.occurred_at.isoformat() + "Z"}
        elif kind == "dns.proxy.skipped":
            state = {"state": "skipped", "detail": event.summary, "at": event.occurred_at.isoformat() + "Z"}
        elif kind == "dns.proxy.stopped":
            state = {"state": "off", "detail": event.summary, "at": event.occurred_at.isoformat() + "Z"}
        else:
            continue
        break
    return state


@router.get("/devices")
def devices(tenant_id: str | None = None, q: str = "", principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    scope = scoped_tenant(principal, tenant_id)
    dnsfilter.flush_counts(db, force=True)
    db.commit()
    query = select(Device).where(Device.tenant_id.in_(scope))
    if q:
        query = query.where(Device.hostname.ilike(f"%{q.strip()[:100]}%"))
    rows = db.execute(query.order_by(Device.hostname).limit(2000)).scalars().all()
    ids = [d.id for d in rows]
    today = utcnow().strftime("%Y-%m-%d")
    week = (utcnow() - timedelta(days=6)).strftime("%Y-%m-%d")
    totals: dict[str, list[int]] = {}
    for device_id, day, queries_, blocked in db.execute(select(DnsDeviceDay.device_id, DnsDeviceDay.day, DnsDeviceDay.queries,
                                                               DnsDeviceDay.blocked).where(DnsDeviceDay.device_id.in_(ids), DnsDeviceDay.day >= week)):
        entry = totals.setdefault(device_id, [0, 0, 0, 0])
        entry[2] += queries_
        entry[3] += blocked
        if day == today:
            entry[0] += queries_
            entry[1] += blocked
    proxy_events: dict[str, list[Event]] = {}
    for event in db.execute(select(Event).where(Event.device_id.in_(ids), Event.event_type.like("dns.proxy.%"),
                                                Event.occurred_at >= utcnow() - timedelta(days=30))
                            .order_by(Event.occurred_at.desc()).limit(20000)).scalars():
        proxy_events.setdefault(event.device_id, []).append(event)
    last_block = dict(db.execute(select(DnsQueryLog.device_id, func.max(DnsQueryLog.at)).where(
        DnsQueryLog.device_id.in_(ids), DnsQueryLog.action == "block").group_by(DnsQueryLog.device_id)).all())
    out = []
    for d in rows:
        t = totals.get(d.id, [0, 0, 0, 0])
        out.append({"id": d.id, "tenantId": d.tenant_id, "hostname": d.hostname, "platform": d.platform, "lastSeenAt": d.last_seen_at.isoformat() + "Z" if getattr(d, "last_seen_at", None) else None,
                    "queriesToday": t[0], "blockedToday": t[1], "queries7d": t[2], "blocked7d": t[3],
                    "lastBlockAt": last_block[d.id].isoformat() + "Z" if last_block.get(d.id) else None,
                    "proxy": _proxy_status(proxy_events.get(d.id, [])), "resolving": t[2] > 0})
    return out


@router.get("/devices/{device_id}")
def device_detail(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(device.tenant_id)
    dnsfilter.flush_counts(db, force=True)
    db.commit()
    resolution, _ = services.effective_policy(db, device)
    dns_settings = resolution["settings"]["dns"]
    since_day = (utcnow() - timedelta(days=13)).strftime("%Y-%m-%d")
    daily = db.execute(select(DnsDeviceDay.day, DnsDeviceDay.queries, DnsDeviceDay.blocked).where(
        DnsDeviceDay.device_id == device.id, DnsDeviceDay.day >= since_day).order_by(DnsDeviceDay.day)).all()
    recent = db.execute(select(DnsQueryLog).where(DnsQueryLog.device_id == device.id).order_by(DnsQueryLog.at.desc()).limit(200)).scalars().all()
    blocks = [r for r in recent if r.action == "block"]
    events = db.execute(select(Event).where(Event.device_id == device.id, Event.event_type.like("dns.%"))
                        .order_by(Event.occurred_at.desc()).limit(30)).scalars().all()
    rules = dns_rules.CACHE.for_device(db, device)
    applying = [{"id": r.id, "name": r.name, "kind": r.kind, "action": r.action, "mode": r.mode, "scopeType": r.scope_type,
                 "mspWide": r.msp} for r in rules.rules
                if r.scope_type == "tenant" or (r.scope_type == "device" and device.id in r.scope_ids)
                or (r.scope_type == "group" and r.scope_ids & rules.group_ids)]
    group = db.get(DeviceGroup, device.group_id) if device.group_id else None
    return {"device": {"id": device.id, "hostname": device.hostname, "platform": device.platform, "tenantId": device.tenant_id,
                       "groupId": device.group_id, "groupName": group.name if group else ""},
            "policy": {"origins": sorted({v for k, v in (resolution.get("origin") or {}).items() if k.startswith("dns.") and v != "default"}),
                       "enabled": dns_settings.get("enabled"), "mode": dns_settings.get("mode"),
                       "blockedCategories": dns_settings.get("blockedCategories", []), "fenrirRuleset": dns_settings.get("fenrirRuleset", "block"),
                       "externalLists": dns_settings.get("externalLists", "direct"), "logQueries": dns_settings.get("logQueries"),
                       "localProxy": dns_settings.get("localProxy"), "localProxyFailMode": dns_settings.get("localProxyFailMode"),
                       "safeSearch": dns_settings.get("safeSearch"), "allowDomains": len(dns_settings.get("allowDomains", [])),
                       "blockDomains": len(dns_settings.get("blockDomains", []))},
            "proxy": _proxy_status([e for e in events if e.event_type.startswith("dns.proxy.")]),
            "events": [{"type": e.event_type, "summary": e.summary, "at": e.occurred_at.isoformat() + "Z"} for e in events],
            "daily": [{"day": d, "queries": q, "blocked": b} for d, q, b in daily],
            "topBlocked": Counter(r.qname for r in blocks).most_common(10),
            "categories": Counter(r.category for r in blocks if r.category).most_common(10),
            "recent": [_query_view(r, {device.id: device.hostname}) for r in recent[:100]], "rules": applying}


# --------------------------------------------------------------------------- domain check (explains every step)


@router.get("/explain")
def explain(domain: str, device_id: str | None = None, tenant_id: str | None = None, qtype: str = "A",
            principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    domain = domain.strip().lower().rstrip(".")
    domain = re.sub(r"^[a-z]+://", "", domain).split("/")[0]
    if not domain or len(domain) > 253:
        raise HTTPException(422, "Enter a domain")
    if device_id:
        device = db.get(Device, device_id)
        if device is None:
            raise HTTPException(404, "Not found")
        principal.check_tenant(device.tenant_id)
        resolution, _ = services.effective_policy(db, device)
        tid, rules = device.tenant_id, dns_rules.CACHE.for_device(db, device)
    else:
        tenant = _tenant(db, principal, tenant_id)
        from ..policy_schema import resolve

        resolution = resolve(services.policy_layers(db, tenant))
        tid, rules = tenant.id, dns_rules.CACHE.for_tenant(db, tenant.id)
    settings = resolution["settings"]["dns"]
    decision = dnsfilter.decide(domain, settings, dnsfilter.INTEL.domains(db, tid), blocklists.CACHE.active(db), rules=rules,
                                ruleset=dns_ruleset.CACHE.active(db), qtype=qtype.upper())
    if settings.get("mode") == "observe" and decision.action == "block":
        decision.trail.append("Policy is in observe mode: logged, not blocked")
    return {"domain": domain, "action": decision.action, "reason": decision.reason or "no rule, list or category matched",
            "category": decision.category, "source": decision.source, "ruleId": decision.rule_id, "score": decision.score,
            "trail": decision.trail, "audits": decision.audits, "observe": settings.get("mode") == "observe",
            "dgaLike": dnsfilter.looks_like_dga(domain), "ruleset": dns_ruleset.explain(db, domain), "deviceId": device_id}


# --------------------------------------------------------------------------- rules and lists


@router.get("/rules")
def list_rules(tenant_id: str | None = None, kind: str = "", principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    scope = scoped_tenant(principal, tenant_id)
    # MSP-wide rules apply to every customer: shown (read-only to customer staff) alongside the customer's own.
    msp_ids = [t.id for t in db.execute(select(Tenant).where(Tenant.kind == "msp")).scalars()]
    query = select(DnsRule).where(or_(DnsRule.tenant_id.in_(scope), DnsRule.tenant_id.in_(msp_ids)))
    if kind:
        query = query.where(DnsRule.kind == kind)
    rows = db.execute(query.order_by(DnsRule.priority, DnsRule.created_at)).scalars().all()
    names = _names(db, sorted({i for r in rows for i in (r.scope_ids or [])}))
    return [{**dns_rules.view(r, names), "mspWide": r.tenant_id in msp_ids, "editable": r.tenant_id in principal.tenant_ids} for r in rows]


def _owned_rule(db: Session, principal: Principal, rule_id: str) -> DnsRule:
    rule = db.get(DnsRule, rule_id)
    if rule is None or rule.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    return rule


@router.post("/rules")
def create_rule(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    tenant = _tenant(db, principal, body.get("tenantId"))
    _require_write(principal, tenant)
    try:
        clean = dns_rules.validate(db, tenant.id, body, principal.tenant_ids if tenant.kind == "msp" else None)
    except dns_rules.RuleError as exc:
        raise HTTPException(422, str(exc)) from None
    rule = dns_rules.save(db, tenant.id, clean, principal.actor, comment=str(body.get("changeComment") or ""))
    audit.record(db, principal.actor, f"dns.{rule.kind}.create", rule.id, tenant.id, rule_action=rule.action, patterns=rule.patterns[:5])
    db.commit()
    return dns_rules.view(rule, _names(db, rule.scope_ids or []))


@router.put("/rules/{rule_id}")
def update_rule(rule_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rule = _owned_rule(db, principal, rule_id)
    tenant = db.get(Tenant, rule.tenant_id)
    _require_write(principal, tenant)
    try:
        clean = dns_rules.validate(db, tenant.id, {**dns_rules.view(rule), **body}, principal.tenant_ids if tenant.kind == "msp" else None)
    except dns_rules.RuleError as exc:
        raise HTTPException(422, str(exc)) from None
    dns_rules.save(db, tenant.id, clean, principal.actor, rule, comment=str(body.get("changeComment") or ""))
    audit.record(db, principal.actor, f"dns.{rule.kind}.update", rule.id, tenant.id, version=rule.version)
    db.commit()
    return dns_rules.view(rule, _names(db, rule.scope_ids or []))


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rule = _owned_rule(db, principal, rule_id)
    tenant = db.get(Tenant, rule.tenant_id)
    _require_write(principal, tenant)
    dns_rules.delete(db, rule, principal.actor)
    audit.record(db, principal.actor, f"dns.{rule.kind}.delete", rule_id, tenant.id)
    db.commit()
    return {"deleted": rule_id}


@router.get("/rules/{rule_id}/history")
def rule_history(rule_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    rows = dns_rules.history(db, rule_id)
    if not rows or rows[0].tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    return [{"version": r.version, "change": r.change, "actor": r.actor, "comment": r.comment, "at": r.at.isoformat() + "Z",
             "changes": r.changes, "snapshot": r.snapshot} for r in rows]


@router.post("/rules/{rule_id}/restore/{version}")
def restore_rule(rule_id: str, version: int, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Put a rule back as it was in an earlier version (as a new version), or bring back a deleted rule."""
    rows = dns_rules.history(db, rule_id)
    if not rows or rows[0].tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    tenant = db.get(Tenant, rows[0].tenant_id)
    _require_write(principal, tenant)
    target = next((r for r in rows if r.version == version and r.change != "delete"), None)
    if target is None:
        raise HTTPException(404, "No such version")
    rule = db.get(DnsRule, rule_id)
    if rule is None:
        rule = DnsRule(id=rule_id, tenant_id=tenant.id, created_by=principal.actor, version=rows[0].version)
        db.add(rule)
    dns_rules.save(db, tenant.id, dns_rules.restore_clean(target.snapshot), principal.actor, rule,
                   comment=f"Restored version {version}", change="restore")
    audit.record(db, principal.actor, "dns.rule.restore", rule_id, tenant.id, version=version)
    db.commit()
    return dns_rules.view(rule)


@router.post("/rules/import")
def import_entries(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Paste many domains at once: one allow or block entry per domain (so each has its own hit count)."""
    tenant = _tenant(db, principal, body.get("tenantId"))
    _require_write(principal, tenant)
    text = str(body.get("text") or "")
    lines = [re.split(r"\s+", line.strip())[-1] for line in text.splitlines() if line.strip() and not line.strip().startswith(("#", "!"))]
    if not lines:
        raise HTTPException(422, "Paste at least one domain")
    if len(lines) > 5000:
        raise HTTPException(422, "At most 5,000 domains at once")
    existing = {(r.action, tuple(r.patterns or [])) for r in db.execute(select(DnsRule).where(
        DnsRule.tenant_id == tenant.id, DnsRule.kind == "entry")).scalars()}
    created, skipped, errors = 0, 0, []
    for line in lines:
        try:
            clean = dns_rules.validate(db, tenant.id, {**body, "kind": "entry", "patterns": [line], "name": ""},
                                       principal.tenant_ids if tenant.kind == "msp" else None)
        except dns_rules.RuleError as exc:
            errors.append(f"{line}: {exc}")
            continue
        if (clean["action"], tuple(clean["patterns"])) in existing:
            skipped += 1
            continue
        existing.add((clean["action"], tuple(clean["patterns"])))
        dns_rules.save(db, tenant.id, clean, principal.actor, comment="Imported")
        created += 1
    audit.record(db, principal.actor, "dns.entry.import", tenant.id, tenant.id, created=created, skipped=skipped, errors=len(errors))
    db.commit()
    return {"created": created, "skipped": skipped, "errors": errors[:50]}


@router.post("/quick")
def quick_entry(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """One click from the query explorer or a device: allow or block a domain for that device or the whole customer."""
    device = db.get(Device, body.get("deviceId")) if body.get("deviceId") else None
    tenant = _tenant(db, principal, device.tenant_id if device else body.get("tenantId"))
    _require_write(principal, tenant)
    scope = body.get("scope", "tenant")
    payload = {"kind": "entry", "action": body.get("action", "allow"), "match": "domain", "patterns": [body.get("domain", "")],
               "scopeType": "device" if scope == "device" and device else "tenant", "scopeIds": [device.id] if scope == "device" and device else [],
               "comment": str(body.get("comment") or "")[:500], "expiresAt": body.get("expiresAt")}
    try:
        clean = dns_rules.validate(db, tenant.id, payload)
    except dns_rules.RuleError as exc:
        raise HTTPException(422, str(exc)) from None
    rule = dns_rules.save(db, tenant.id, clean, principal.actor, comment="From the query log")
    audit.record(db, principal.actor, "dns.entry.create", rule.id, tenant.id, rule_action=rule.action, patterns=rule.patterns)
    db.commit()
    return dns_rules.view(rule, _names(db, rule.scope_ids or []))


@router.get("/scope-options")
def scope_options(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Groups and devices a rule can target."""
    principal.require("read")
    scope = scoped_tenant(principal, tenant_id)
    groups = db.execute(select(DeviceGroup).where(DeviceGroup.tenant_id.in_(scope)).order_by(DeviceGroup.name)).scalars().all()
    devices_ = db.execute(select(Device.id, Device.hostname, Device.tenant_id).where(Device.tenant_id.in_(scope))
                          .order_by(Device.hostname).limit(5000)).all()
    return {"groups": [{"id": g.id, "name": g.name, "tenantId": g.tenant_id} for g in groups],
            "devices": [{"id": d, "name": h, "tenantId": t} for d, h, t in devices_]}


# --------------------------------------------------------------------------- the Fenrir ruleset

_BUILD = {"running": False, "error": "", "startedAt": None}


def _build_job(actor: str) -> None:
    db = session_factory()()
    try:
        row = dns_ruleset.build(db, actor)
        audit.record(db, actor, "dns.ruleset.build", row.id, None, version=row.version, domains=row.domain_count)
        db.commit()
        _BUILD["error"] = ""
    except Exception as exc:  # noqa: BLE001 - reported to the console
        db.rollback()
        _BUILD["error"] = str(exc)[:300]
    finally:
        db.close()
        _BUILD["running"] = False


@router.get("/ruleset")
def ruleset(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    cfg = dns_ruleset.config(db)
    builds = db.execute(select(DnsRuleset).order_by(DnsRuleset.version.desc()).limit(10)).scalars().all()
    lists = db.execute(select(blocklists.DnsBlocklist).order_by(blocklists.DnsBlocklist.builtin.desc(), blocklists.DnsBlocklist.id)).scalars().all()
    used = {s["id"] for s in dns_ruleset.list_sources(db, cfg)}
    sources = [{"id": l.id, "name": l.name, "category": l.category, "enabled": l.enabled, "domains": l.domain_count,
                "weight": int(cfg["weights"].get(l.id, dns_ruleset.CUSTOM_WEIGHT if not l.builtin else 0)), "inRuleset": l.id in used}
               for l in lists]
    return {"config": {k: cfg[k] for k in ("blockThreshold", "monitorThreshold", "intelWeight", "protected", "autoBuild")},
            "builtinProtected": list(dns_ruleset.PROTECTED), "sources": sources, "builds": [dns_ruleset.view(b) for b in builds],
            "building": _BUILD["running"], "buildError": _BUILD["error"], "canManage": _can(principal, "platform")}


def _can(principal: Principal, permission: str) -> bool:
    try:
        principal.require(permission)
        return True
    except HTTPException:
        return False


@router.put("/ruleset/config")
def ruleset_config(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("platform")
    try:
        cfg = dns_ruleset.save_config(db, body)
    except (ValueError, dns_rules.RuleError) as exc:
        raise HTTPException(422, str(exc)) from None
    audit.record(db, principal.actor, "dns.ruleset.config", "dns-ruleset", None,
                 **{k: body[k] for k in body if k in ("blockThreshold", "monitorThreshold", "intelWeight", "autoBuild")})
    db.commit()
    return cfg


@router.post("/ruleset/build")
def ruleset_build(background: BackgroundTasks, principal: Principal = Depends(current_principal)):
    principal.require("platform")
    if _BUILD["running"]:
        raise HTTPException(409, "A build is already running")
    _BUILD.update(running=True, error="", startedAt=utcnow().isoformat() + "Z")
    background.add_task(_build_job, principal.actor)
    return {"building": True}


@router.post("/ruleset/{version}/activate")
def ruleset_activate(version: int, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("platform")
    row = db.execute(select(DnsRuleset).where(DnsRuleset.version == version)).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "No such build")
    dns_ruleset.activate_build(db, row)
    audit.record(db, principal.actor, "dns.ruleset.activate", row.id, None, version=version)
    db.commit()
    return dns_ruleset.view(row)


@router.get("/ruleset/explain")
def ruleset_explain(domain: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    return dns_ruleset.explain(db, domain)
