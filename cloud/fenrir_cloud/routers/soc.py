"""Security operations: dashboard, hunting, alerts, incidents, rules, automation."""

from __future__ import annotations

import re
import uuid
from collections import Counter
from datetime import timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import audit, evidence, services
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..detection import RULES, playbooks
from ..models import (Alert, AutomationRule, Command, DetectionRule, Device, DnsQueryLog, Event, Incident, Ticket,
                      Vulnerability, utcnow)
from ..serialize import apply_fields, to_dict
from ..sigma import CorrelationRule, SigmaError, lookup, parse_rule

router = APIRouter(prefix="/api/console", tags=["Security operations"])


# --------------------------------------------------------------------------- dashboard


@router.get("/dashboard")
def dashboard(tenant_id: str | None = None, days: int = Query(default=7, ge=1, le=90),
              principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    scope = scoped_tenant(principal, tenant_id)
    since = utcnow() - timedelta(days=days)
    online_cutoff = utcnow() - timedelta(minutes=10)
    devices = db.execute(select(Device).where(Device.tenant_id.in_(scope))).scalars().all()
    alerts = db.execute(select(Alert.severity, func.count()).where(Alert.tenant_id.in_(scope), Alert.created_at >= since)
                        .group_by(Alert.severity)).all()
    open_incidents = db.execute(select(Incident).where(Incident.tenant_id.in_(scope), Incident.status.notin_(("resolved", "closed")))
                                .order_by(Incident.created_at.desc()).limit(10)).scalars().all()
    per_day = db.execute(select(func.date(Alert.created_at), func.count()).where(Alert.tenant_id.in_(scope), Alert.created_at >= since)
                         .group_by(func.date(Alert.created_at))).all()
    top_rules = db.execute(select(Alert.title, func.count()).where(Alert.tenant_id.in_(scope), Alert.created_at >= since)
                           .group_by(Alert.title).order_by(func.count().desc()).limit(8)).all()
    mitre = Counter()
    for (tags,) in db.execute(select(Alert.mitre).where(Alert.tenant_id.in_(scope), Alert.created_at >= since)).all():
        mitre.update(t for t in tags or [] if t.startswith("T"))
    dns_blocked = db.execute(select(func.count()).where(DnsQueryLog.tenant_id.in_(scope), DnsQueryLog.at >= since,
                                                        DnsQueryLog.action == "block")).scalar() or 0
    threats_blocked = db.execute(select(func.count()).where(Event.tenant_id.in_(scope), Event.occurred_at >= since,
                                                            Event.category == "malware")).scalar() or 0
    vulns = db.execute(select(Vulnerability.severity, func.count()).where(Vulnerability.tenant_id.in_(scope),
                                                                          Vulnerability.status == "open")
                       .group_by(Vulnerability.severity)).all()
    kev = db.execute(select(func.count()).where(Vulnerability.tenant_id.in_(scope), Vulnerability.status == "open",
                                                Vulnerability.known_exploited.is_(True))).scalar() or 0
    open_tickets = db.execute(select(func.count()).where(or_(Ticket.account_tenant_id.in_(scope), Ticket.tenant_id.in_(scope)),
                                                         Ticket.status.notin_(("Resolved", "Closed")))).scalar() or 0
    breached = db.execute(select(func.count()).where(or_(Ticket.account_tenant_id.in_(scope), Ticket.tenant_id.in_(scope)),
                                                     Ticket.status.notin_(("Resolved", "Closed")), Ticket.sla_due_at < utcnow())).scalar() or 0
    return {
        "devices": {
            "total": len(devices),
            "online": sum(1 for d in devices if d.last_seen_at and d.last_seen_at >= online_cutoff),
            "isolated": sum(1 for d in devices if d.isolated),
            "pendingApproval": sum(1 for d in devices if not d.approved),
            "atRisk": sum(1 for d in devices if d.risk_score >= 40),
            "byPlatform": dict(Counter(d.platform for d in devices)),
            "outdatedPolicy": sum(1 for d in devices if d.applied_policy_revision == ""),
        },
        "alerts": {"bySeverity": dict(alerts), "perDay": [{"day": str(day), "count": count} for day, count in per_day],
                   "topRules": [{"title": t, "count": c} for t, c in top_rules]},
        "incidents": [to_dict(i) for i in open_incidents],
        "mitre": [{"technique": t, "count": c} for t, c in mitre.most_common(20)],
        "protection": {"dnsBlocked": dns_blocked, "threatEvents": threats_blocked},
        "vulnerabilities": {"bySeverity": dict(vulns), "knownExploited": kev},
        "psa": {"openTickets": open_tickets, "slaBreached": breached},
        "riskiestDevices": [{"id": d.id, "hostname": d.hostname, "riskScore": d.risk_score, "tenantId": d.tenant_id}
                            for d in sorted(devices, key=lambda d: -d.risk_score)[:8] if d.risk_score > 0],
    }


# --------------------------------------------------------------------------- hunting

_TERM = re.compile(r'(?:(?P<field>[A-Za-z_][\w.]*)\s*(?P<op>:|!=|>=|<=|>|<)\s*(?P<value>"[^"]*"|\S+))|(?P<word>"[^"]*"|\S+)')


def _compile_query(text: str):
    """Tiny hunting language: Field:value (wildcards ok), Field!=value, Field>N, bare words, OR between groups."""
    from ..sigma import _wildcard_regex

    groups = []
    for chunk in re.split(r"\s+OR\s+", text.strip()) if text.strip() else []:
        terms = []
        for match in _TERM.finditer(re.sub(r"\s+AND\s+", " ", chunk)):
            if match.group("field"):
                value = match.group("value").strip('"')
                terms.append((match.group("field"), match.group("op"), value, _wildcard_regex(value if "*" in value else value)))
            else:
                word = match.group("word").strip('"')
                terms.append((None, "~", word, _wildcard_regex(f"*{word}*")))
        groups.append(terms)

    def matches(event: Event) -> bool:
        if not groups:
            return True
        haystack = {**(event.fields or {}), "summary": event.summary, "EventType": event.event_type}
        for terms in groups:
            ok = True
            for field, op, value, regex in terms:
                if field is None:
                    if not any(regex.match(str(v)) for v in haystack.values() if v is not None):
                        ok = False
                        break
                    continue
                actual = lookup(haystack, field)
                if op == ":":
                    ok = actual is not None and bool(regex.match(str(actual)))
                elif op == "!=":
                    ok = actual is None or not regex.match(str(actual))
                else:
                    try:
                        a, b = float(actual), float(value)
                    except (TypeError, ValueError):
                        ok = False
                    else:
                        ok = {">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b}[op]
                if not ok:
                    break
            if ok:
                return True
        return False

    return matches


@router.get("/events")
def search_events(
    q: str = "",
    tenant_id: str | None = None,
    device_id: str | None = None,
    category: str | None = None,
    hours: int = Query(default=24, ge=1, le=24 * 365),
    limit: int = Query(default=200, ge=1, le=2000),
    principal: Principal = Depends(current_principal),
    db: Session = Depends(get_db),
):
    query = select(Event).where(Event.tenant_id.in_(scoped_tenant(principal, tenant_id)),
                                Event.occurred_at >= utcnow() - timedelta(hours=hours))
    if device_id:
        query = query.where(Event.device_id == device_id)
    if category:
        query = query.where(Event.category == category)
    matcher = _compile_query(q)
    results, scanned = [], 0
    for event in db.execute(query.order_by(Event.occurred_at.desc()).limit(50000)).scalars():
        scanned += 1
        if matcher(event):
            results.append(to_dict(event))
            if len(results) >= limit:
                break
    return {"scanned": scanned, "count": len(results), "events": results}


@router.post("/hunt")
def retro_hunt(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Run any Sigma rule over stored history (retro-hunt), without deploying it."""
    try:
        rule = parse_rule(str(body.get("rule") or ""))
    except SigmaError as exc:
        raise HTTPException(400, str(exc)) from exc
    if isinstance(rule, CorrelationRule):
        raise HTTPException(400, "Retro-hunts take detection rules, not correlation rules")
    days = min(int(body.get("days") or 7), 365)
    scope = scoped_tenant(principal, body.get("tenantId"))
    platforms = dict(db.execute(select(Device.id, Device.platform).where(Device.tenant_id.in_(scope))).all())
    hits, scanned = [], 0
    query = select(Event).where(Event.tenant_id.in_(scope), Event.occurred_at >= utcnow() - timedelta(days=days)) \
        .order_by(Event.occurred_at.desc()).limit(200000)
    for event in db.execute(query).scalars():
        scanned += 1
        if rule.matches(event.fields or {}, event.category, platforms.get(event.device_id)):
            hits.append(to_dict(event))
            if len(hits) >= 1000:
                break
    devices = Counter(h["deviceId"] for h in hits)
    return {"rule": rule.title, "scanned": scanned, "hits": len(hits), "devices": dict(devices), "events": hits[:200]}


# --------------------------------------------------------------------------- alerts


@router.get("/alerts")
def list_alerts(tenant_id: str | None = None, status: str | None = None, severity: str | None = None, device_id: str | None = None,
                principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    query = select(Alert).where(Alert.tenant_id.in_(scoped_tenant(principal, tenant_id)))
    if status:
        query = query.where(Alert.status == status)
    if severity:
        query = query.where(Alert.severity == severity)
    if device_id:
        query = query.where(Alert.device_id == device_id)
    rows = db.execute(query.order_by(Alert.created_at.desc()).limit(1000)).scalars().all()
    hosts = dict(db.execute(select(Device.id, Device.hostname).where(Device.id.in_({a.device_id for a in rows if a.device_id}))).all())
    return [{**to_dict(a), "hostname": hosts.get(a.device_id, "")} for a in rows]


@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(alert.tenant_id)
    events = db.execute(select(Event).where(Event.id.in_(alert.event_ids[:200]))).scalars().all()
    rule = db.get(DetectionRule, alert.rule_id)
    # Process tree context: events on the same device within +/- 5 minutes sharing a PID lineage.
    context = []
    if events:
        first = min(e.occurred_at for e in events)
        pids = {str(lookup(e.fields, "ProcessId")) for e in events} | {str(lookup(e.fields, "ParentProcessId")) for e in events}
        pids.discard("None")
        window = db.execute(select(Event).where(Event.device_id == alert.device_id,
                                                Event.occurred_at.between(first - timedelta(minutes=5), first + timedelta(minutes=5)))
                            .order_by(Event.occurred_at).limit(2000)).scalars().all()
        context = [to_dict(e) for e in window if str(lookup(e.fields, "ProcessId")) in pids or str(lookup(e.fields, "ParentProcessId")) in pids]
    view = to_dict(alert)
    view["details"] = _with_evidence(alert, events)
    return {"alert": view, "events": [to_dict(e) for e in events], "rule": to_dict(rule) if rule else None,
            "processContext": context[:300]}


def _with_evidence(alert: Alert, events: list[Event] | None = None, db: Session | None = None) -> dict:
    """The alert's details, with evidence rebuilt from its events for alerts raised before evidence was stored."""
    details = dict(alert.details or {})
    if details.get("evidence"):
        return details
    if events is None and db is not None:
        events = db.execute(select(Event).where(Event.id.in_((alert.event_ids or [])[:25]))).scalars().all()
    for event in sorted(events or [], key=lambda e: e.occurred_at)[:25]:
        details = evidence.add_occurrence(details, evidence.extract(
            event.fields or {}, event.event_type, event.summary or "", event.occurred_at.isoformat() + "Z", event.source, event.id))
    head = evidence.headline((details.get("evidence") or [{}])[-1])
    for key, value in head.items():
        details.setdefault(key, value)
    if not details.get("process") and head.get("process"):
        details["process"] = head["process"]
    return details


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(alert.tenant_id)
    if body.get("status") not in (None, "new", "triaged", "resolved", "false_positive"):
        raise HTTPException(400, "invalid status")
    apply_fields(alert, body, {"status"})
    alert.updated_at = utcnow()
    if body.get("status") == "false_positive" and body.get("suppress"):
        # Learn from the analyst: exclude this exact process image for this rule in this tenant.
        image = (alert.details or {}).get("process")
        if image:
            _add_rule_exclusion(db, alert.rule_id, alert.tenant_id, str(image), principal.actor)
    audit.record(db, principal.actor, "alert.updated", alert.id, alert.tenant_id, status=alert.status)
    db.commit()
    return to_dict(alert)


def _add_rule_exclusion(db: Session, rule_id: str, tenant_id: str, image: str, actor: str) -> None:
    base = db.get(DetectionRule, rule_id)
    if base is None or base.kind != "sigma":
        return
    import yaml

    doc = yaml.safe_load(base.source)
    detection = doc["detection"]
    condition = detection["condition"] if isinstance(detection["condition"], str) else detection["condition"][0]
    detection["fenrir_fp_exclusion"] = {"Image": image}
    detection["condition"] = f"({condition}) and not fenrir_fp_exclusion"
    doc["id"] = f"{rule_id}--{tenant_id}"[:64]
    doc["title"] = f"{base.title} (tuned)"
    tuned_id = doc["id"]
    existing = db.get(DetectionRule, tuned_id)
    if existing is not None:
        current = yaml.safe_load(existing.source)
        images = current["detection"]["fenrir_fp_exclusion"]["Image"]
        images = images if isinstance(images, list) else [images]
        if image not in images:
            images.append(image)
        current["detection"]["fenrir_fp_exclusion"]["Image"] = images
        existing.source = yaml.safe_dump(current, sort_keys=False)
    else:
        db.add(DetectionRule(id=tuned_id, tenant_id=tenant_id, title=doc["title"], kind="sigma", level=base.level,
                             source=yaml.safe_dump(doc, sort_keys=False), mitre=base.mitre, builtin=False))
    # The tuned copy replaces the global rule for this tenant only, via a tenant-scoped disable marker.
    marker_id = f"{rule_id}--off--{tenant_id}"[:64]
    if db.get(DetectionRule, marker_id) is None:
        db.add(DetectionRule(id=marker_id, tenant_id=tenant_id, title=f"Suppression marker for {rule_id}", kind="marker",
                             source=rule_id, level="informational", enabled=False, builtin=False))
    audit.record(db, actor, "rule.tuned", rule_id, tenant_id, excludedImage=image)
    RULES.invalidate()


# --------------------------------------------------------------------------- incidents


@router.get("/incidents")
def list_incidents(tenant_id: str | None = None, status: str | None = None, principal: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)):
    query = select(Incident).where(Incident.tenant_id.in_(scoped_tenant(principal, tenant_id)))
    if status:
        query = query.where(Incident.status == status)
    rows = db.execute(query.order_by(Incident.created_at.desc()).limit(500)).scalars().all()
    hosts = dict(db.execute(select(Device.id, Device.hostname).where(Device.id.in_({i.device_id for i in rows if i.device_id}))).all())
    return [{**to_dict(i), "hostname": hosts.get(i.device_id, "")} for i in rows]


@router.get("/incidents/{incident_id}")
def incident_detail(incident_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(incident.tenant_id)
    alerts = db.execute(select(Alert).where(Alert.incident_id == incident.id).order_by(Alert.created_at)).scalars().all()
    commands = db.execute(select(Command).where(Command.incident_id == incident.id).order_by(Command.created_at)).scalars().all()
    device = db.get(Device, incident.device_id) if incident.device_id else None
    ticket = db.get(Ticket, incident.ticket_id) if incident.ticket_id else None
    book = next((b for b in playbooks() if b.get("id") == incident.playbook), None)
    alert_views = []
    for a in alerts:
        view = to_dict(a)
        view["details"] = _with_evidence(a, db=db)
        alert_views.append(view)
    return {"incident": to_dict(incident), "alerts": alert_views, "commands": [to_dict(c) for c in commands],
            "indicators": evidence.indicators([a["details"] for a in alert_views]),
            "device": to_dict(device, exclude={"dns_token"}) if device else None, "ticket": to_dict(ticket) if ticket else None,
            "playbook": book}


@router.patch("/incidents/{incident_id}")
def update_incident(incident_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                    db: Session = Depends(get_db)):
    principal.require("respond")
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(incident.tenant_id)
    if body.get("status") not in (None, "open", "investigating", "contained", "resolved", "closed"):
        raise HTTPException(400, "invalid status")
    if body.get("status") == "closed":
        gates = [item for item in incident.checklist or [] if item.get("stage") == "closure_gate" and not item.get("done")]
        if gates and not body.get("force"):
            raise HTTPException(409, f"{len(gates)} closure gates are not complete: " + "; ".join(g["task"] for g in gates[:3]))
    changed = apply_fields(incident, body, {"status", "assignee", "severity", "checklist"})
    note = str(body.get("note") or "").strip()
    entries = []
    if changed:
        entries.append({"at": utcnow().isoformat(), "kind": "update", "text": f"{principal.actor} changed {', '.join(changed)}"})
    if note:
        entries.append({"at": utcnow().isoformat(), "kind": "note", "text": note, "by": principal.actor})
    incident.timeline = (incident.timeline or []) + entries
    incident.updated_at = utcnow()
    if incident.status in {"resolved", "closed"}:
        for alert in db.execute(select(Alert).where(Alert.incident_id == incident.id, Alert.status.in_(("new", "triaged")))).scalars():
            alert.status = "resolved"
    audit.record(db, principal.actor, "incident.updated", incident.id, incident.tenant_id, fields=changed)
    db.commit()
    return to_dict(incident)


@router.post("/incidents/{incident_id}/ticket")
def incident_ticket(incident_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(incident.tenant_id)
    if incident.ticket_id:
        return to_dict(db.get(Ticket, incident.ticket_id))
    ticket = services.open_ticket(db, incident.tenant_id, f"[Security] {incident.title}", f"Opened from incident {incident.id}",
                                  services.PRIORITY_BY_SEVERITY.get(incident.severity, "P3"), "incident", principal.actor,
                                  incident.id, incident.device_id, "Security Operations")
    db.flush()
    incident.ticket_id = ticket.id
    db.commit()
    return to_dict(ticket)


# --------------------------------------------------------------------------- rules


@router.get("/rules")
def list_rules(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(DetectionRule).where(DetectionRule.kind != "marker",
                                                  or_(DetectionRule.tenant_id.is_(None), DetectionRule.tenant_id.in_(principal.tenant_ids)))
                      .order_by(DetectionRule.title)).scalars().all()
    return [to_dict(r) for r in rows]


@router.post("/rules/test")
def test_rule(body: dict = Body(...), principal: Principal = Depends(current_principal)):
    """Validate a rule and evaluate it against sample events, without saving."""
    from ..normalize import normalize

    try:
        rule = parse_rule(str(body.get("rule") or ""))
    except SigmaError as exc:
        return {"valid": False, "error": str(exc)}
    if isinstance(rule, CorrelationRule):
        return {"valid": True, "kind": "correlation", "title": rule.title}
    results = []
    for sample in body.get("events") or []:
        norm = normalize(sample, str(sample.get("platform") or ""))
        results.append({"eventType": norm["event_type"], "category": norm["category"],
                        "matched": rule.matches(norm["fields"], norm["category"], sample.get("platform"))})
    return {"valid": True, "kind": "sigma", "title": rule.title, "level": rule.level, "mitre": rule.mitre, "results": results}


@router.post("/rules")
def create_rule(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.get("tenantId")
    principal.check_tenant(tenant_id)
    source = str(body.get("rule") or "")
    try:
        rule = parse_rule(source)
    except SigmaError as exc:
        raise HTTPException(400, str(exc)) from exc
    rule_id = rule.id if tenant_id is None else f"{rule.id}"[:64]
    if db.get(DetectionRule, rule_id):
        rule_id = f"{rule.id[:40]}-{uuid.uuid4().hex[:8]}"
    row = DetectionRule(id=rule_id, tenant_id=tenant_id, title=rule.title, kind="correlation" if isinstance(rule, CorrelationRule) else "sigma",
                        source=source, level=rule.level, mitre=rule.mitre, response=body.get("response") or [])
    db.add(row)
    audit.record(db, principal.actor, "rule.created", rule_id, tenant_id)
    db.commit()
    RULES.invalidate()
    return to_dict(row)


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = db.get(DetectionRule, rule_id)
    if row is None:
        raise HTTPException(404, "Not found")
    if row.tenant_id is None and not principal.can("platform") and set(body) - {"enabled"}:
        raise HTTPException(403, "Only platform admins edit global rules")
    if row.tenant_id is None and "enabled" in body and not principal.can("platform"):
        raise HTTPException(403, "Ask a platform admin to disable a global rule, or tune it from an alert")
    if row.tenant_id is not None:
        principal.check_tenant(row.tenant_id)
    if "rule" in body:
        try:
            parsed = parse_rule(str(body["rule"]))
        except SigmaError as exc:
            raise HTTPException(400, str(exc)) from exc
        row.source, row.title, row.level, row.mitre = str(body["rule"]), parsed.title, parsed.level, parsed.mitre
    apply_fields(row, body, {"enabled", "response"})
    row.updated_at = utcnow()
    audit.record(db, principal.actor, "rule.updated", rule_id, row.tenant_id, fields=sorted(body))
    db.commit()
    RULES.invalidate()
    return to_dict(row)


@router.get("/mitre")
def mitre_coverage(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Which ATT&CK techniques the enabled rule set covers, and how often each fired."""
    coverage: dict[str, dict] = {}
    for row in db.execute(select(DetectionRule).where(DetectionRule.enabled.is_(True), DetectionRule.kind != "marker")).scalars():
        for tag in row.mitre or []:
            if tag[:1] == "T":
                entry = coverage.setdefault(tag, {"technique": tag, "rules": [], "hits": 0})
                entry["rules"].append(row.title)
                entry["hits"] += row.hits or 0
            else:
                coverage.setdefault(f"tactic:{tag}", {"tactic": tag, "rules": [], "hits": 0})["rules"].append(row.title)
    techniques = sorted((v for k, v in coverage.items() if not k.startswith("tactic:")), key=lambda v: v["technique"])
    tactics = sorted((v for k, v in coverage.items() if k.startswith("tactic:")), key=lambda v: v["tactic"])
    return {"techniques": techniques, "tactics": tactics}


# --------------------------------------------------------------------------- automation


@router.get("/automations")
def list_automations(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(AutomationRule).where(or_(AutomationRule.tenant_id.is_(None),
                                                       AutomationRule.tenant_id.in_(principal.tenant_ids)))).scalars().all()
    return [to_dict(r) for r in rows]


@router.post("/automations")
def create_automation(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.get("tenantId")
    principal.check_tenant(tenant_id)
    for action in body.get("actions") or []:
        if action.get("type") not in {"command", "ticket", "webhook"}:
            raise HTTPException(400, "action type must be command, ticket or webhook")
    row = AutomationRule(tenant_id=tenant_id, name=str(body.get("name") or "Automation"), conditions=body.get("conditions") or {},
                         actions=body.get("actions") or [], enabled=bool(body.get("enabled", True)))
    db.add(row)
    audit.record(db, principal.actor, "automation.created", row.name, tenant_id)
    db.commit()
    return to_dict(row)


@router.patch("/automations/{automation_id}")
def update_automation(automation_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                      db: Session = Depends(get_db)):
    principal.require("configure")
    row = db.get(AutomationRule, automation_id)
    if row is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(row.tenant_id)
    apply_fields(row, body, {"name", "conditions", "actions", "enabled"})
    db.commit()
    return to_dict(row)


@router.get("/playbooks")
def list_playbooks(principal: Principal = Depends(current_principal)):
    return playbooks()
