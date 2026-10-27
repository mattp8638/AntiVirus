"""Telemetry pipeline: store -> detect -> correlate -> alert -> incident -> respond."""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import yaml
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import evidence, services
from .models import Alert, AutomationRule, DetectionRule, Device, Event, Incident, RuleMatch, Tenant, utcnow
from .normalize import normalize
from .sigma import CorrelationRule, SigmaError, SigmaRule, parse_rule

log = logging.getLogger("fenrir.detection")

ALERT_LEVELS = {"medium", "high", "critical"}
LEVEL_TO_SEVERITY = {"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
ALERT_DEDUP_WINDOW = timedelta(minutes=10)
REPEAT_FOLD_WINDOW = timedelta(days=30)
INCIDENT_GROUP_WINDOW = timedelta(hours=2)


# ---------------------------------------------------------------------------
# Rule loading and cache
# ---------------------------------------------------------------------------


def split_rule_file(text: str) -> list[str]:
    return [doc for doc in re.split(r"(?m)^---\s*$", text) if doc.strip()]


def sync_builtin_rules(db: Session, rules_dir: Path) -> int:
    """Upsert the shipped rule pack. Keeps an admin's enabled/disabled choice."""
    count = 0
    for path in sorted(rules_dir.glob("*.yml")):
        for text in split_rule_file(path.read_text(encoding="utf-8")):
            try:
                rule = parse_rule(text)
            except SigmaError as exc:
                log.error("built-in rule in %s failed to parse: %s", path.name, exc)
                continue
            row = db.get(DetectionRule, rule.id)
            kind = "correlation" if isinstance(rule, CorrelationRule) else "sigma"
            if row is None:
                row = DetectionRule(id=rule.id, builtin=True, enabled=True)
                db.add(row)
            row.title, row.kind, row.source, row.level, row.mitre = rule.title, kind, text.strip(), rule.level, rule.mitre
            row.updated_at = utcnow()
            count += 1
    _rebuild_tuned_copies(db)
    db.commit()
    RULES.invalidate()
    return count


def _rebuild_tuned_copies(db: Session) -> None:
    """A tenant's tuned copy (an analyst's false-positive exclusions) follows the shipped rule: rebuilt from the new
    version with the same exclusions, so fixing a built-in rule also fixes every customer's copy."""
    import yaml

    for row in db.execute(select(DetectionRule).where(DetectionRule.builtin.is_(False), DetectionRule.kind == "sigma",
                                                      DetectionRule.id.contains("--"))).scalars().all():
        base = db.get(DetectionRule, row.id.split("--")[0])
        if base is None or not base.builtin or base.kind != "sigma":
            continue
        try:
            current = yaml.safe_load(row.source)
            doc = yaml.safe_load(base.source)
        except yaml.YAMLError:
            continue
        exclusion = (current.get("detection") or {}).get("fenrir_fp_exclusion")
        if not exclusion:
            continue
        detection = doc["detection"]
        condition = detection["condition"] if isinstance(detection["condition"], str) else detection["condition"][0]
        detection["fenrir_fp_exclusion"] = exclusion
        detection["condition"] = f"({condition}) and not fenrir_fp_exclusion"
        doc["id"], doc["title"] = row.id, f"{base.title} (tuned)"
        source = yaml.safe_dump(doc, sort_keys=False)
        if source != row.source:
            row.source, row.level, row.mitre, row.title = source, base.level, base.mitre, doc["title"]
            row.updated_at = utcnow()


@dataclass
class CompiledRules:
    sigma: list[tuple[DetectionRule, SigmaRule]]
    correlations: list[tuple[DetectionRule, CorrelationRule]]
    by_base: dict[str, list[tuple[DetectionRule, CorrelationRule]]]
    # (global rule id, tenant id) pairs replaced by a tenant-tuned copy.
    suppressed: set[tuple[str, str]]


class RuleCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._compiled: CompiledRules | None = None

    def invalidate(self) -> None:
        with self._lock:
            self._compiled = None

    def get(self, db: Session) -> CompiledRules:
        with self._lock:
            if self._compiled is not None:
                return self._compiled
            sigma_rules: list = []
            correlations: list = []
            suppressed = {(row.source, row.tenant_id) for row in
                          db.execute(select(DetectionRule).where(DetectionRule.kind == "marker")).scalars()}
            for row in db.execute(select(DetectionRule).where(DetectionRule.enabled.is_(True),
                                                              DetectionRule.kind != "marker")).scalars():
                try:
                    parsed = parse_rule(row.source)
                except SigmaError as exc:
                    log.warning("rule %s disabled at runtime: %s", row.id, exc)
                    continue
                db.expunge(row)
                (correlations if isinstance(parsed, CorrelationRule) else sigma_rules).append((row, parsed))
            by_base: dict[str, list] = {}
            for row, corr in correlations:
                for base in corr.rules:
                    by_base.setdefault(base, []).append((row, corr))
            self._compiled = CompiledRules(sigma_rules, correlations, by_base, suppressed)
            return self._compiled


RULES = RuleCache()


def _rule_visible(row: DetectionRule, tenant_id: str, suppressed: set[tuple[str, str]] = frozenset()) -> bool:
    if row.tenant_id is None:
        return (row.id, tenant_id) not in suppressed
    return row.tenant_id == tenant_id


def _group_key(fields: dict, group_by: list[str]) -> str:
    from .sigma import lookup

    return "|".join(f"{name}={lookup(fields, name)}" for name in group_by)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


@dataclass
class IngestResult:
    accepted: int = 0
    duplicates: int = 0
    alerts: int = 0


def ingest(db: Session, device: Device, raw_events: list[dict], *, apply_device_effects: bool = True) -> IngestResult:
    result = IngestResult()
    compiled = RULES.get(db)
    tenant = db.get(Tenant, device.tenant_id)
    new_alerts: list[Alert] = []

    for raw in raw_events:
        if not isinstance(raw, dict):
            continue
        norm = normalize(raw, device.platform)
        if not norm["event_id"]:
            norm["event_id"] = f"auto-{device.id}-{utcnow().timestamp()}-{result.accepted}"
        fields = norm["fields"]
        fields.setdefault("Hostname", device.hostname)
        fields.setdefault("DeviceId", device.id)

        event = Event(
            tenant_id=device.tenant_id, device_id=device.id, event_id=norm["event_id"], event_type=norm["event_type"],
            category=norm["category"], source=norm["source"], summary=norm["summary"], severity=norm["severity"],
            occurred_at=norm["occurred_at"], fields=fields,
        )
        try:
            with db.begin_nested():
                db.add(event)
                db.flush()
        except IntegrityError:
            result.duplicates += 1
            continue
        result.accepted += 1
        if apply_device_effects:
            _apply_side_effects(db, device, norm)

        for row, rule in compiled.sigma:
            if not _rule_visible(row, device.tenant_id, compiled.suppressed) or not rule.matches(fields, norm["category"], device.platform):
                continue
            db.add(RuleMatch(tenant_id=device.tenant_id, rule_id=row.id, device_id=device.id, event_pk=event.id,
                             group_key="", at=event.occurred_at))
            _bump_hits(db, row.id)
            if rule.level in ALERT_LEVELS:
                alert = _raise_alert(db, device, row.id, rule.title, rule.level, rule.mitre, event,
                                     {"description": rule.description, "falsePositives": rule.falsepositives,
                                      "process": fields.get("Image"), "commandLine": fields.get("CommandLine"),
                                      "pid": fields.get("ProcessId"), "file": fields.get("TargetFilename")})
                if alert is not None:
                    new_alerts.append(alert)
            for corr_row, corr in compiled.by_base.get(row.id.split("--")[0], []):
                if not _rule_visible(corr_row, device.tenant_id, compiled.suppressed):
                    continue
                alert = _evaluate_correlation(db, device, corr_row, corr, row.id, fields, event)
                if alert is not None:
                    new_alerts.append(alert)

    db.flush()
    for alert in new_alerts:
        _route_alert(db, device, tenant, alert)
    result.alerts = len(new_alerts)
    device.risk_score = _risk_score(db, device)
    return result


def _bump_hits(db: Session, rule_id: str) -> None:
    row = db.get(DetectionRule, rule_id)
    if row is not None:
        row.hits = (row.hits or 0) + 1


def _apply_side_effects(db: Session, device: Device, norm: dict) -> None:
    """Keep device state in sync with what the agent reports."""
    event_type = norm["event_type"]
    if event_type == "device.isolated":
        device.isolated = True
    elif event_type == "device.released":
        device.isolated = False
    elif event_type in {"device.inventory.snapshot", "inventory.snapshot"}:
        from .exposure import record_inventory

        record_inventory(db, device, norm["fields"])


def _evaluate_correlation(db: Session, device: Device, corr_row: DetectionRule, corr: CorrelationRule, base_id: str,
                          fields: dict, event: Event) -> Alert | None:
    key = _group_key(fields, corr.group_by)
    # One tagged match row per (correlation, group) so a base rule can feed several correlations.
    # Tenant-tuned copies ("<id>--<tenant>") count as the rule they were tuned from.
    db.add(RuleMatch(tenant_id=device.tenant_id, rule_id=base_id.split("--")[0], device_id=device.id, event_pk=event.id,
                     group_key=f"{corr_row.id}:{key}", at=event.occurred_at))
    db.flush()
    window_start = event.occurred_at - timedelta(seconds=corr.timespan_seconds)
    scoped = select(RuleMatch).where(
        RuleMatch.tenant_id == device.tenant_id, RuleMatch.rule_id.in_(corr.rules),
        RuleMatch.group_key == f"{corr_row.id}:{key}", RuleMatch.at >= window_start, RuleMatch.at <= event.occurred_at,
    )
    matches = db.execute(scoped).scalars().all()
    if corr.type == "event_count":
        observed = len(matches)
    elif corr.type == "value_count":
        values = set()
        for m in matches:
            ev = db.get(Event, m.event_pk) if m.event_pk else None
            if ev is not None:
                from .sigma import lookup

                values.add(str(lookup(ev.fields, corr.value_field or "")))
        observed = len(values)
    else:  # temporal: every listed rule fired in the window
        observed = len({m.rule_id for m in matches})
    if not corr.threshold_met(observed):
        return None
    return _raise_alert(db, device, corr_row.id, corr.title, corr.level, corr.mitre, event,
                        {"correlation": corr.type, "observed": observed, "groupBy": key, "windowSeconds": corr.timespan_seconds,
                         "process": fields.get("Image"), "pid": fields.get("ProcessId")})


def _raise_alert(db: Session, device: Device, rule_id: str, title: str, level: str, mitre: list[str], event: Event,
                 details: dict) -> Alert | None:
    """Create an alert, or fold the event into a recent alert for the same rule and device."""
    from .models import AlertSuppression
    if db.scalar(select(AlertSuppression.id).where(AlertSuppression.tenant_id == device.tenant_id,
            AlertSuppression.rule_id == rule_id, AlertSuppression.expires_at > utcnow()).limit(1)):
        return None
    since = event.occurred_at - ALERT_DEDUP_WINDOW
    # What the alert is about (file, hash, threat, process, origin, service, registry, network...), for the console.
    found = evidence.extract(event.fields or {}, event.event_type, event.summary or "",
                             event.occurred_at.isoformat() + "Z" if event.occurred_at else None, event.source, event.id)
    # A file an analyst marked as a false positive (a tenant or global "allow" indicator) never alerts again.
    sha256 = str((found.get("file") or {}).get("sha256") or "").lower()
    if sha256 and is_trusted_hash(db, device.tenant_id, sha256):
        return None
    mitre = attack_for(rule_id, mitre, found, event.fields or {}, event.event_type)
    # The same file/process on the same device folds into its open alert for 30 days (daily scans repeat it).
    if evidence.headline(found):
        for open_alert in db.execute(select(Alert).where(
                Alert.device_id == device.id, Alert.rule_id == rule_id, Alert.status.in_(("new", "triaged")),
                Alert.created_at >= event.occurred_at - REPEAT_FOLD_WINDOW).order_by(Alert.created_at.desc()).limit(50)).scalars():
            if any(evidence.same_occurrence(e, found) for e in (open_alert.details or {}).get("evidence") or []):
                ids = list(open_alert.event_ids or [])
                if event.id not in ids and len(ids) < 500:
                    open_alert.event_ids = ids + [event.id]
                open_alert.updated_at = utcnow()
                open_alert.details = evidence.add_occurrence(open_alert.details or {}, found)
                open_alert.mitre = list(dict.fromkeys([*(open_alert.mitre or []), *mitre]))
                return None
    recent = db.execute(
        select(Alert).where(Alert.device_id == device.id, Alert.rule_id == rule_id, Alert.created_at >= since,
                            Alert.status.in_(("new", "triaged")))
    ).scalars().first()
    if recent is not None:
        ids = list(recent.event_ids or [])
        if event.id not in ids and len(ids) < 500:
            ids.append(event.id)
            recent.event_ids = ids
            recent.updated_at = utcnow()
            recent.details = evidence.add_occurrence(recent.details or {}, found)
            recent.mitre = list(dict.fromkeys([*(recent.mitre or []), *mitre]))
        return None
    head = evidence.headline(found)
    details = {**{k: v for k, v in head.items() if k in {"file", "sha256", "threat", "user"}}, **details}
    for key in ("process", "file"):
        if not details.get(key) and head.get(key):
            details[key] = head[key]
    details = evidence.add_occurrence({k: v for k, v in details.items() if v not in (None, "", [])}, found)
    alert = Alert(tenant_id=device.tenant_id, device_id=device.id, rule_id=rule_id, title=title,
                  severity=LEVEL_TO_SEVERITY.get(level, "medium"), mitre=mitre, event_ids=[event.id],
                  details=details, created_at=event.occurred_at)
    db.add(alert)
    db.flush()
    return alert


# ---------------------------------------------------------------------------
# Incidents, playbooks, and automated response
# ---------------------------------------------------------------------------


_PLAYBOOKS: list[dict] | None = None


def playbooks() -> list[dict]:
    global _PLAYBOOKS
    if _PLAYBOOKS is None:
        loaded = []
        for path in sorted((Path(__file__).parent / "playbooks").glob("*.yml")):
            try:
                loaded.append(yaml.safe_load(path.read_text(encoding="utf-8")))
            except yaml.YAMLError as exc:  # pragma: no cover - shipped files are valid
                log.error("playbook %s invalid: %s", path.name, exc)
        _PLAYBOOKS = loaded
    return _PLAYBOOKS


def choose_playbook(mitre: list[str], title: str) -> dict | None:
    tags = {tag.upper() for tag in mitre}
    for book in playbooks():
        wanted = {str(t).upper() for t in book.get("match_mitre", [])}
        if wanted & tags or any(t.split(".")[0] in wanted for t in tags):
            return book
    lowered = title.lower()
    for book in playbooks():
        if book.get("incident_type") and book["incident_type"].replace("_", " ") in lowered:
            return book
    return next((b for b in playbooks() if b.get("incident_type") == "malware"), None)


def _checklist(book: dict | None) -> list[dict]:
    if not book:
        return []
    items = [{"stage": stage, "task": info.get("objective", ""), "done": False}
             for stage, info in (book.get("stages") or {}).items()]
    items += [{"stage": "closure_gate", "task": gate, "done": False} for gate in book.get("critical_closure_gates", [])]
    return items


def _route_alert(db: Session, device: Device, tenant: Tenant | None, alert: Alert) -> None:
    since = alert.created_at - INCIDENT_GROUP_WINDOW
    incident = db.execute(
        select(Incident).where(Incident.device_id == device.id, Incident.created_at >= since,
                               Incident.status.in_(("open", "investigating", "contained")))
        .order_by(Incident.created_at.desc())
    ).scalars().first()
    created = False
    if incident is None:
        book = choose_playbook(alert.mitre, alert.title)
        incident = Incident(tenant_id=device.tenant_id, device_id=device.id, title=f"{alert.title} on {device.hostname}",
                            severity=alert.severity, mitre=list(alert.mitre), playbook=(book or {}).get("id", ""),
                            checklist=_checklist(book), timeline=[], created_at=alert.created_at)
        db.add(incident)
        db.flush()
        created = True
    else:
        if services.SEVERITY_ORDER[alert.severity] > services.SEVERITY_ORDER.get(incident.severity, 0):
            incident.severity = alert.severity
            incident.title = f"{alert.title} on {device.hostname}"
        # Upgrade to a more specific playbook (e.g. ransomware) while nobody has started the checklist.
        book = choose_playbook(sorted(set(incident.mitre or []) | set(alert.mitre)), alert.title)
        if book and book.get("id") != incident.playbook and book.get("match_mitre") \
                and not any(item.get("done") for item in incident.checklist or []):
            incident.playbook, incident.checklist = book["id"], _checklist(book)
    alert.incident_id = incident.id
    incident.alert_count = (incident.alert_count or 0) + 1
    incident.mitre = sorted(set(incident.mitre or []) | set(alert.mitre))
    incident.timeline = (incident.timeline or []) + [
        {"at": alert.created_at.isoformat(), "kind": "alert", "text": alert.title, "severity": alert.severity, "alertId": alert.id}
    ]
    incident.updated_at = utcnow()

    actions = _automated_response(db, device, alert, incident)
    if actions:
        incident.timeline = incident.timeline + [
            {"at": utcnow().isoformat(), "kind": "response", "text": f"Automated: {', '.join(actions)}"}
        ]
    if created:
        services.fire_webhooks(db, device.tenant_id, "incident.created", {
            "title": incident.title, "severity": incident.severity, "tenant": tenant.name if tenant else "",
            "incidentId": incident.id, "device": device.hostname,
        })


def _automated_response(db: Session, device: Device, alert: Alert, incident: Incident) -> list[str]:
    resolution, _ = services.effective_policy(db, device)
    response = resolution["settings"]["response"]
    taken: list[str] = []
    image = (alert.details or {}).get("process")
    pid = (alert.details or {}).get("pid")
    actor = "automation"
    skipped: list[str] = []

    def queue(command_type: str, target_path: str = "", why: str = "") -> None:
        if command_type in KILL_COMMANDS:
            # Only PID-targeted kills are automatic; a path-wide kill of e.g. powershell.exe would hit unrelated work.
            stopped = _already_stopped_by_agent(db, alert)
            if not target_path or not pid or stopped:
                skipped.append(f"{command_type} ({'the agent already stopped it' if stopped else 'no process ID to target'})")
                return
        try:
            payload = {"pid": int(pid)} if command_type in KILL_COMMANDS and pid else {}
            services.enqueue_command(db, device, command_type, actor, target_path=target_path, reason=why or alert.title,
                                     incident_id=incident.id, payload=payload)
            taken.append(command_type)
        except services.CommandError as exc:
            log.info("auto-response %s skipped: %s", command_type, exc)

    if response["autoKillOnHigh"] and image and services.severity_at_least(alert.severity, "high"):
        queue("process.tree.terminate", str(image))
    if response["autoIsolateOnCritical"] and alert.severity == "critical" and not device.isolated:
        queue("device.isolate")
    target_file = str((alert.details or {}).get("file") or "")
    if response["autoQuarantine"] and alert.rule_id == "fenrir-av-threat-unremediated" and target_file \
            and not is_shared_binary(target_file) and not _protected_location(target_file):
        # The agent found malware it did not (or could not) remove: ask it to quarantine the file.
        queue("remediate.path", target_file, "auto-quarantine: malware was left in place")
    if response["autoRollbackRansomware"] and "T1486" in alert.mitre and alert.severity == "critical":
        queue("ransomware.rollback")

    rule = db.get(DetectionRule, alert.rule_id)
    for command_type in (rule.response if rule else []) or []:
        queue(command_type, str(image or ""), f"rule {alert.rule_id}")

    for automation in db.execute(select(AutomationRule).where(AutomationRule.enabled.is_(True))).scalars():
        if automation.tenant_id not in (None, device.tenant_id) or not _automation_matches(automation.conditions or {}, alert):
            continue
        automation.runs = (automation.runs or 0) + 1
        for action in automation.actions or []:
            kind = action.get("type")
            if kind == "command" and action.get("command"):
                queue(action["command"], str(image or "") if action.get("useProcessPath") else action.get("targetPath", ""),
                      f"automation '{automation.name}'")
            elif kind == "ticket" and not incident.ticket_id:
                _ticket_for(db, device, incident, alert)
                taken.append("ticket")
            elif kind == "webhook":
                services.fire_webhooks(db, device.tenant_id, "alert.automation", {"title": alert.title, "severity": alert.severity})
                taken.append("webhook")

    if skipped:
        incident.timeline = (incident.timeline or []) + [
            {"at": utcnow().isoformat(), "kind": "note", "text": "Automation skipped " + "; ".join(skipped)}
        ]
    threshold = response["autoOpenTicket"]
    if threshold != "off" and not incident.ticket_id and services.severity_at_least(alert.severity, threshold):
        _ticket_for(db, device, incident, alert)
        taken.append("ticket")
    return taken


KILL_COMMANDS = {"process.terminate", "process.tree.terminate"}

# Interpreters and OS binaries are shared by many processes. The console warns before a path-wide kill of these.
_SHARED_BINARIES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "svchost.exe", "explorer.exe", "conhost.exe", "msiexec.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe",
    "sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby", "node", "java", "sudo", "systemd", "sshd",
}


_PROTECTED_PREFIXES = ("c:\\windows\\", "c:\\program files", "/system/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
                       "/usr/lib/", "/lib/")


def _protected_location(path: str) -> bool:
    """Operating-system locations are never auto-quarantined; a person reviews those findings."""
    return path.lower().replace("/", "\\" if "\\" in path else "/").startswith(_PROTECTED_PREFIXES)


def is_shared_binary(path: str) -> bool:
    lowered = path.replace("\\", "/").lower()
    name = lowered.rsplit("/", 1)[-1]
    if name in _SHARED_BINARIES:
        return True
    return lowered.startswith(("c:/windows/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/lib/"))


def _already_stopped_by_agent(db: Session, alert: Alert) -> bool:
    events = db.execute(select(Event.event_type).where(Event.id.in_((alert.event_ids or [])[:20]))).scalars().all()
    return any(t.endswith((".blocked", ".terminated", ".quarantined")) for t in events)


def _automation_matches(conditions: dict, alert: Alert) -> bool:
    if conditions.get("minSeverity") and not services.severity_at_least(alert.severity, conditions["minSeverity"]):
        return False
    if conditions.get("ruleIds") and alert.rule_id not in conditions["ruleIds"]:
        return False
    if conditions.get("mitre") and not set(conditions["mitre"]) & set(alert.mitre):
        return False
    if conditions.get("titleContains") and conditions["titleContains"].lower() not in alert.title.lower():
        return False
    return True


def _ticket_for(db: Session, device: Device, incident: Incident, alert: Alert) -> None:
    ticket = services.open_ticket(
        db, device.tenant_id, subject=f"[Security] {incident.title}",
        description=f"Automatically opened from incident {incident.id}.\nFirst alert: {alert.title} ({alert.severity}).\n"
                    f"MITRE: {', '.join(alert.mitre) or 'n/a'}",
        priority=services.PRIORITY_BY_SEVERITY.get(alert.severity, "P3"), source="incident", incident_id=incident.id,
        device_id=device.id, queue="Security Operations",
    )
    db.flush()
    incident.ticket_id = ticket.id


ALERT_WEIGHTS = {"critical": 40, "high": 20, "medium": 8, "low": 2}
VULN_WEIGHTS = (3.0, 1.5, 1.0, 0.75, 0.5)  # the worst vulnerability counts most; the long tail a little each


def risk_breakdown(db: Session, device: Device) -> dict:
    """The device's 0-100 risk score and what makes it up: open alerts in the last 7 days (up to 60 points),
    open vulnerabilities weighted by their own risk, worst first (up to 45), and isolation (5)."""
    from . import vulnmgmt
    from .models import Vulnerability

    since = utcnow() - timedelta(days=7)
    rows = db.execute(
        select(Alert.severity, func.count()).where(Alert.device_id == device.id, Alert.created_at >= since,
                                                   Alert.status.in_(("new", "triaged"))).group_by(Alert.severity)
    ).all()
    alert_points = min(sum(ALERT_WEIGHTS.get(sev, 0) * count for sev, count in rows), 60)
    vulns = db.execute(select(Vulnerability).where(Vulnerability.device_id == device.id,
                                                   Vulnerability.status.in_(vulnmgmt.UNRESOLVED))).scalars().all()
    # A compensating control halves a vulnerability's weight; an accepted risk is still the full exposure.
    scored = sorted(((vulnmgmt.risk_score(v, device.criticality) * (0.5 if v.status == "mitigated" else 1), v) for v in vulns),
                    key=lambda x: -x[0])
    vuln_points = 0.0
    for index, (risk, _) in enumerate(scored):
        vuln_points += risk * (VULN_WEIGHTS[index] if index < len(VULN_WEIGHTS) else 0.2)
    vuln_points = min(round(vuln_points), 45)
    parts = []
    if alert_points:
        parts.append({"kind": "alerts", "points": alert_points,
                      "detail": ", ".join(f"{count} {sev}" for sev, count in sorted(rows, key=lambda r: -ALERT_WEIGHTS.get(r[0], 0)))
                      + " open alert(s) in the last 7 days"})
    if vuln_points:
        kev = sum(1 for _, v in scored if v.known_exploited)
        parts.append({"kind": "vulnerabilities", "points": vuln_points,
                      "detail": f"{len(scored)} open vulnerabilit{'y' if len(scored) == 1 else 'ies'}" + (f", {kev} known exploited" if kev else ""),
                      "top": [{"vulnId": v.vuln_id, "package": v.package, "risk": risk, "fix": (v.fix or {}).get("ref") or v.fixed_version,
                               "reasons": vulnmgmt.risk_reasons(v)} for risk, v in scored[:5]]})
    if device.isolated:
        parts.append({"kind": "isolated", "points": 5, "detail": "isolated from the network"})
    return {"score": min(sum(p["points"] for p in parts), 100), "parts": parts}


def _risk_score(db: Session, device: Device) -> int:
    return risk_breakdown(db, device)["score"]


def refresh_risk_scores(db: Session, device_ids: list[str] | None = None) -> int:
    """Recompute stored risk scores (after vulnerability scans and intelligence updates). Returns how many changed."""
    query = select(Device)
    if device_ids is not None:
        query = query.where(Device.id.in_(device_ids))
    changed = 0
    for device in db.execute(query).scalars():
        score = _risk_score(db, device)
        if score != device.risk_score:
            device.risk_score = score
            changed += 1
    return changed



# ---------------------------------------------------------------------------
# Precision: ATT&CK from evidence, trusted files, re-checking open alerts
# ---------------------------------------------------------------------------

ANTIMALWARE_RULES = ("fenrir-av-threat-remediated", "fenrir-av-threat-unremediated", "fenrir-malware-verdict")
# Parents that mean a person launched the file (User Execution, T1204.002), not a service or scheduled task.
USER_LAUNCHERS = ("\\explorer.exe", "\\chrome.exe", "\\msedge.exe", "\\firefox.exe", "\\brave.exe", "\\opera.exe",
                  "\\iexplore.exe", "\\outlook.exe", "\\olk.exe", "\\winword.exe", "\\excel.exe", "\\powerpnt.exe",
                  "\\7zfm.exe", "\\winrar.exe", "\\thunderbird.exe", "\\ms-teams.exe", "\\teams.exe")


def attack_for(rule_id: str, static: list[str], found: dict, fields: dict, event_type: str = "") -> list[str]:
    """ATT&CK for a malware alert from what actually happened, not a blanket tag.

    A file found at rest by a scan is not "User Execution": it gets no technique unless it arrived as an email
    attachment (T1566.001). Execution techniques are only claimed when the agent saw it run: a person launching it
    from Explorer, a browser or Office is T1204.002; scripts keep the agent's interpreter technique (T1059.x).
    """
    if rule_id.split("--")[0] not in ANTIMALWARE_RULES:
        return static
    tags: list[str] = []
    origin, process = found.get("origin") or {}, found.get("process") or {}
    if origin.get("emailAttachment"):
        tags += ["initial_access", "T1566.001"]
    operation = str(fields.get("operation") or "").lower()
    technique = str(fields.get("techniqueId") or "")
    executed = (event_type.startswith(("threat.ml", "threat.process.")) or operation in {"execute", "section-map"}
                or (event_type == "realtime.protection.action" and bool(process.get("pid"))))
    script = bool(fields.get("appName"))  # AMSI: script content in memory
    if (executed or script) and technique.startswith(("T1059", "T1218")):
        tags += ["execution", technique]
    elif executed:
        parent = str(process.get("parentImage") or "").lower()
        tags += ["execution", "T1204.002"] if parent.endswith(USER_LAUNCHERS) else ["execution"]
    return list(dict.fromkeys(tags))


def is_trusted_hash(db: Session, tenant_id: str, sha256: str) -> bool:
    from sqlalchemy import or_

    from .intel import _not_expired
    from .models import Indicator

    return db.execute(select(Indicator.id).where(
        Indicator.type == "sha256", Indicator.verdict == "allow", func.lower(Indicator.value) == sha256.lower(),
        or_(Indicator.tenant_id.is_(None), Indicator.tenant_id == tenant_id), _not_expired()).limit(1)).first() is not None


def _why_not_alerting(fields: dict, event_type: str) -> str:
    """Plain-language reason an old alert no longer meets the tuned rules."""
    disposition = str(fields.get("disposition") or "").lower()
    reputation = str(fields.get("reputation") or "").lower()
    if disposition == "allow" or str(fields.get("action") or "").lower() == "allow":
        return "the agent checked the file and allowed it (trusted signer, known-good hash or an exclusion)"
    if "trusted-signed" in reputation or "intel-known-good" in reputation:
        return "the file is signed by a trusted publisher or has a known-good hash"
    if event_type.endswith(".audited"):
        return "an audit-only machine-learning score; nothing was blocked and a score alone is not proof"
    score = fields.get("heuristicScore")
    if isinstance(score, (int, float)) and score < 70:
        return f"a moderate heuristic score ({score}) with no malicious hash, signature or cloud verdict; now recorded for review"
    return "a routine event, not a malware verdict"


def retune_open_alerts(db: Session) -> dict:
    """Re-check open antimalware alerts against the current rules (after tuning). Alerts none of whose events still
    qualify are closed as false positives with the reason; kept ones get evidence-based ATT&CK. Incidents left
    with no open alert are resolved. Returns counts."""
    from .normalize import _repair, normalize

    compiled = RULES.get(db)
    alerting = [(row, rule) for row, rule in compiled.sigma
                if row.id.split("--")[0] in ANTIMALWARE_RULES and rule.level in ALERT_LEVELS]
    rows = db.execute(select(Alert).where(Alert.status.in_(("new", "triaged")))).scalars().all()
    rows = [a for a in rows if a.rule_id.split("--")[0] in ANTIMALWARE_RULES]
    closed, kept, incidents = 0, 0, set()
    reasons: dict[str, int] = {}
    for alert in rows:
        device = db.get(Device, alert.device_id) if alert.device_id else None
        events = db.execute(select(Event).where(Event.id.in_((alert.event_ids or [])[:500]))).scalars().all()
        still: list[tuple[Event, str]] = []
        last_reason = "no stored events still qualify"
        for event in events:
            fields = event.fields or {}
            if set(fields) <= {"raw"} and isinstance(fields.get("raw"), str):
                repaired = _repair(fields["raw"])
                if set(repaired) != {"raw"}:  # fix the stored event too
                    fields = normalize({"eventType": event.event_type, "payload": repaired}, device.platform if device else "")["fields"]
                    event.fields = fields
            sha = str(fields.get("sha256") or "").lower()
            if sha and device is not None and is_trusted_hash(db, device.tenant_id, sha):
                last_reason = "the file was marked trusted"
                continue
            match = next((row.id for row, rule in alerting
                          if device is not None and _rule_visible(row, device.tenant_id, compiled.suppressed)
                          and rule.matches(fields, event.category, device.platform)), None)
            if match:
                still.append((event, match))
            else:
                last_reason = _why_not_alerting(fields, event.event_type)
        if still:
            event, _ = still[0]
            found = evidence.extract(event.fields or {}, event.event_type, event.summary or "")
            alert.mitre = attack_for(alert.rule_id, alert.mitre, found, event.fields or {}, event.event_type)
            kept += 1
            continue
        alert.status = "false_positive"
        alert.updated_at = utcnow()
        alert.details = {**(alert.details or {}), "autoResolved": f"Closed by detection tuning: {last_reason}."}
        reasons[last_reason] = reasons.get(last_reason, 0) + 1
        closed += 1
        if alert.incident_id:
            incidents.add(alert.incident_id)
    db.flush()
    resolved = 0
    for incident_id in incidents:
        incident = db.get(Incident, incident_id)
        if incident is None or incident.status not in {"open", "investigating"}:
            continue
        open_left = db.execute(select(func.count()).where(Alert.incident_id == incident_id,
                                                          Alert.status.in_(("new", "triaged")))).scalar() or 0
        if open_left == 0:
            incident.status = "resolved"
            incident.timeline = (incident.timeline or []) + [{"at": utcnow().isoformat(), "kind": "update",
                                                              "text": "Resolved by detection tuning: every alert in it was a false positive."}]
            incident.updated_at = utcnow()
            resolved += 1
    for device_id in {a.device_id for a in rows if a.device_id}:
        device = db.get(Device, device_id)
        if device is not None:
            device.risk_score = _risk_score(db, device)
    return {"checked": len(rows), "closed": closed, "kept": kept, "incidentsResolved": resolved, "reasons": reasons}
