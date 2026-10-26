"""Remote monitoring and management: jobs, scripts, schedules, monitors, patching.

The agent side of everything here is an ordinary command (``script.run``,
``patch.scan``, ``patch.install``...). This module decides *what* to send
and *when*, and folds the results back into jobs, patch state and alerts.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit, services
from .models import (Alert, Command, ConditionState, Device, DeviceGroup, DeviceMetric, DevicePatch, Job, MonitorCondition,
                     PatchApproval, PatchPolicy, ScheduledTask, Script, SoftwarePackage, Ticket, Vulnerability, utcnow)

log = logging.getLogger("fenrir.rmm")

PARAM_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
LANGUAGES = {"powershell": ("windows",), "cmd": ("windows",), "bash": ("linux", "macos"), "sh": ("linux", "macos"),
             "python": ("windows", "linux", "macos"), "zsh": ("macos",)}
MAX_OUTPUT = 64 * 1024


# --------------------------------------------------------------------------- targets


def resolve_targets(db: Session, allowed_tenants: set[str] | frozenset[str], targets: dict) -> list[Device]:
    """Devices selected by ids, groups (including sub-groups), tenants and platform/tag filters."""
    device_ids = set(targets.get("deviceIds") or [])
    group_ids = set(targets.get("groupIds") or [])
    tenant_ids = set(targets.get("tenantIds") or [])
    platforms = set(targets.get("platforms") or [])
    tags = set(targets.get("tags") or [])
    if group_ids:
        # Expand to child groups.
        groups = db.execute(select(DeviceGroup.id, DeviceGroup.parent_id)).all()
        changed = True
        while changed:
            changed = False
            for gid, parent in groups:
                if parent in group_ids and gid not in group_ids:
                    group_ids.add(gid)
                    changed = True
    query = select(Device).where(Device.tenant_id.in_(list(allowed_tenants)), Device.approved.is_(True))
    selected: dict[str, Device] = {}
    if device_ids:
        for device in db.execute(query.where(Device.id.in_(device_ids))).scalars():
            selected[device.id] = device
    if group_ids:
        for device in db.execute(query.where(Device.group_id.in_(group_ids))).scalars():
            selected[device.id] = device
    if tenant_ids:
        for device in db.execute(query.where(Device.tenant_id.in_(tenant_ids & set(allowed_tenants)))).scalars():
            selected[device.id] = device
    devices = list(selected.values())
    if platforms:
        devices = [d for d in devices if d.platform in platforms]
    if tags:
        devices = [d for d in devices if tags & set(d.tags or [])]
    return sorted(devices, key=lambda d: d.hostname.lower())


# --------------------------------------------------------------------------- scripts


def _quote(language: str, value) -> str:
    text = "" if value is None else str(value)
    if language == "powershell":
        return "'" + text.replace("'", "''") + "'"
    if language in {"bash", "sh", "zsh"}:
        return "'" + text.replace("'", "'\"'\"'") + "'"
    if language == "python":
        return json.dumps(text)
    return text


def validate_parameters(script: Script, supplied: dict) -> dict:
    values: dict[str, str] = {}
    for spec in script.parameters or []:
        name = str(spec.get("name") or "")
        if not PARAM_NAME.match(name):
            raise ValueError(f"invalid parameter name '{name}'")
        value = supplied.get(name, spec.get("default", ""))
        if spec.get("required") and (value is None or str(value) == ""):
            raise ValueError(f"parameter '{spec.get('label') or name}' is required")
        kind = spec.get("type", "string")
        if kind == "number" and str(value) != "":
            try:
                float(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"parameter '{name}' must be a number") from exc
        if kind == "boolean":
            value = "true" if str(value).lower() in {"1", "true", "yes", "on"} else "false"
        if kind == "choice" and spec.get("choices") and str(value) not in [str(c) for c in spec["choices"]]:
            raise ValueError(f"parameter '{name}' must be one of {spec['choices']}")
        values[name] = "" if value is None else str(value)
    return values


def render_script(script: Script, values: dict) -> str:
    """Prefix the body with parameter assignments. cmd scripts read %NAME% environment variables instead."""
    lang = script.language
    lines: list[str] = []
    for name, value in values.items():
        if lang == "powershell":
            lines.append(f"${name} = {_quote(lang, value)}")
        elif lang in {"bash", "sh", "zsh"}:
            lines.append(f"{name}={_quote(lang, value)}")
        elif lang == "python":
            lines.append(f"{name} = {_quote(lang, value)}")
    if not lines:
        return script.body
    if lang in {"bash", "sh", "zsh"} and script.body.startswith("#!"):
        shebang, _, rest = script.body.partition("\n")
        return shebang + "\n" + "\n".join(lines) + "\n" + rest
    return "\n".join(lines) + "\n" + script.body


def script_payload(script: Script, values: dict) -> dict:
    return {
        "scriptId": script.id,
        "scriptName": script.name,
        "language": script.language,
        "body": render_script(script, values),
        "environment": {f"FENRIR_{k.upper()}": v for k, v in values.items()} | dict(values),
        "timeoutSeconds": int(script.timeout_seconds or 600),
        "runAs": script.run_as,
    }


# --------------------------------------------------------------------------- jobs


def create_job(db: Session, *, tenant_id: str, actor: str, name: str, devices: list[Device], command_type: str,
               kind: str = "command", payload: dict | None = None, script: Script | None = None, parameters: dict | None = None,
               targets: dict | None = None, target_path: str = "", record_id: str = "", scheduled_task_id: str | None = None,
               ticket_id: str | None = None) -> Job:
    job = Job(tenant_id=tenant_id, name=name[:200], kind=kind, command_type=command_type, script_id=script.id if script else None,
              parameters=parameters or {}, payload=payload or {}, targets=targets or {}, created_by=actor,
              scheduled_task_id=scheduled_task_id, ticket_id=ticket_id)
    db.add(job)
    db.flush()
    skipped: dict[str, str] = {}
    command_ids: dict[str, str] = {}
    for device in devices:
        if script and device.platform not in (script.platforms or []):
            skipped[device.id] = f"script does not support {device.platform}"
            continue
        try:
            command = services.enqueue_command(db, device, command_type, actor, target_path=target_path, record_id=record_id,
                                               payload={**(payload or {}), "jobId": job.id}, reason=f"Job: {name}")
        except services.CommandError as exc:
            skipped[device.id] = str(exc)
            continue
        db.flush()
        command_ids[device.id] = command.id
    job.command_ids = command_ids
    if skipped:
        job.payload = {**job.payload, "skipped": skipped}
    if not command_ids:
        job.status, job.finished_at = "failed", utcnow()
    audit.record(db, actor, "rmm.job.created", name, tenant_id, devices=len(command_ids), skipped=len(skipped), command=command_type)
    return job


def run_script(db: Session, *, script: Script, devices: list[Device], actor: str, tenant_id: str, parameters: dict | None = None,
               targets: dict | None = None, scheduled_task_id: str | None = None, ticket_id: str | None = None,
               name: str | None = None) -> Job:
    values = validate_parameters(script, parameters or {})
    return create_job(db, tenant_id=tenant_id, actor=actor, name=name or script.name, devices=devices, command_type="script.run",
                      kind="script", payload=script_payload(script, values), script=script, parameters=values, targets=targets,
                      scheduled_task_id=scheduled_task_id, ticket_id=ticket_id)


def retry_failed(db: Session, job: Job, actor: str) -> int:
    """Queue the job's command again on the devices where it failed or expired. Returns how many."""
    command_ids = dict(job.command_ids or {})
    failed = db.execute(select(Command).where(Command.id.in_(list(command_ids.values())),
                                              Command.status.in_(("failed", "expired")))).scalars().all()
    history = list((job.payload or {}).get("retryHistory") or [])
    retried = 0
    for old in failed:
        device = db.get(Device, old.device_id)
        if device is None:
            continue
        try:
            command = services.enqueue_command(db, device, old.type, actor, target_path=old.target_path, record_id=old.record_id,
                                               payload={**(old.payload or {}), "jobId": job.id, "retryOf": old.id},
                                               reason=f"Retry of job: {job.name}")
        except services.CommandError:
            continue
        db.flush()
        history.append({"deviceId": device.id, "previousCommandId": old.id, "newCommandId": command.id,
                        "at": utcnow().isoformat(), "by": actor})
        command_ids[device.id] = command.id
        retried += 1
    if retried:
        job.command_ids = command_ids
        job.status, job.finished_at = "running", None
        job.payload = {**(job.payload or {}), "retries": int((job.payload or {}).get("retries", 0)) + 1,
                       "retryHistory": history}
    audit.record(db, actor, "rmm.job.retried", job.name, job.tenant_id, commands=retried)
    return retried


def job_summary(db: Session, job: Job) -> dict:
    ids = list((job.command_ids or {}).values())
    commands = db.execute(select(Command).where(Command.id.in_(ids))).scalars().all() if ids else []
    counts: dict[str, int] = {}
    for command in commands:
        counts[command.status] = counts.get(command.status, 0) + 1
    return {"total": len(ids), "skipped": len((job.payload or {}).get("skipped") or {}), **counts}


def _ticket_remediation_finished(db: Session, ticket: Ticket) -> bool:
    """An automatic ticket resolution requires verified healthy monitoring AND all completed work."""
    jobs = db.execute(select(Job).where(Job.ticket_id == ticket.id)).scalars().all()
    return all(job.status == "completed" for job in jobs)


def _maybe_close_recovered_monitor_ticket(db: Session, ticket: Ticket) -> None:
    from . import psa
    if ticket.assignee or psa.is_closed(db, ticket) or not _ticket_remediation_finished(db, ticket):
        return
    states = db.execute(select(ConditionState).where(ConditionState.ticket_id == ticket.id)).scalars().all()
    if not states or any(state.triggered or state.resolved_at is None for state in states):
        return
    psa.add_note(db, ticket, "rmm-monitor",
                 "Monitoring has recovered and all linked remediation jobs completed successfully.",
                 kind="resolution")
    psa.set_status(db, ticket, "Resolved", "rmm-monitor")


def refresh_job(db: Session, job_id: str) -> None:
    job = db.get(Job, job_id)
    if job is None or job.status not in {"running"}:
        return
    summary = job_summary(db, job)
    open_count = summary.get("pending", 0) + summary.get("dispatched", 0)
    if open_count:
        return
    failed = summary.get("failed", 0) + summary.get("expired", 0)
    done, cancelled = summary.get("completed", 0), summary.get("cancelled", 0)
    skipped = summary.get("skipped", 0)
    if done == 0 and failed == 0 and cancelled and not skipped:
        job.status = "cancelled"
    elif failed == 0 and cancelled == 0 and skipped == 0:
        job.status = "completed"
    elif done == 0 and failed:
        job.status = "failed"
    else:
        job.status = "partial"
    job.finished_at = utcnow()
    if job.ticket_id:
        ticket = db.get(Ticket, job.ticket_id)
        if ticket is not None and ticket.account_tenant_id == job.tenant_id:
            from . import psa
            psa.add_note(db, ticket, "rmm-job",
                         f"RMM job '{job.name}' finished: {job.status}. "
                         f"{done} completed, {failed} failed/expired, {cancelled} cancelled, "
                         f"{skipped} skipped. Job reference: {job.id}.",
                         kind="internal")
            _maybe_close_recovered_monitor_ticket(db, ticket)


# --------------------------------------------------------------------------- command results


def on_command_complete(db: Session, device: Device, command: Command) -> None:
    """Fold agent results into RMM state. Called from the agent API after a command completes."""
    result = command.result or {}
    if command.type == "patch.scan" and command.status == "completed":
        ingest_patch_scan(db, device, result)
    elif command.type == "patch.install":
        apply_patch_install_result(db, device, command, result)
    elif command.type in {"remote.session.start", "remote.session.end"}:
        from . import remote

        remote.on_command_complete(db, device, command)
    elif command.type == "network.probe":
        from . import network

        network.apply_probe_results(db, device, command)
    job_id = (command.payload or {}).get("jobId")
    if job_id:
        refresh_job(db, job_id)


CLASSIFICATIONS = ("critical", "security", "updates", "feature", "driver", "definition", "third-party", "other")


def _classify(raw: str, severity: str, source: str) -> str:
    text = f"{raw} {severity}".lower()
    if source in {"winget", "choco", "third-party"}:
        return "third-party"
    if "critical" in text:
        return "critical"
    if "security" in text:
        return "security"
    if "definition" in text:
        return "definition"
    if "driver" in text:
        return "driver"
    if "feature" in text or "upgrade" in text:
        return "feature"
    return "updates"


def ingest_patch_scan(db: Session, device: Device, result: dict) -> int:
    patches = result.get("patches")
    if not isinstance(patches, list):
        return 0
    now = utcnow()
    existing = {p.patch_key: p for p in db.execute(select(DevicePatch).where(DevicePatch.device_id == device.id)).scalars()}
    seen: set[str] = set()
    row_cves: dict[str, list[str]] = {}
    for item in patches[:5000]:
        if not isinstance(item, dict):
            continue
        key = str(item.get("id") or item.get("kb") or "").strip()[:200]
        if not key:
            continue
        seen.add(key)
        source = str(item.get("source") or ("windows-update" if device.platform == "windows" else "package"))[:30]
        row = existing.get(key)
        if row is None:
            row = DevicePatch(device_id=device.id, tenant_id=device.tenant_id, patch_key=key, first_seen_at=now)
            db.add(row)
        row.title = str(item.get("title") or key)[:400]
        row.source = source
        row.severity = str(item.get("severity") or "")[:20]
        row.classification = (str(item.get("classification") or "").lower()
                              if str(item.get("classification") or "").lower() in CLASSIFICATIONS
                              else _classify(str(item.get("classification") or item.get("categories") or ""), row.severity, source))
        row.product = str(item.get("product") or "")[:200]
        row.installed_version = str(item.get("installedVersion") or "")[:80]
        row.available_version = str(item.get("availableVersion") or "")[:80]
        row.reboot_required = bool(item.get("rebootRequired"))
        cves = item.get("cves") or []
        if isinstance(cves, str):
            cves = [c.strip() for c in cves.split(",")]
        row_cves[key] = [str(c)[:30] for c in cves if str(c).startswith("CVE-")][:200]
        released = item.get("releasedAt")
        if released:
            try:
                row.released_at = datetime.fromisoformat(str(released).replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None)
            except ValueError:
                pass
        # Still reported as missing: keep "installing" briefly and keep "failed" visible; anything else is missing.
        if not (row.status == "installing" and now - row.last_seen_at < timedelta(hours=6)) and row.status != "failed":
            row.status = "missing"
        row.last_seen_at = now
    # Anything previously missing that is no longer reported has been installed.
    for key, row in existing.items():
        if key not in seen and row.status in {"missing", "installing", "failed"}:
            row.status, row.installed_at = "installed", now
    db.flush()
    sync_update_vulnerabilities(db, device, now, row_cves)
    metrics = dict(device.metrics or {})
    metrics["patchScanAt"] = now.isoformat() + "Z"
    if "rebootPending" in result:
        metrics["rebootPending"] = bool(result["rebootPending"])
    device.metrics = metrics
    return len(seen)


MSRC_SEVERITY = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}
UPDATE_VULN_SOURCE = "windows-update"


def sync_update_vulnerabilities(db: Session, device: Device, scanned_at: datetime, cves: dict[str, list[str]]) -> int:
    """Missing Windows security updates are this device's OS vulnerabilities (OSV has no Windows data).

    One vulnerability per missing update, named by its KB; it is verified fixed once a patch scan no
    longer reports the update. Returns how many new ones were found.
    """
    from . import vulnmgmt

    if device.platform != "windows":
        return 0
    missing = db.execute(select(DevicePatch).where(
        DevicePatch.device_id == device.id, DevicePatch.source == "windows-update",
        DevicePatch.status.in_(("missing", "installing", "failed")),
        DevicePatch.classification.in_(("critical", "security")))).scalars().all()
    kev = _known_exploited_cves(db)
    found = 0
    for patch in missing:
        ids = cves.get(patch.patch_key, [])
        row = db.execute(select(Vulnerability).where(Vulnerability.device_id == device.id,
                                                     Vulnerability.vuln_id == patch.patch_key[:80],
                                                     Vulnerability.package == "Windows")).scalar_one_or_none()
        is_new = row is None
        if row is None:
            row = Vulnerability(tenant_id=device.tenant_id, device_id=device.id, vuln_id=patch.patch_key[:80], package="Windows",
                                source=UPDATE_VULN_SOURCE, first_seen=patch.first_seen_at or scanned_at)
            db.add(row)
            found += 1
        row.source = UPDATE_VULN_SOURCE
        row.installed_version = (device.os_version or "")[:100]
        row.fixed_version = patch.patch_key[:100]
        row.severity = MSRC_SEVERITY.get((patch.severity or "").lower(),
                                         "critical" if patch.classification == "critical" else "high")
        row.known_exploited = bool(set(ids) & kev)
        if row.known_exploited:
            row.severity = "critical"
        summary = patch.title
        if ids:
            summary += "\nAddresses " + ", ".join(ids[:50]) + (f" and {len(ids) - 50} more" if len(ids) > 50 else "")
        row.summary = summary[:2000]
        row.last_seen = scanned_at
        reopened = row.status == "fixed"
        if reopened:
            row.status, row.verified_at, row.status_changed_at = "open", None, utcnow()
        if is_new or reopened:
            db.flush()
            vulnmgmt.record_detection(db, row, reopened)
    vulnmgmt.verify_after_scan(db, device, scanned_at, source=UPDATE_VULN_SOURCE)
    return found


def _known_exploited_cves(db: Session) -> set[str]:
    """CISA KEV CVE IDs from the catalogue the vulnerability scanner last fetched (no network call here)."""
    from . import exposure

    return exposure._KEV_CACHE[1]


def apply_patch_install_result(db: Session, device: Device, command: Command, result: dict) -> None:
    now = utcnow()
    outcomes = {str(o.get("id")): o for o in result.get("results", []) if isinstance(o, dict) and o.get("id")}
    requested = [str(i) for i in (command.payload or {}).get("patchIds", [])]
    for key in requested or outcomes:
        row = db.execute(select(DevicePatch).where(DevicePatch.device_id == device.id, DevicePatch.patch_key == key)).scalar_one_or_none()
        if row is None:
            continue
        outcome = outcomes.get(key)
        ok = command.status == "completed" and (outcome is None or outcome.get("success", True))
        row.status = "installed" if ok else "failed"
        row.installed_at = now if ok else row.installed_at
        row.error = "" if ok else str((outcome or {}).get("error") or result.get("error") or "install failed")[:300]
    if result.get("rebootRequired"):
        device.metrics = {**(device.metrics or {}), "rebootPending": True}


# --------------------------------------------------------------------------- patch policy


DEFAULT_APPROVALS = {"critical": "auto", "security": "auto", "updates": "manual", "feature": "reject", "driver": "manual",
                     "definition": "auto", "third-party": "auto", "other": "manual"}
DEFAULT_WINDOW = {"days": [0, 1, 2, 3, 4, 5, 6], "start": "02:00", "durationMinutes": 180, "tz": "UTC"}
DEFAULT_REBOOT = {"mode": "if_required", "notifyUser": True, "deferMinutes": 60, "maxDeferrals": 3}


def rmm_policy_for_device(db: Session, device: Device, policies: list[PatchPolicy] | None = None) -> PatchPolicy | None:
    """The RMM patch policy (Patching page) that covers this device, if any."""
    candidates = policies if policies is not None else db.execute(
        select(PatchPolicy).where(PatchPolicy.tenant_id == device.tenant_id, PatchPolicy.enabled.is_(True))).scalars().all()
    group_match = [p for p in candidates if p.tenant_id == device.tenant_id and p.group_id and p.group_id == device.group_id]
    if group_match:
        return group_match[0]
    tenant_match = [p for p in candidates if p.tenant_id == device.tenant_id and not p.group_id]
    return tenant_match[0] if tenant_match else None


def policy_for_device(db: Session, device: Device, policies: list[PatchPolicy] | None = None) -> PatchPolicy | None:
    """An RMM patch policy wins; otherwise the patch section of the device's protection policy applies."""
    return rmm_policy_for_device(db, device, policies) or protection_patch_policy(db, device)


# ---------------------------------------------------------------- patching from the protection policy

WINDOW_DAYS = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
WINDOW_GROUPS = {"daily": list(range(7)), "everyday": list(range(7)), "weekdays": [0, 1, 2, 3, 4], "weekends": [5, 6]}
REBOOT_BY_BEHAVIOUR = {
    "never": {"mode": "never", "notifyUser": False, "deferMinutes": 0},
    "prompt": {"mode": "if_required", "notifyUser": True, "deferMinutes": 60},
    "outside-hours": {"mode": "if_required", "notifyUser": True, "deferMinutes": 5},  # installs already run in the window
    "force": {"mode": "always", "notifyUser": True, "deferMinutes": 5},
}


def parse_maintenance_window(text: str, tz: str = "UTC") -> dict:
    """'daily 22:00-05:00', 'weekdays 19:00-23:00', 'sat,sun 02:00-06:00', 'mon-fri 20:00-23:30' -> window dict."""
    match = re.fullmatch(r"\s*([a-z,\-]+)\s+(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*", (text or "").lower())
    if not match:
        return {**DEFAULT_WINDOW, "tz": tz}
    spec, h1, m1, h2, m2 = match.groups()
    days: list[int] = []
    for part in spec.split(","):
        if part in WINDOW_GROUPS:
            days += WINDOW_GROUPS[part]
        elif "-" in part and all(p in WINDOW_DAYS for p in part.split("-", 1)):
            start, end = (WINDOW_DAYS[p] for p in part.split("-", 1))
            days += [d % 7 for d in range(start, start + ((end - start) % 7) + 1)]
        elif part in WINDOW_DAYS:
            days.append(WINDOW_DAYS[part])
    start_minutes, end_minutes = int(h1) * 60 + int(m1), int(h2) * 60 + int(m2)
    duration = (end_minutes - start_minutes) % (24 * 60) or 24 * 60
    return {"days": sorted(set(days)) or DEFAULT_WINDOW["days"], "start": f"{int(h1):02d}:{int(m1):02d}", "durationMinutes": duration, "tz": tz}


def protection_patch_policy(db: Session, device: Device) -> PatchPolicy | None:
    """A transient (never saved) patch policy built from the protection policy's patch settings."""
    cache = db.info.setdefault("protection_patch_policy", {})
    if device.id in cache:
        return cache[device.id]
    resolution, _ = services.effective_policy(db, device)
    settings = resolution["settings"]["patch"]
    policy = None
    if settings.get("enabled"):
        auto = settings.get("autoApprove", "security")
        approvals = {
            "critical": "auto" if auto in {"critical", "security", "all"} else "manual",
            "security": "auto" if auto in {"security", "all"} else "manual",
            "definition": "manual" if auto == "none" else "auto",
            "updates": "auto" if auto == "all" else "manual",
            "other": "auto" if auto == "all" else "manual",
            "driver": "manual",
            "feature": "reject",
            "third-party": ("auto" if auto in {"security", "all"} else "manual") if settings.get("thirdPartyApps", True) else "reject",
        }
        from .models import Tenant

        tenant = db.get(Tenant, device.tenant_id)
        tz = str(((tenant.settings or {}) if tenant else {}).get("timezone") or "UTC")
        policy = PatchPolicy(id=f"protection-policy:{device.tenant_id}", tenant_id=device.tenant_id, name="Protection policy patch settings",
                             enabled=True, approvals=approvals, delay_days=int(settings.get("deferralDaysOther", 7)), rings=[],
                             window=parse_maintenance_window(settings.get("maintenanceWindow", ""), tz),
                             reboot=dict(REBOOT_BY_BEHAVIOUR.get(settings.get("rebootBehaviour", "prompt"), DEFAULT_REBOOT)),
                             scan_interval_hours=int(settings.get("vulnerabilityScanHours", 24)), last_window_run="")
        policy.derived = True  # python attribute only, not a column
        policy.critical_delay_days = int(settings.get("deferralDaysCritical", 0))
        policy.prioritise_known_exploited = bool(settings.get("prioritiseKnownExploited", True))
        policy.install_in_window = bool(settings.get("installInWindow", False))
    cache[device.id] = policy
    return policy


def _known_exploited_products(db: Session, device: Device) -> set[str]:
    """Packages on this device with an open known-exploited (CISA KEV) vulnerability."""
    from .models import Vulnerability

    rows = db.execute(select(Vulnerability.package).where(Vulnerability.device_id == device.id, Vulnerability.known_exploited.is_(True),
                                                          Vulnerability.status.in_(("open", "patching")))).all()
    return {name.lower() for (name,) in rows}


def ring_delay(policy: PatchPolicy, device: Device) -> tuple[str, int]:
    for ring in policy.rings or []:
        if device.group_id and device.group_id in (ring.get("groupIds") or []):
            return str(ring.get("name") or "Ring"), int(ring.get("delayDays") or 0)
    rings = policy.rings or []
    catch_all = [r for r in rings if not r.get("groupIds")]
    if catch_all:
        return str(catch_all[-1].get("name") or "Broad"), int(catch_all[-1].get("delayDays") or 0)
    return "Default", int(policy.delay_days or 0)


def approval_state(policy: PatchPolicy | None, patch: DevicePatch, decisions: dict[str, str]) -> str:
    """approved | rejected | pending (needs a human)."""
    decision = decisions.get(patch.patch_key)
    if decision:
        return decision
    rules = {**DEFAULT_APPROVALS, **((policy.approvals if policy else None) or {})}
    rule = rules.get(patch.classification, "manual")
    return {"auto": "approved", "reject": "rejected"}.get(rule, "pending")


def installable_patches(db: Session, device: Device, policy: PatchPolicy | None, now: datetime | None = None,
                        scheduled: bool = False) -> list[DevicePatch]:
    """Approved, missing patches. Protection-policy deferrals apply to scheduled installs, not to "Install now"."""
    now = now or utcnow()
    decisions = dict(db.execute(select(PatchApproval.patch_key, PatchApproval.decision)
                                .where(PatchApproval.tenant_id == device.tenant_id)).all())
    _, delay = ring_delay(policy, device) if policy else ("Default", 0)
    derived = bool(getattr(policy, "derived", False))
    kev_products = _known_exploited_products(db, device) if derived and getattr(policy, "prioritise_known_exploited", False) else set()
    out = []
    for patch in db.execute(select(DevicePatch).where(DevicePatch.device_id == device.id, DevicePatch.status.in_(("missing", "failed")))).scalars():
        state = approval_state(policy, patch, decisions)
        if state != "approved":
            continue
        if derived and scheduled:
            # Protection-policy deferrals: critical vs everything else; known-exploited fixes skip deferral.
            name = (patch.product or patch.patch_key.split(":", 1)[-1]).lower()
            delay = 0 if name in kev_products else (policy.critical_delay_days if patch.classification == "critical" else policy.delay_days)
        elif derived:
            delay = 0  # "Install now" from a technician is never deferred by the protection policy
        # Manual approvals install straight away; auto-approvals respect the ring delay.
        reference = patch.released_at or patch.first_seen_at
        if patch.patch_key not in decisions and delay and reference + timedelta(days=delay) > now:
            continue
        out.append(patch)
    return out


def _tz(name: str | None):
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name or "UTC")
    except Exception:  # noqa: BLE001 - unknown zone or no tz database
        return timezone.utc


def in_window(window: dict, now_utc: datetime) -> tuple[bool, str]:
    """(inside?, window key) for a maintenance window like {"days": [5,6], "start": "02:00", "durationMinutes": 180}."""
    window = {**DEFAULT_WINDOW, **(window or {})}
    local = now_utc.replace(tzinfo=timezone.utc).astimezone(_tz(window.get("tz")))
    hour, minute = (int(x) for x in str(window.get("start", "02:00")).split(":")[:2])
    duration = timedelta(minutes=int(window.get("durationMinutes") or 180))
    for days_back in (0, 1):
        start = (local - timedelta(days=days_back)).replace(hour=hour, minute=minute, second=0, microsecond=0)
        if start.weekday() in [int(d) for d in window.get("days", [])] and start <= local < start + duration:
            return True, start.strftime("%Y-%m-%dT%H:%M")
    return False, ""


def run_patch_windows(db: Session, now: datetime | None = None) -> int:
    """Queue patch.install for devices whose policy window is open and have approved missing patches."""
    now = now or utcnow()
    queued = 0
    policies = db.execute(select(PatchPolicy).where(PatchPolicy.enabled.is_(True))).scalars().all()
    for policy in policies:
        inside, key = in_window(policy.window, now)
        if not inside or policy.last_window_run == key:
            continue
        policy.last_window_run = key
        devices = db.execute(select(Device).where(Device.tenant_id == policy.tenant_id, Device.approved.is_(True))).scalars().all()
        per_tenant = [p for p in policies if p.tenant_id == policy.tenant_id]
        for device in devices:
            if policy_for_device(db, device, per_tenant) is not policy:
                continue
            patches = installable_patches(db, device, policy, now)
            if not patches:
                continue
            reboot = {**DEFAULT_REBOOT, **(policy.reboot or {})}
            payload = {"patchIds": [p.patch_key for p in patches],
                       "patches": [{"id": p.patch_key, "source": p.source, "title": p.title} for p in patches],
                       "reboot": reboot, "policyId": policy.id}
            try:
                services.enqueue_command(db, device, "patch.install", "patch-policy", payload=payload,
                                         reason=f"Maintenance window {key} ({policy.name})")
            except services.CommandError as exc:
                log.info("skip patch install on %s: %s", device.hostname, exc)
                continue
            for patch in patches:
                patch.status = "installing"
            queued += 1
    queued += _run_protection_policy_windows(db, policies, now)
    return queued


def _run_protection_policy_windows(db: Session, rmm_policies: list[PatchPolicy], now: datetime) -> int:
    """Devices no RMM patch policy covers follow their protection policy's window, approvals and reboots."""
    queued = 0
    for device in db.execute(select(Device).where(Device.approved.is_(True))).scalars():
        if rmm_policy_for_device(db, device, [p for p in rmm_policies if p.tenant_id == device.tenant_id]):
            continue
        policy = protection_patch_policy(db, device)
        if policy is None or not policy.install_in_window:
            continue
        inside, key = in_window(policy.window, now)
        if not inside or device.patch_window_run == key:
            continue
        device.patch_window_run = key  # once per window per device
        patches = installable_patches(db, device, policy, now, scheduled=True)
        if not patches:
            continue
        payload = {"patchIds": [p.patch_key for p in patches],
                   "patches": [{"id": p.patch_key, "source": p.source, "title": p.title} for p in patches],
                   "reboot": dict(policy.reboot), "policyId": policy.id}
        try:
            services.enqueue_command(db, device, "patch.install", "protection-policy", payload=payload,
                                     reason=f"Maintenance window {key} (protection policy)")
        except services.CommandError as exc:
            log.info("skip patch install on %s: %s", device.hostname, exc)
            continue
        for patch in patches:
            patch.status = "installing"
        queued += 1
    return queued


def queue_patch_scans(db: Session, now: datetime | None = None) -> int:
    """Ask online devices for a patch scan when their last one is older than the policy interval (default 12h)."""
    now = now or utcnow()
    online_since = now - timedelta(minutes=10)
    policies = db.execute(select(PatchPolicy).where(PatchPolicy.enabled.is_(True))).scalars().all()
    queued = 0
    for device in db.execute(select(Device).where(Device.approved.is_(True), Device.last_seen_at >= online_since)).scalars():
        policy = policy_for_device(db, device, [p for p in policies if p.tenant_id == device.tenant_id])
        interval = timedelta(hours=(policy.scan_interval_hours if policy else 24) or 24)
        last = (device.metrics or {}).get("patchScanAt")
        last_at = datetime.fromisoformat(last.rstrip("Z")) if last else None
        if last_at and now - last_at < interval:
            continue
        recent = db.execute(select(Command.id).where(Command.device_id == device.id, Command.type == "patch.scan",
                                                     Command.created_at >= now - interval)).first()
        if recent:
            continue
        try:
            services.enqueue_command(db, device, "patch.scan", "patch-policy", reason="Scheduled patch scan")
            queued += 1
        except services.CommandError:
            continue
    return queued


def patch_compliance(db: Session, tenant_ids: list[str]) -> dict:
    devices = db.execute(select(Device).where(Device.tenant_id.in_(tenant_ids), Device.approved.is_(True))).scalars().all()
    missing_by_device: dict[str, dict[str, int]] = {}
    for device_id, classification, count in db.execute(
            select(DevicePatch.device_id, DevicePatch.classification, func.count())
            .where(DevicePatch.tenant_id.in_(tenant_ids), DevicePatch.status.in_(("missing", "failed", "installing")))
            .group_by(DevicePatch.device_id, DevicePatch.classification)).all():
        missing_by_device.setdefault(device_id, {})[classification] = count
    failed = db.execute(select(func.count()).where(DevicePatch.tenant_id.in_(tenant_ids), DevicePatch.status == "failed")).scalar() or 0
    scanned = [d for d in devices if (d.metrics or {}).get("patchScanAt")]
    fully = [d for d in scanned if not missing_by_device.get(d.id)]
    critical = [d for d in scanned if missing_by_device.get(d.id, {}).get("critical") or missing_by_device.get(d.id, {}).get("security")]
    reboot = [d for d in devices if (d.metrics or {}).get("rebootPending")]
    return {
        "devices": len(devices), "scanned": len(scanned), "fullyPatched": len(fully),
        "missingCriticalOrSecurity": len(critical), "pendingReboot": len(reboot), "failedPatches": failed,
        "compliancePercent": round(100 * len(fully) / len(scanned), 1) if scanned else 0,
        "byDevice": {d.id: missing_by_device.get(d.id, {}) for d in devices},
    }


# --------------------------------------------------------------------------- scheduling


def next_run(schedule: dict, after: datetime) -> datetime | None:
    """Next UTC run time strictly after ``after`` for once/interval/daily/weekly/monthly schedules."""
    kind = schedule.get("type", "daily")
    tz = _tz(schedule.get("tz"))
    if kind == "interval":
        minutes = max(5, int(schedule.get("everyMinutes") or 60))
        return after + timedelta(minutes=minutes)
    hour, minute = (int(x) for x in str(schedule.get("at") or "02:00").split(":")[:2])
    local_after = after.replace(tzinfo=timezone.utc).astimezone(tz)
    if kind == "once":
        try:
            day = datetime.fromisoformat(str(schedule.get("date")))
        except ValueError:
            return None
        candidate = day.replace(hour=hour, minute=minute, tzinfo=tz)
        utc = candidate.astimezone(timezone.utc).replace(tzinfo=None)
        return utc if utc > after else None
    for offset in range(0, 400):
        day = local_after + timedelta(days=offset)
        candidate = day.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if candidate <= local_after:
            continue
        if kind == "weekly" and candidate.weekday() not in [int(d) for d in schedule.get("days", [0])]:
            continue
        if kind == "monthly" and candidate.day != int(schedule.get("dayOfMonth") or 1):
            continue
        return candidate.astimezone(timezone.utc).replace(tzinfo=None)
    return None


def run_scheduled_task(db: Session, task: ScheduledTask, actor: str | None = None) -> list[Job]:
    from .deps import tenant_subtree

    allowed = tenant_subtree(db, task.tenant_id)
    devices = resolve_targets(db, allowed, task.targets or {})
    jobs: list[Job] = []
    who = actor or f"schedule:{task.name}"
    for action in task.actions or []:
        if action.get("type") == "script":
            script = db.get(Script, action.get("scriptId"))
            if script is None:
                continue
            try:
                jobs.append(run_script(db, script=script, devices=devices, actor=who, tenant_id=task.tenant_id,
                                       parameters=action.get("parameters") or {}, targets=task.targets, scheduled_task_id=task.id,
                                       name=f"{task.name}: {script.name}"))
            except ValueError as exc:
                log.warning("scheduled task %s script error: %s", task.id, exc)
        elif action.get("type") == "command":
            jobs.append(create_job(db, tenant_id=task.tenant_id, actor=who, name=f"{task.name}: {action.get('command')}",
                                   devices=devices, command_type=str(action.get("command")), payload=action.get("payload") or {},
                                   targets=task.targets, target_path=str(action.get("targetPath") or ""), scheduled_task_id=task.id))
        elif action.get("type") == "software":
            package = db.get(SoftwarePackage, action.get("packageId"))
            if package is not None:
                jobs.append(deploy_software(db, package, devices, who, task.tenant_id, scheduled_task_id=task.id))
    task.last_run_at = utcnow()
    return jobs


def run_due_tasks(db: Session, now: datetime | None = None) -> int:
    now = now or utcnow()
    count = 0
    for task in db.execute(select(ScheduledTask).where(ScheduledTask.enabled.is_(True), ScheduledTask.next_run_at <= now)).scalars():
        run_scheduled_task(db, task)
        task.next_run_at = next_run(task.schedule or {}, now)
        if task.next_run_at is None:
            task.enabled = False
        count += 1
    return count


# --------------------------------------------------------------------------- software


def software_payload(package: SoftwarePackage, action: str = "install") -> dict:
    return {"packageId": package.id, "name": package.name, "installer": package.installer, "identifier": package.identifier,
            "sha256": package.sha256, "args": package.install_args if action == "install" else package.uninstall_args,
            "version": package.version, "action": action}


def deploy_software(db: Session, package: SoftwarePackage, devices: list[Device], actor: str, tenant_id: str,
                    action: str = "install", scheduled_task_id: str | None = None) -> Job:
    matching = [d for d in devices if d.platform == package.platform]
    command = "software.install" if action == "install" else "software.uninstall"
    return create_job(db, tenant_id=tenant_id, actor=actor, name=f"{action.title()} {package.name}", devices=matching,
                      command_type=command, kind="software", payload=software_payload(package, action),
                      record_id=package.identifier if action == "uninstall" else "", scheduled_task_id=scheduled_task_id)


# --------------------------------------------------------------------------- monitoring

OPS = {">": lambda a, b: a > b, "<": lambda a, b: a < b, ">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b,
       "==": lambda a, b: a == b, "!=": lambda a, b: a != b}
METRICS = {
    "cpu": "CPU usage (%)", "memory": "Memory usage (%)", "disk_free_percent": "Disk free (%)", "disk_free_gb": "Disk free (GB)",
    "offline_minutes": "Offline for (minutes)", "service_stopped": "Service not running", "process_missing": "Process not running",
    "reboot_pending": "Reboot pending", "pending_patches": "Missing patches (count)", "uptime_days": "Uptime (days)",
    "av_unhealthy": "Protection unhealthy",
}


def _disks(metrics: dict, target: str) -> list[dict]:
    disks = [d for d in metrics.get("disks", []) if isinstance(d, dict)]
    if target:
        disks = [d for d in disks if str(d.get("mount", "")).lower().rstrip("\\/") == target.lower().rstrip("\\/")]
    return disks


def metric_value(db: Session, condition: MonitorCondition, device: Device, now: datetime) -> tuple[float | None, str]:
    """Current value of the condition's metric for this device, and a human description."""
    metrics = device.metrics or {}
    m, target = condition.metric, condition.target.strip()
    if m == "offline_minutes":
        if device.last_seen_at is None:
            return None, ""
        minutes = (now - device.last_seen_at).total_seconds() / 60
        return round(minutes, 1), f"offline for {int(minutes)} minutes"
    if m == "pending_patches":
        query = select(func.count()).where(DevicePatch.device_id == device.id, DevicePatch.status.in_(("missing", "failed")))
        if target:
            query = query.where(DevicePatch.classification == target)
        count = db.execute(query).scalar() or 0
        return float(count), f"{count} missing {target or ''} patches".replace("  ", " ")
    if m == "av_unhealthy":
        bad = device.health_state not in {"healthy", "unknown", "isolated"}
        return (1.0 if bad else 0.0), f"agent health is {device.health_state}"
    if not metrics or not metrics.get("reportedAt"):
        return None, ""
    if m == "cpu" and "cpuPercent" in metrics:
        return float(metrics["cpuPercent"]), f"CPU at {metrics['cpuPercent']:.0f}%"
    if m == "memory" and "memoryPercent" in metrics:
        return float(metrics["memoryPercent"]), f"memory at {metrics['memoryPercent']:.0f}%"
    if m in {"disk_free_percent", "disk_free_gb"}:
        disks = _disks(metrics, target)
        if not disks:
            return None, ""
        key = "freePercent" if m == "disk_free_percent" else "freeGb"
        worst = min(disks, key=lambda d: float(d.get(key, 1e9)))
        unit = "%" if m == "disk_free_percent" else " GB"
        return float(worst.get(key, 0)), f"{worst.get('mount')} has {float(worst.get(key, 0)):.1f}{unit} free"
    if m == "service_stopped":
        stopped = [str(s).lower() for s in metrics.get("stoppedServices", [])]
        if target:
            hit = target.lower() in stopped
            return (1.0 if hit else 0.0), f"service {target} is not running"
        return float(len(stopped)), f"{len(stopped)} automatic services are not running"
    if m == "process_missing":
        if not target:
            return None, ""
        running = {str(p).lower() for p in metrics.get("processNames", [])}
        if not running:
            return None, ""
        missing = target.lower() not in running
        return (1.0 if missing else 0.0), f"process {target} is not running"
    if m == "reboot_pending":
        return (1.0 if metrics.get("rebootPending") else 0.0), "a restart is pending"
    if m == "uptime_days" and "uptimeSeconds" in metrics:
        days = float(metrics["uptimeSeconds"]) / 86400
        return round(days, 1), f"up for {days:.1f} days"
    return None, ""


def _conditions_for(db: Session, device: Device) -> list[MonitorCondition]:
    """Enabled monitors that apply to a device. A monitor on a parent tenant (e.g. the MSP) covers its customers."""
    from .deps import tenant_subtree

    out = []
    for condition in db.execute(select(MonitorCondition).where(MonitorCondition.enabled.is_(True))).scalars():
        if condition.tenant_id and condition.tenant_id != device.tenant_id \
                and device.tenant_id not in tenant_subtree(db, condition.tenant_id):
            continue
        scope = condition.scope or {}
        if scope.get("platforms") and device.platform not in scope["platforms"]:
            continue
        if scope.get("groupIds") and device.group_id not in scope["groupIds"]:
            continue
        if scope.get("tags") and not set(scope["tags"]) & set(device.tags or []):
            continue
        if scope.get("tenantIds") and device.tenant_id not in scope["tenantIds"]:
            continue
        out.append(condition)
    return out


def evaluate_device(db: Session, device: Device, now: datetime | None = None, offline_only: bool = False) -> list[str]:
    """Evaluate monitors for one device. Returns the ids of conditions that triggered on this call.

    Heartbeats evaluate everything except offline checks; the scheduler evaluates offline checks only.
    """
    now = now or utcnow()
    fired: list[str] = []
    for condition in _conditions_for(db, device):
        if (condition.metric == "offline_minutes") != offline_only:
            continue
        value, message = metric_value(db, condition, device, now)
        state = db.execute(select(ConditionState).where(ConditionState.condition_id == condition.id,
                                                        ConditionState.device_id == device.id)).scalar_one_or_none()
        if value is None:
            continue
        failing = OPS.get(condition.operator, OPS[">"])(value, condition.threshold)
        if state is None:
            state = ConditionState(condition_id=condition.id, device_id=device.id, tenant_id=device.tenant_id)
            db.add(state)
        state.last_value = value
        if failing:
            state.message = message[:300]
            if state.failing_since is None:
                state.failing_since = now
            elapsed = (now - state.failing_since).total_seconds() / 60
            # Offline checks measure their own duration, so they trigger as soon as the threshold is crossed.
            needed = 0 if condition.metric == "offline_minutes" else condition.duration_minutes
            if not state.triggered and elapsed >= needed:
                _trigger(db, condition, device, state, message, now)
                fired.append(condition.id)
        else:
            if state.triggered:
                _clear(db, condition, device, state, now)
            state.failing_since = None
            state.triggered = False
    return fired


def _trigger(db: Session, condition: MonitorCondition, device: Device, state: ConditionState, message: str, now: datetime) -> None:
    state.triggered, state.triggered_at, state.resolved_at = True, now, None
    title = f"{condition.name}: {device.hostname} — {message}"
    alert = Alert(tenant_id=device.tenant_id, device_id=device.id, rule_id=f"monitor:{condition.id}", title=title[:300],
                  severity=condition.severity,
                  details={"category": "monitoring", "metric": condition.metric, "value": state.last_value,
                           "threshold": condition.threshold, "operator": condition.operator, "target": condition.target})
    db.add(alert)
    db.flush()
    state.alert_id = alert.id
    # Create the linked ticket first, even if it appears after a remediation
    # action in the user's rule order. All remediation jobs then share its ID.
    for action in condition.actions or []:
        if action.get("type") != "ticket" or state.ticket_id:
            continue
        priority = action.get("priority") or services.PRIORITY_BY_SEVERITY.get(condition.severity, "P3")
        ticket = services.open_ticket(db, device.tenant_id, title, f"Raised by monitor '{condition.name}'.\n\n{message}",
                                      priority, "rmm", "rmm-monitor", device_id=device.id,
                                      queue=str(action.get("board") or "Service Desk"))
        db.flush()
        state.ticket_id = ticket.id
    for action in condition.actions or []:
        kind = action.get("type")
        if kind == "ticket":
            continue
        elif kind == "script":
            script = db.get(Script, action.get("scriptId"))
            if script is not None and device.platform in (script.platforms or []):
                try:
                    run_script(db, script=script, devices=[device], actor=f"monitor:{condition.name}", tenant_id=device.tenant_id,
                               parameters=action.get("parameters") or {}, name=f"Self-heal: {script.name}",
                               ticket_id=state.ticket_id)
                except ValueError as exc:
                    log.warning("self-heal script failed validation: %s", exc)
        elif kind == "command" and action.get("command"):
            create_job(db, tenant_id=device.tenant_id, actor=f"monitor:{condition.name}",
                       name=f"Self-heal: {condition.name}", devices=[device],
                       command_type=str(action["command"]),
                       target_path=str(action.get("targetPath") or condition.target or ""),
                       payload=action.get("payload") or {}, ticket_id=state.ticket_id)
        elif kind == "webhook":
            services.fire_webhooks(db, device.tenant_id, "monitor.triggered",
                                   {"title": title, "severity": condition.severity, "device": device.hostname})
        elif kind == "email" and action.get("to"):
            from . import mailer

            mailer.send(str(action["to"]), f"[Fenrir] {title}", f"{title}\n\nDevice: {device.hostname}\nCondition: {condition.name}")
    audit.record(db, "rmm-monitor", "monitor.triggered", f"{device.hostname}:{condition.name}", device.tenant_id, value=state.last_value)


def _clear(db: Session, condition: MonitorCondition, device: Device, state: ConditionState, now: datetime) -> None:
    state.resolved_at = now
    state.triggered = False  # Persist recovery before checking linked ticket/job states.
    if not condition.auto_resolve:
        return
    if state.alert_id:
        alert = db.get(Alert, state.alert_id)
        if alert is not None and alert.status in {"new", "triaged"}:
            alert.status, alert.updated_at = "resolved", now
    if state.ticket_id:
        ticket = db.get(Ticket, state.ticket_id)
        if ticket is not None and ticket.device_id == device.id and ticket.source == "rmm":
            from . import psa
            if not psa.is_closed(db, ticket):
                # A technician-assigned ticket requires a human resolution.
                if ticket.assignee:
                    psa.add_note(db, ticket, "rmm-monitor",
                                 f"Condition '{condition.name}' recovered. Ticket remains open for its assigned technician.",
                                 kind="internal")
                else:
                    if not _ticket_remediation_finished(db, ticket):
                        psa.add_note(db, ticket, "rmm-monitor",
                                     f"Condition '{condition.name}' recovered, but linked RMM work has not "
                                     "all completed successfully. The ticket remains open for review.",
                                     kind="internal")
                    else:
                        _maybe_close_recovered_monitor_ticket(db, ticket)


def record_heartbeat_metrics(db: Session, device: Device, metrics: dict) -> None:
    if not isinstance(metrics, dict) or not metrics:
        return
    clean: dict = {"reportedAt": utcnow().isoformat() + "Z"}
    for key in ("cpuPercent", "memoryPercent", "memoryTotalGb", "uptimeSeconds"):
        if isinstance(metrics.get(key), (int, float)):
            clean[key] = round(float(metrics[key]), 2)
    if isinstance(metrics.get("disks"), list):
        clean["disks"] = [
            {"mount": str(d.get("mount", ""))[:120], "totalGb": round(float(d.get("totalGb", 0)), 1),
             "freeGb": round(float(d.get("freeGb", 0)), 1), "freePercent": round(float(d.get("freePercent", 0)), 1)}
            for d in metrics["disks"][:32] if isinstance(d, dict)
        ]
    for key in ("loggedOnUser", "lastBootAt", "publicIp", "domain", "manufacturer", "model", "cpuModel", "timezone"):
        if metrics.get(key):
            clean[key] = str(metrics[key])[:200]
    for key in ("stoppedServices", "processNames", "users"):
        if isinstance(metrics.get(key), list):
            clean[key] = [str(x)[:120] for x in metrics[key][:400]]
    if "rebootPending" in metrics:
        clean["rebootPending"] = bool(metrics["rebootPending"])
    if isinstance(metrics.get("remoteCapabilities"), list):
        clean["remoteCapabilities"] = [str(x)[:20] for x in metrics["remoteCapabilities"][:10]]
    previous = device.metrics or {}
    for key in ("patchScanAt",):
        if key in previous:
            clean[key] = previous[key]
    if "rebootPending" not in clean and "rebootPending" in previous:
        clean["rebootPending"] = previous["rebootPending"]
    device.metrics = clean
    free = [d["freePercent"] for d in clean.get("disks", [])]
    db.add(DeviceMetric(device_id=device.id, cpu=clean.get("cpuPercent", 0), memory=clean.get("memoryPercent", 0),
                        disk_free_percent=min(free) if free else 100))


def evaluate_offline(db: Session, now: datetime | None = None) -> int:
    now = now or utcnow()
    count = 0
    has_offline = db.execute(select(MonitorCondition.id).where(MonitorCondition.enabled.is_(True),
                                                               MonitorCondition.metric == "offline_minutes")).first()
    if not has_offline:
        return 0
    for device in db.execute(select(Device).where(Device.approved.is_(True), Device.last_seen_at.is_not(None))).scalars():
        count += len(evaluate_device(db, device, now, offline_only=True))
    return count


MAX_PENDING_COMMAND_DAYS = 7


def expire_stale_queued_commands(db: Session, now: datetime | None = None) -> int:
    """Expire only commands that were NEVER delivered to an endpoint.

    Already-dispatched work may have executed; those commands deliberately stay
    outstanding for durable-result reconciliation instead of being re-issued.
    """
    now = now or utcnow()
    cutoff = now - timedelta(days=MAX_PENDING_COMMAND_DAYS)
    query = select(Command).where(Command.status == "pending", Command.created_at < cutoff)
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        query = query.with_for_update(skip_locked=True)
    expired = db.execute(query).scalars().all()
    for command in expired:
        command.status = "expired"
        command.updated_at = command.completed_at = now
        command.result = {"error": "Queued command expired before endpoint delivery",
                          "expiredWithoutExecution": True}
        job_id = (command.payload or {}).get("jobId")
        if job_id:
            refresh_job(db, job_id)
    return len(expired)


def tick(db: Session) -> dict:
    """One scheduler pass: due tasks, offline monitors, patch windows and scans."""
    now = utcnow()
    result = {"tasks": run_due_tasks(db, now), "offline": evaluate_offline(db, now), "patchInstalls": run_patch_windows(db, now),
              "patchScans": queue_patch_scans(db, now)}
    from . import vulnmgmt

    result["vulnerabilityAcceptancesExpired"] = vulnmgmt.expire_acceptances(db, now)
    result["undeliveredCommandsExpired"] = expire_stale_queued_commands(db, now)
    cutoff = now - timedelta(days=30)
    db.query(DeviceMetric).filter(DeviceMetric.at < cutoff).delete()
    return result
