"""RMM API: scripts, jobs, scheduled tasks, monitoring, patch management and software deployment."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import approvals, audit, rmm, services
from ..commands import BY_TYPE, INTERACTIVE_ONLY
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import (Alert, Command, ConditionState, Device, DeviceMetric, DevicePatch, Job, MonitorCondition, PatchApproval,
                      PatchPolicy, RemoteSession, ScheduledTask, Script, SoftwarePackage, Tenant, utcnow)
from ..serialize import apply_fields, to_dict

router = APIRouter(prefix="/api/console/rmm", tags=["RMM"])


def _visible(principal: Principal, obj) -> bool:
    return obj is not None and (obj.tenant_id is None or obj.tenant_id in principal.tenant_ids)


def _editable(principal: Principal, obj) -> None:
    if obj is None or (obj.tenant_id is not None and obj.tenant_id not in principal.tenant_ids):
        raise HTTPException(404, "Not found")
    if obj.tenant_id is None and not principal.can("platform"):
        raise HTTPException(403, "Built-in items can only be changed by a platform admin. Duplicate it instead.")


def _targets(principal: Principal, db: Session, targets: dict) -> list[Device]:
    if not isinstance(targets, dict) or not any(targets.get(k) for k in ("deviceIds", "groupIds", "tenantIds")):
        raise HTTPException(400, "choose at least one device, group or customer")
    devices = rmm.resolve_targets(db, principal.tenant_ids, targets)
    if not devices:
        raise HTTPException(400, "no approved devices match those targets")
    return devices


def _job_tenant(principal: Principal, devices: list[Device]) -> str:
    tenants = {d.tenant_id for d in devices}
    return tenants.pop() if len(tenants) == 1 else principal.user.tenant_id


# --------------------------------------------------------------------------- overview


@router.get("/overview")
def overview(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    scope = scoped_tenant(principal, tenant_id)
    now = utcnow()
    devices = db.execute(select(Device).where(Device.tenant_id.in_(scope), Device.approved.is_(True))).scalars().all()
    online = [d for d in devices if d.last_seen_at and now - d.last_seen_at < timedelta(minutes=5)]
    triggered = db.execute(select(func.count()).where(ConditionState.tenant_id.in_(scope), ConditionState.triggered.is_(True))).scalar() or 0
    jobs_running = db.execute(select(func.count()).where(Job.tenant_id.in_(scope), Job.status == "running")).scalar() or 0
    active_sessions = db.execute(select(func.count()).where(RemoteSession.tenant_id.in_(scope),
                                                            RemoteSession.status.in_(("waiting", "connected")))).scalar() or 0
    compliance = rmm.patch_compliance(db, scope)
    compliance.pop("byDevice")
    low_disk = [d.hostname for d in devices for disk in (d.metrics or {}).get("disks", []) if disk.get("freePercent", 100) < 10]
    return {"devices": len(devices), "online": len(online), "offline": len(devices) - len(online), "monitorsTriggered": triggered,
            "jobsRunning": jobs_running, "remoteSessions": active_sessions, "patching": compliance, "lowDisk": sorted(set(low_disk))[:20],
            "rebootPending": sorted(d.hostname for d in devices if (d.metrics or {}).get("rebootPending"))[:50],
            "platforms": {p: len([d for d in devices if d.platform == p]) for p in {d.platform for d in devices}}}


# --------------------------------------------------------------------------- scripts

SCRIPT_FIELDS = {"name", "description", "category", "language", "platforms", "body", "parameters", "run_as", "timeout_seconds"}


def _check_script(body: dict) -> None:
    language = body.get("language")
    if language is not None and language not in rmm.LANGUAGES:
        raise HTTPException(400, f"language must be one of {sorted(rmm.LANGUAGES)}")
    for spec in body.get("parameters") or []:
        if not rmm.PARAM_NAME.match(str(spec.get("name") or "")):
            raise HTTPException(400, f"parameter names must be letters, digits and _ (got '{spec.get('name')}')")
    if "timeoutSeconds" in body and not 10 <= int(body["timeoutSeconds"]) <= 86400:
        raise HTTPException(400, "timeout must be between 10 seconds and 24 hours")


@router.get("/scripts")
def list_scripts(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(Script).where(or_(Script.tenant_id.is_(None), Script.tenant_id.in_(principal.tenant_ids)))
                      .order_by(Script.category, Script.name)).scalars().all()
    return [to_dict(r) for r in rows]


@router.get("/scripts/{script_id}")
def get_script(script_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    script = db.get(Script, script_id)
    if not _visible(principal, script):
        raise HTTPException(404, "Not found")
    return to_dict(script)


@router.post("/scripts")
def create_script(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    _check_script(body)
    if not body.get("name") or not body.get("body"):
        raise HTTPException(400, "name and body are required")
    tenant_id = body.get("tenantId") or principal.user.tenant_id
    principal.check_tenant(tenant_id)
    script = Script(tenant_id=tenant_id, updated_by=principal.actor, language="powershell", run_as="system", timeout_seconds=600,
                    parameters=[], category="General", description="", version=1)
    apply_fields(script, body, SCRIPT_FIELDS)
    script.platforms = script.platforms or list(rmm.LANGUAGES.get(script.language, ("windows",)))
    db.add(script)
    audit.record(db, principal.actor, "rmm.script.created", script.name, tenant_id)
    db.commit()
    return to_dict(script)


@router.patch("/scripts/{script_id}")
def update_script(script_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    script = db.get(Script, script_id)
    _editable(principal, script)
    _check_script(body)
    changed = apply_fields(script, body, SCRIPT_FIELDS)
    if "body" in changed or "parameters" in changed:
        script.version += 1
    script.updated_by, script.updated_at = principal.actor, utcnow()
    audit.record(db, principal.actor, "rmm.script.updated", script.name, script.tenant_id, fields=changed, version=script.version)
    db.commit()
    return to_dict(script)


@router.delete("/scripts/{script_id}")
def delete_script(script_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    script = db.get(Script, script_id)
    _editable(principal, script)
    db.delete(script)
    audit.record(db, principal.actor, "rmm.script.deleted", script.name, script.tenant_id)
    db.commit()
    return {"ok": True}


@router.post("/scripts/{script_id}/run")
def run_script(script_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    principal.require("scripts")
    script = db.get(Script, script_id)
    if not _visible(principal, script):
        raise HTTPException(404, "Not found")
    devices = _targets(principal, db, body.get("targets") or {})
    blocked = []
    for device in devices:
        resolution, _ = services.effective_policy(db, device)
        if not resolution["settings"]["response"].get("scriptExecution", True):
            blocked.append(device.hostname)
    if blocked and len(blocked) == len(devices):
        raise HTTPException(403, "Script execution is turned off by policy on the selected devices")
    allowed = [d for d in devices if d.hostname not in blocked]
    approvals.gate(db, principal, "script.run", f"Run {script.name} on {len(allowed)} devices", {"scriptId": script_id, **body}, allowed,
                   route=f"rmm/scripts/{script_id}/run")
    try:
        job = rmm.run_script(db, script=script, devices=allowed, actor=principal.actor, tenant_id=_job_tenant(principal, allowed),
                             parameters=body.get("parameters") or {}, targets=body.get("targets"), ticket_id=body.get("ticketId"))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if blocked:
        job.payload = {**job.payload, "skipped": {**job.payload.get("skipped", {}), **{h: "script execution off in policy" for h in blocked}}}
    db.commit()
    return _job_view(db, job)


# --------------------------------------------------------------------------- jobs


def _job_view(db: Session, job: Job, detail: bool = False) -> dict:
    view = {**to_dict(job), "summary": rmm.job_summary(db, job)}
    view["payload"] = {k: v for k, v in (job.payload or {}).items() if k not in {"body"}}
    if detail:
        ids = list((job.command_ids or {}).values())
        commands = {c.id: c for c in db.execute(select(Command).where(Command.id.in_(ids))).scalars()} if ids else {}
        devices = {d.id: d for d in db.execute(select(Device).where(Device.id.in_(list((job.command_ids or {}).keys())))).scalars()}
        results = []
        for device_id, command_id in (job.command_ids or {}).items():
            command = commands.get(command_id)
            device = devices.get(device_id)
            result = (command.result if command else {}) or {}
            results.append({"deviceId": device_id, "hostname": device.hostname if device else device_id,
                            "platform": device.platform if device else "", "commandId": command_id,
                            "status": command.status if command else "unknown",
                            "exitCode": result.get("exitCode"), "stdout": str(result.get("stdout", ""))[:rmm.MAX_OUTPUT],
                            "stderr": str(result.get("stderr", ""))[:rmm.MAX_OUTPUT], "durationMs": result.get("durationMs"),
                            "error": result.get("error"), "result": {k: v for k, v in result.items() if k not in {"stdout", "stderr"}},
                            "completedAt": to_dict(command)["completedAt"] if command else None})
        view["results"] = sorted(results, key=lambda r: r["hostname"].lower())
        script = db.get(Script, job.script_id) if job.script_id else None
        view["script"] = {"id": script.id, "name": script.name, "language": script.language} if script else None
    return view


@router.get("/jobs")
def list_jobs(tenant_id: str | None = None, device_id: str | None = Query(default=None, alias="deviceId"), limit: int = 200,
              principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    scope = scoped_tenant(principal, tenant_id)
    # Creator identity never overrides current tenant authorisation: access
    # may be revoked or the technician reassigned to another MSP.
    rows = db.execute(select(Job).where(Job.tenant_id.in_(scope))
                      .order_by(Job.created_at.desc()).limit(min(limit, 1000))).scalars().all()
    if device_id:
        rows = [r for r in rows if device_id in (r.command_ids or {})]
    return [_job_view(db, r) for r in rows]


@router.get("/jobs/{job_id}")
def get_job(job_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    job = db.get(Job, job_id)
    if job is None or job.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    return _job_view(db, job, detail=True)


@router.post("/jobs")
def create_command_job(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Bulk action: queue one command (restart, patch scan, isolate...) on many devices."""
    command_type = str(body.get("commandType") or "")
    spec = BY_TYPE.get(command_type)
    if spec is None or command_type in {"remote.session.start", "remote.session.end", "script.run"} | INTERACTIVE_ONLY:
        raise HTTPException(400, "unknown or unsupported command for a bulk job")
    principal.require("configure" if spec.permission == "configure" else "respond")
    if spec.destructive:
        principal.require("destructive")
    devices = _targets(principal, db, body.get("targets") or {})
    approvals.gate(db, principal, "command.job", f"{spec.label} on {len(devices)} devices", body, devices, destructive=spec.destructive, route="rmm/jobs")
    job = rmm.create_job(db, tenant_id=_job_tenant(principal, devices), actor=principal.actor,
                         name=str(body.get("name") or spec.label), devices=devices, command_type=command_type,
                         payload=body.get("payload") or {}, targets=body.get("targets"), target_path=str(body.get("targetPath") or ""),
                         record_id=str(body.get("recordId") or ""))
    db.commit()
    return _job_view(db, job)


@router.post("/jobs/{job_id}/retry")
def retry_job(job_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Run the job again on the devices where it failed (same script, parameters and payload)."""
    job = db.get(Job, job_id)
    if job is None or job.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    principal.require("configure" if job.command_type == "script.run" else "respond")
    retried = rmm.retry_failed(db, job, principal.actor)
    db.commit()
    return {**_job_view(db, job), "retried": retried}


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    job = db.get(Job, job_id)
    if job is None or job.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    cancelled = 0
    for command in db.execute(select(Command).where(Command.id.in_(list((job.command_ids or {}).values())),
                                                    Command.status == "pending")).scalars():
        command.status, command.updated_at = "cancelled", utcnow()
        cancelled += 1
    rmm.refresh_job(db, job.id)
    # A command already dispatched to an endpoint cannot be recalled safely.
    # Leave the job running until the real agent result is received rather
    # than falsely telling technicians that executing work was cancelled.
    in_flight = db.execute(select(Command).where(
        Command.id.in_(list((job.command_ids or {}).values())),
        Command.status == "dispatched")).scalars().all()
    audit.record(db, principal.actor, "rmm.job.cancel.requested", job.name, job.tenant_id,
                 cancelledPending=cancelled, alreadyDispatched=len(in_flight))
    db.commit()
    return {**_job_view(db, job), "cancelledPending": cancelled,
            "alreadyDispatched": len(in_flight), "cancellationComplete": not bool(in_flight)}


# --------------------------------------------------------------------------- scheduled tasks

TASK_FIELDS = {"name", "enabled", "schedule", "targets", "actions", "run_offline_on_reconnect"}


@router.get("/tasks")
def list_tasks(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return [to_dict(t) for t in db.execute(select(ScheduledTask).where(ScheduledTask.tenant_id.in_(principal.tenant_ids))
                                           .order_by(ScheduledTask.name)).scalars()]


def _validate_task(task: ScheduledTask) -> None:
    if task.schedule.get("type") not in {"once", "interval", "daily", "weekly", "monthly"}:
        raise HTTPException(400, "schedule type must be once, interval, daily, weekly or monthly")
    if not task.actions:
        raise HTTPException(400, "add at least one action")
    for action in task.actions:
        if action.get("type") not in {"script", "command", "software"}:
            raise HTTPException(400, "actions are script, command or software")
        if action.get("type") == "command" and (action.get("command") not in BY_TYPE or action.get("command") in INTERACTIVE_ONLY):
            raise HTTPException(400, f"unknown or unsupported command {action.get('command')}")


@router.post("/tasks")
def create_task(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.get("tenantId") or principal.user.tenant_id
    principal.check_tenant(tenant_id)
    task = ScheduledTask(tenant_id=tenant_id, name=str(body.get("name") or "Scheduled task"), created_by=principal.actor)
    apply_fields(task, body, TASK_FIELDS)
    task.schedule, task.targets, task.actions = task.schedule or {}, task.targets or {}, task.actions or []
    _validate_task(task)
    task.next_run_at = rmm.next_run(task.schedule, utcnow())
    db.add(task)
    audit.record(db, principal.actor, "rmm.task.created", task.name, tenant_id)
    db.commit()
    return to_dict(task)


@router.patch("/tasks/{task_id}")
def update_task(task_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    task = db.get(ScheduledTask, task_id)
    if task is None or task.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    changed = apply_fields(task, body, TASK_FIELDS)
    _validate_task(task)
    if "schedule" in changed or ("enabled" in changed and task.enabled):
        task.next_run_at = rmm.next_run(task.schedule, utcnow())
    audit.record(db, principal.actor, "rmm.task.updated", task.name, task.tenant_id, fields=changed)
    db.commit()
    return to_dict(task)


@router.delete("/tasks/{task_id}")
def delete_task(task_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    task = db.get(ScheduledTask, task_id)
    if task is None or task.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    db.delete(task)
    audit.record(db, principal.actor, "rmm.task.deleted", task.name, task.tenant_id)
    db.commit()
    return {"ok": True}


@router.post("/tasks/{task_id}/run")
def run_task_now(task_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    principal.require("scripts")
    task = db.get(ScheduledTask, task_id)
    if task is None or task.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    jobs = rmm.run_scheduled_task(db, task, actor=principal.actor)
    db.commit()
    return [_job_view(db, j) for j in jobs]


# --------------------------------------------------------------------------- monitoring

CONDITION_FIELDS = {"name", "enabled", "metric", "operator", "threshold", "target", "duration_minutes", "severity", "scope", "actions",
                    "auto_resolve"}


@router.get("/conditions")
def list_conditions(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(MonitorCondition).where(or_(MonitorCondition.tenant_id.is_(None),
                                                         MonitorCondition.tenant_id.in_(principal.tenant_ids)))).scalars().all()
    triggered = dict(db.execute(select(ConditionState.condition_id, func.count()).where(ConditionState.triggered.is_(True),
                                                                                         ConditionState.tenant_id.in_(principal.tenant_ids))
                                .group_by(ConditionState.condition_id)).all())
    return {"metrics": rmm.METRICS, "conditions": [{**to_dict(r), "triggered": triggered.get(r.id, 0)} for r in rows]}


def _check_condition(cond: MonitorCondition, db: Session, principal: Principal) -> None:
    if cond.metric not in rmm.METRICS:
        raise HTTPException(400, f"metric must be one of {sorted(rmm.METRICS)}")
    if cond.operator not in rmm.OPS:
        raise HTTPException(400, "operator must be one of > < >= <= == !=")
    if cond.severity not in {"low", "medium", "high", "critical", "info"}:
        raise HTTPException(400, "invalid severity")
    if not isinstance(cond.actions, list) or len(cond.actions) > 12:
        raise HTTPException(400, "monitor actions must be a list of at most 12 actions")
    for action in cond.actions:
        if not isinstance(action, dict):
            raise HTTPException(400, "monitor action must be an object")
        kind = action.get("type")
        if kind not in {"ticket", "script", "command", "webhook", "email"}:
            raise HTTPException(400, f"unsupported monitor action: {kind}")
        if kind == "script":
            script = db.get(Script, action.get("scriptId")) if action.get("scriptId") else None
            if script is None or not _visible(principal, script):
                raise HTTPException(400, "monitor self-heal script does not exist or is not accessible")
            if cond.tenant_id is not None and script.tenant_id not in {
                None, cond.tenant_id, services.msp_tenant_id(db, cond.tenant_id),
            }:
                raise HTTPException(400, "monitor script belongs to an unrelated customer")
            if cond.tenant_id is None and script.tenant_id is not None:
                raise HTTPException(400, "global monitors may only use global scripts")
            try:
                rmm.validate_parameters(script, action.get("parameters") or {})
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
        if kind == "command":
            spec = BY_TYPE.get(action.get("command"))
            if spec is None or action.get("command") in {"script.run", "remote.session.start", "remote.session.end"} | INTERACTIVE_ONLY:
                raise HTTPException(400, "invalid command in monitor action")
            if "targetPath" in spec.needs and not (action.get("targetPath") or cond.target):
                raise HTTPException(400, "monitor command needs a target path")
            if "recordId" in spec.needs:
                raise HTTPException(400, "monitor command requires an explicit record ID and cannot run automatically")
        if kind == "email" and not action.get("to"):
            raise HTTPException(400, "monitor email action needs a recipient")


@router.post("/conditions")
def create_condition(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.get("tenantId", principal.user.tenant_id)
    principal.check_tenant(tenant_id)
    cond = MonitorCondition(tenant_id=tenant_id, name=str(body.get("name") or "Monitor"), metric=str(body.get("metric") or "cpu"),
                            target="", scope={}, actions=[], severity="medium", operator=">", threshold=0, duration_minutes=5,
                            enabled=True, auto_resolve=True)
    apply_fields(cond, body, CONDITION_FIELDS)
    _check_condition(cond, db, principal)
    db.add(cond)
    audit.record(db, principal.actor, "rmm.condition.created", cond.name, tenant_id)
    db.commit()
    return to_dict(cond)


@router.patch("/conditions/{condition_id}")
def update_condition(condition_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                     db: Session = Depends(get_db)):
    principal.require("configure")
    cond = db.get(MonitorCondition, condition_id)
    _editable(principal, cond)
    changed = apply_fields(cond, body, CONDITION_FIELDS)
    _check_condition(cond, db, principal)
    audit.record(db, principal.actor, "rmm.condition.updated", cond.name, cond.tenant_id, fields=changed)
    db.commit()
    return to_dict(cond)


@router.delete("/conditions/{condition_id}")
def delete_condition(condition_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    cond = db.get(MonitorCondition, condition_id)
    _editable(principal, cond)
    db.query(ConditionState).filter(ConditionState.condition_id == cond.id).delete()
    db.delete(cond)
    audit.record(db, principal.actor, "rmm.condition.deleted", cond.name, cond.tenant_id)
    db.commit()
    return {"ok": True}


@router.get("/monitoring")
def active_monitors(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    scope = scoped_tenant(principal, tenant_id)
    states = db.execute(select(ConditionState).where(ConditionState.tenant_id.in_(scope), ConditionState.triggered.is_(True))
                        .order_by(ConditionState.triggered_at.desc())).scalars().all()
    conditions = {c.id: c for c in db.execute(select(MonitorCondition)).scalars()}
    devices = {d.id: d for d in db.execute(select(Device).where(Device.id.in_({s.device_id for s in states}))).scalars()}
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    out = []
    for state in states:
        cond, device = conditions.get(state.condition_id), devices.get(state.device_id)
        if cond is None or device is None:
            continue
        out.append({"id": state.id, "condition": cond.name, "conditionId": cond.id, "metric": cond.metric, "severity": cond.severity,
                    "deviceId": device.id, "hostname": device.hostname, "account": names.get(device.tenant_id, ""),
                    "value": state.last_value, "message": state.message, "since": to_dict(state)["triggeredAt"],
                    "alertId": state.alert_id, "ticketId": state.ticket_id})
    return out


@router.get("/devices/{device_id}/metrics")
def device_metrics(device_id: str, hours: int = Query(default=24, ge=1, le=720), principal: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)):
    device = db.get(Device, device_id)
    if device is None or device.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    since = utcnow() - timedelta(hours=hours)
    rows = db.execute(select(DeviceMetric).where(DeviceMetric.device_id == device_id, DeviceMetric.at >= since)
                      .order_by(DeviceMetric.at)).scalars().all()
    # Average into at most ~300 buckets so a week of one-minute samples stays a light chart; keep the peaks too.
    size = max(1, -(-len(rows) // 300))
    series = []
    for start in range(0, len(rows), size):
        bucket = rows[start:start + size]
        series.append({"at": to_dict(bucket[-1])["at"],
                       "cpu": round(sum(r.cpu for r in bucket) / len(bucket), 1), "cpuMax": round(max(r.cpu for r in bucket), 1),
                       "memory": round(sum(r.memory for r in bucket) / len(bucket), 1), "memoryMax": round(max(r.memory for r in bucket), 1),
                       "diskFree": round(min(r.disk_free_percent for r in bucket), 1)})
    states = db.execute(select(ConditionState).where(ConditionState.device_id == device_id)).scalars().all()
    conditions = {c.id: c.name for c in db.execute(select(MonitorCondition)).scalars()}
    return {"current": device.metrics or {}, "hours": hours,
            "series": series,
            "monitors": [{"condition": conditions.get(s.condition_id, s.condition_id), "triggered": s.triggered, "value": s.last_value,
                          "message": s.message} for s in states]}


# --------------------------------------------------------------------------- patching


@router.get("/patches")
def patch_catalogue(tenant_id: str | None = None, classification: str | None = None, status: str | None = None,
                    principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Every patch seen across the fleet, grouped by patch, with device counts and approval state."""
    scope = scoped_tenant(principal, tenant_id)
    query = select(DevicePatch).where(DevicePatch.tenant_id.in_(scope))
    if classification:
        query = query.where(DevicePatch.classification == classification)
    rows = db.execute(query).scalars().all()
    decisions = {(a.tenant_id, a.patch_key): a for a in db.execute(select(PatchApproval).where(PatchApproval.tenant_id.in_(scope))).scalars()}
    policies = db.execute(select(PatchPolicy).where(PatchPolicy.tenant_id.in_(scope), PatchPolicy.enabled.is_(True))).scalars().all()
    devices = {d.id: d for d in db.execute(select(Device).where(Device.tenant_id.in_(scope))).scalars()}
    grouped: dict[str, dict] = {}
    for row in rows:
        item = grouped.setdefault(row.patch_key, {"patchKey": row.patch_key, "title": row.title, "classification": row.classification,
                                                  "severity": row.severity, "source": row.source, "product": row.product,
                                                  "availableVersion": row.available_version, "missing": 0, "installed": 0, "failed": 0,
                                                  "installing": 0, "rebootRequired": row.reboot_required, "approval": {},
                                                  "releasedAt": to_dict(row)["releasedAt"]})
        item[row.status] = item.get(row.status, 0) + 1
        device = devices.get(row.device_id)
        if device is not None:
            policy = rmm.policy_for_device(db, device, [p for p in policies if p.tenant_id == device.tenant_id])
            decision = decisions.get((device.tenant_id, row.patch_key))
            state = rmm.approval_state(policy, row, {row.patch_key: decision.decision} if decision else {})
            item["approval"][state] = item["approval"].get(state, 0) + 1
    out = list(grouped.values())
    for item in out:
        approvals = item["approval"]
        item["approvalState"] = max(approvals, key=approvals.get) if approvals else "pending"
    if status == "missing":
        out = [i for i in out if i["missing"] or i["failed"]]
    order = {c: n for n, c in enumerate(rmm.CLASSIFICATIONS)}
    return sorted(out, key=lambda i: (order.get(i["classification"], 99), -(i["missing"] + i["failed"]), i["title"]))


@router.get("/patches/compliance")
def patches_compliance(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    scope = scoped_tenant(principal, tenant_id)
    result = rmm.patch_compliance(db, scope)
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    devices = db.execute(select(Device).where(Device.tenant_id.in_(scope), Device.approved.is_(True))).scalars().all()
    result["devices_detail"] = [{"id": d.id, "hostname": d.hostname, "account": names.get(d.tenant_id, ""), "platform": d.platform,
                                 "missing": result["byDevice"].get(d.id, {}), "lastScan": (d.metrics or {}).get("patchScanAt"),
                                 "rebootPending": bool((d.metrics or {}).get("rebootPending"))} for d in devices]
    result.pop("byDevice")
    return result


@router.post("/patches/approve")
def approve_patches(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    principal.require("approve")
    decision = str(body.get("decision") or "approved")
    if decision not in {"approved", "rejected", "reset"}:
        raise HTTPException(400, "decision must be approved, rejected or reset")
    keys = [str(k) for k in body.get("patchKeys") or []]
    tenants = [body["tenantId"]] if body.get("tenantId") else sorted(
        {t for (t,) in db.execute(select(DevicePatch.tenant_id).where(DevicePatch.patch_key.in_(keys),
                                                                      DevicePatch.tenant_id.in_(principal.tenant_ids))).all()})
    for tenant_id in tenants:
        principal.check_tenant(tenant_id)
        for key in keys:
            existing = db.execute(select(PatchApproval).where(PatchApproval.tenant_id == tenant_id, PatchApproval.patch_key == key)).scalar_one_or_none()
            if decision == "reset":
                if existing:
                    db.delete(existing)
                continue
            if existing is None:
                existing = PatchApproval(tenant_id=tenant_id, patch_key=key, decision=decision, decided_by=principal.actor)
                db.add(existing)
            existing.decision, existing.decided_by, existing.decided_at = decision, principal.actor, utcnow()
            existing.note = str(body.get("note") or "")[:300]
    audit.record(db, principal.actor, f"rmm.patch.{decision}", ", ".join(keys)[:200], principal.user.tenant_id, tenants=len(tenants))
    db.commit()
    return {"patches": len(keys), "tenants": len(tenants), "decision": decision}


@router.post("/patches/scan")
def scan_patches(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    devices = _targets(principal, db, body.get("targets") or {})
    job = rmm.create_job(db, tenant_id=_job_tenant(principal, devices), actor=principal.actor, name="Patch scan", devices=devices,
                         command_type="patch.scan", kind="patch", targets=body.get("targets"))
    db.commit()
    return _job_view(db, job)


@router.post("/patches/install")
def install_patches_now(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Install approved (or the listed) patches now, outside the maintenance window."""
    principal.require("configure")
    principal.require("scripts")
    devices = _targets(principal, db, body.get("targets") or {})
    only = set(body.get("patchKeys") or [])
    reboot = {**rmm.DEFAULT_REBOOT, **(body.get("reboot") or {})}
    queued, skipped = {}, {}
    job = Job(tenant_id=_job_tenant(principal, devices), name="Install patches now", kind="patch", command_type="patch.install",
              targets=body.get("targets") or {}, created_by=principal.actor, payload={"reboot": reboot})
    db.add(job)
    db.flush()
    for device in devices:
        policy = rmm.policy_for_device(db, device)
        if only:
            patches = db.execute(select(DevicePatch).where(DevicePatch.device_id == device.id, DevicePatch.patch_key.in_(only),
                                                           DevicePatch.status.in_(("missing", "failed")))).scalars().all()
        else:
            patches = rmm.installable_patches(db, device, policy)
        if not patches:
            skipped[device.id] = "nothing approved to install"
            continue
        payload = {"patchIds": [p.patch_key for p in patches], "reboot": reboot, "jobId": job.id,
                   "patches": [{"id": p.patch_key, "source": p.source, "title": p.title} for p in patches]}
        try:
            command = services.enqueue_command(db, device, "patch.install", principal.actor, payload=payload, reason="Install patches now")
        except services.CommandError as exc:
            skipped[device.id] = str(exc)
            continue
        db.flush()
        queued[device.id] = command.id
        for patch in patches:
            patch.status = "installing"
    job.command_ids = queued
    job.payload = {**job.payload, "skipped": skipped}
    if not queued:
        job.status, job.finished_at = "failed", utcnow()
    audit.record(db, principal.actor, "rmm.patch.install_now", f"{len(queued)} devices", job.tenant_id)
    db.commit()
    return _job_view(db, job)


@router.get("/devices/{device_id}/patches")
def device_patches(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    device = db.get(Device, device_id)
    if device is None or device.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    policy = rmm.policy_for_device(db, device)
    decisions = dict(db.execute(select(PatchApproval.patch_key, PatchApproval.decision).where(PatchApproval.tenant_id == device.tenant_id)).all())
    rows = db.execute(select(DevicePatch).where(DevicePatch.device_id == device_id).order_by(DevicePatch.status, DevicePatch.title)).scalars()
    ring = rmm.ring_delay(policy, device) if policy else ("Default", 0)
    return {"policy": to_dict(policy) if policy else None, "ring": {"name": ring[0], "delayDays": ring[1]},
            "lastScan": (device.metrics or {}).get("patchScanAt"), "rebootPending": bool((device.metrics or {}).get("rebootPending")),
            "patches": [{**to_dict(r), "approval": rmm.approval_state(policy, r, decisions)} for r in rows]}


POLICY_FIELDS = {"name", "group_id", "enabled", "approvals", "delay_days", "rings", "window", "reboot", "scan_interval_hours"}


@router.get("/patch-policies")
def list_patch_policies(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    return {"defaults": {"approvals": rmm.DEFAULT_APPROVALS, "window": rmm.DEFAULT_WINDOW, "reboot": rmm.DEFAULT_REBOOT},
            "classifications": list(rmm.CLASSIFICATIONS),
            "policies": [{**to_dict(p), "account": names.get(p.tenant_id, "")}
                         for p in db.execute(select(PatchPolicy).where(PatchPolicy.tenant_id.in_(principal.tenant_ids))).scalars()]}


def _check_patch_policy(policy: PatchPolicy) -> None:
    for classification, rule in (policy.approvals or {}).items():
        if rule not in {"auto", "manual", "reject"}:
            raise HTTPException(400, f"approval for {classification} must be auto, manual or reject")
    window = policy.window or {}
    if window:
        try:
            hour, minute = (int(x) for x in str(window.get("start", "02:00")).split(":")[:2])
            assert 0 <= hour < 24 and 0 <= minute < 60
        except (ValueError, AssertionError) as exc:
            raise HTTPException(400, "window start must be HH:MM") from exc
    if (policy.reboot or {}).get("mode", "if_required") not in {"if_required", "never", "always"}:
        raise HTTPException(400, "reboot mode must be if_required, never or always")


@router.post("/patch-policies")
def create_patch_policy(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.get("tenantId") or principal.user.tenant_id
    principal.check_tenant(tenant_id)
    policy = PatchPolicy(tenant_id=tenant_id, name=str(body.get("name") or "Patch policy"), approvals=dict(rmm.DEFAULT_APPROVALS),
                         window=dict(rmm.DEFAULT_WINDOW), reboot=dict(rmm.DEFAULT_REBOOT),
                         rings=[{"name": "Pilot", "groupIds": [], "delayDays": 0}])
    apply_fields(policy, body, POLICY_FIELDS)
    _check_patch_policy(policy)
    db.add(policy)
    audit.record(db, principal.actor, "rmm.patch_policy.created", policy.name, tenant_id)
    db.commit()
    return to_dict(policy)


@router.patch("/patch-policies/{policy_id}")
def update_patch_policy(policy_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                        db: Session = Depends(get_db)):
    principal.require("configure")
    policy = db.get(PatchPolicy, policy_id)
    if policy is None or policy.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    changed = apply_fields(policy, body, POLICY_FIELDS)
    _check_patch_policy(policy)
    audit.record(db, principal.actor, "rmm.patch_policy.updated", policy.name, policy.tenant_id, fields=changed)
    db.commit()
    return to_dict(policy)


@router.delete("/patch-policies/{policy_id}")
def delete_patch_policy(policy_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    policy = db.get(PatchPolicy, policy_id)
    if policy is None or policy.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    db.delete(policy)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- software

PACKAGE_FIELDS = {"name", "publisher", "platform", "installer", "identifier", "sha256", "install_args", "uninstall_args", "version",
                  "keep_updated"}
INSTALLERS = {"winget", "choco", "msi", "exe", "apt", "dnf", "snap", "brew", "pkg", "script"}


@router.get("/software")
def list_packages(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(SoftwarePackage).where(or_(SoftwarePackage.tenant_id.is_(None),
                                                        SoftwarePackage.tenant_id.in_(principal.tenant_ids)))
                      .order_by(SoftwarePackage.platform, SoftwarePackage.name)).scalars()
    return [to_dict(r) for r in rows]


def _check_package(package: SoftwarePackage) -> None:
    if package.installer not in INSTALLERS:
        raise HTTPException(400, f"installer must be one of {sorted(INSTALLERS)}")
    if package.installer in {"msi", "exe", "pkg"}:
        if not package.identifier.startswith("https://"):
            raise HTTPException(400, "MSI/EXE/PKG packages need an https:// download URL")
        if len(package.sha256 or "") != 64:
            raise HTTPException(400, "MSI/EXE/PKG packages need the installer's SHA-256 so agents can verify the download")
    if not package.identifier:
        raise HTTPException(400, "identifier is required (package id or download URL)")


@router.post("/software")
def create_package(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    package = SoftwarePackage(tenant_id=body.get("tenantId") or principal.user.tenant_id, name=str(body.get("name") or ""),
                              installer="winget", platform="windows", identifier="", sha256="", install_args="", uninstall_args="",
                              version="latest", keep_updated=True)
    principal.check_tenant(package.tenant_id)
    apply_fields(package, body, PACKAGE_FIELDS)
    package.sha256 = (package.sha256 or "").lower()
    _check_package(package)
    db.add(package)
    audit.record(db, principal.actor, "rmm.software.created", package.name, package.tenant_id)
    db.commit()
    return to_dict(package)


@router.patch("/software/{package_id}")
def update_package(package_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    package = db.get(SoftwarePackage, package_id)
    _editable(principal, package)
    apply_fields(package, body, PACKAGE_FIELDS)
    package.sha256 = (package.sha256 or "").lower()
    _check_package(package)
    db.commit()
    return to_dict(package)


@router.delete("/software/{package_id}")
def delete_package(package_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    package = db.get(SoftwarePackage, package_id)
    _editable(principal, package)
    db.delete(package)
    db.commit()
    return {"ok": True}


@router.post("/software/{package_id}/deploy")
def deploy_package(package_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    principal.require("scripts")
    package = db.get(SoftwarePackage, package_id)
    if not _visible(principal, package):
        raise HTTPException(404, "Not found")
    action = str(body.get("action") or "install")
    if action not in {"install", "uninstall"}:
        raise HTTPException(400, "action must be install or uninstall")
    devices = _targets(principal, db, body.get("targets") or {})
    job = rmm.deploy_software(db, package, devices, principal.actor, _job_tenant(principal, devices), action)
    db.commit()
    return _job_view(db, job)


# --------------------------------------------------------------------------- monitoring alerts summary


@router.get("/alerts")
def monitoring_alerts(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(Alert).where(Alert.tenant_id.in_(principal.tenant_ids), Alert.rule_id.like("monitor:%"))
                      .order_by(Alert.created_at.desc()).limit(500)).scalars()
    return [to_dict(r) for r in rows]
