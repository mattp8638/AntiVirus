"""Server and workload protection (AV-21): file integrity monitoring and container runtime posture.

Both run on the Linux and macOS agents as commands. The support matrix is in ``docs/WORKLOAD_PROTECTION.md``.

**File integrity monitoring** (``fim.scan``). The agent hashes the watched paths and returns a manifest:

* the SHA-256 of each file (or the target of a link);
* size, permissions, owner and modification time.

Watched paths come from the tenant setting ``workloadMonitoring.paths``, or the defaults the agent carries:
accounts, sudoers, SSH, cron, PAM, systemd units, ``ld.so.preload`` and root's authorized keys.

The first scan becomes the baseline. The baseline is kept in the cloud, not on the device, so an attacker on the
device cannot quietly accept their own change. Each later scan is compared with it file by file (added, removed,
changed, and which fields), and any change raises an alert. The alert is high severity when it touches a
credential, privilege or persistence file. A person accepts a change by making the latest scan the new baseline.

**Container runtime posture** (``container.inventory``). The agent lists running containers through the Docker or
Podman command-line tools, read-only. It reports the image and these risky settings:

* privileged mode;
* the host's network or PID namespace;
* running as root;
* powerful added capabilities;
* sensitive host paths mounted, such as the container runtime's socket, ``/``, ``/etc`` or ``/proc``.

Privileged containers and containers that mount sensitive host paths raise an alert.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, services
from .models import Alert, Device, FimBaseline, Tenant, WorkloadReport, utcnow

FIM_COMMAND, CONTAINER_COMMAND = "fim.scan", "container.inventory"
SUPPORTED = ("linux", "macos")
CRITICAL_PATHS = ("/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/sudoers.d", "/root/.ssh/authorized_keys", "/etc/ld.so.preload",
                  "/etc/pam.d", "/etc/ssh/sshd_config")
SEVERE_RISKS = ("privileged", "mounts host")
ALERT_FIM, ALERT_CONTAINER = "workload.fim_change", "workload.container_risk"
EVERY = timedelta(hours=24)
FIELDS = ("sha256", "size", "mode", "uid", "gid", "link")


class WorkloadError(Exception):
    pass


def settings(db: Session, tenant_id: str) -> dict:
    tenant = db.get(Tenant, tenant_id)
    return ((tenant.settings or {}) if tenant else {}).get("workloadMonitoring") or {}


def request(db: Session, device: Device, kind: str, actor: str):
    if (device.platform or "").lower() not in SUPPORTED:
        raise WorkloadError("File integrity monitoring and container posture run on Linux and macOS agents")
    if kind == "fim":
        paths = settings(db, device.tenant_id).get("paths") or []
        return services.enqueue_command(db, device, FIM_COMMAND, actor, payload={"paths": paths} if paths else {},
                                        reason="File integrity scan")
    return services.enqueue_command(db, device, CONTAINER_COMMAND, actor, payload={}, reason="Container inventory")


def _manifest(result: dict) -> dict:
    return {f["path"]: {k: f.get(k) for k in (*FIELDS, "mtime")} for f in result.get("files") or [] if isinstance(f, dict) and f.get("path")}


def compare(baseline: dict, current: dict) -> list[dict]:
    changes = []
    for path in sorted(set(baseline) | set(current)):
        a, b = baseline.get(path), current.get(path)
        if a is None:
            changes.append({"path": path, "change": "added"})
        elif b is None:
            changes.append({"path": path, "change": "removed"})
        else:
            fields = [{"field": k, "before": a.get(k), "after": b.get(k)} for k in FIELDS if a.get(k) != b.get(k)]
            if fields:
                changes.append({"path": path, "change": "changed", "fields": fields})
    return changes


def _critical(path: str) -> bool:
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in CRITICAL_PATHS)


def _alert(db, device, rule, key, title, severity, description):
    open_ = db.scalars(select(Alert).where(Alert.tenant_id == device.tenant_id, Alert.rule_id == rule, Alert.status.in_(("new", "triaged")))).all()
    if any((a.details or {}).get("key") == key for a in open_):
        return
    db.add(Alert(tenant_id=device.tenant_id, device_id=device.id, rule_id=rule, title=title[:300], severity=severity, mitre=[], event_ids=[],
                 details={"category": "workload", "source": "Fenrir workload protection", "key": key, "description": description[:2000],
                          "link": f"/devices/{device.id}"}))


def on_command_complete(db: Session, device: Device, command) -> None:
    if command.status != "completed":
        return
    result = command.result or {}
    if command.type == FIM_COMMAND:
        current = _manifest(result)
        baseline = db.scalars(select(FimBaseline).where(FimBaseline.device_id == device.id)).first()
        if baseline is None:
            db.add(FimBaseline(tenant_id=device.tenant_id, device_id=device.id, manifest=current, set_by="first scan"))
            findings = [{"change": "baseline", "files": len(current)}]
        else:
            findings = compare(baseline.manifest or {}, current)
            if findings:
                critical = [c["path"] for c in findings if _critical(c["path"])]
                _alert(db, device, ALERT_FIM, f"fim:{device.id}:{command.id}",
                       f"{device.hostname}: {len(findings)} watched file(s) changed" + (f", including {critical[0]}" if critical else ""),
                       "high" if critical else "medium",
                       "; ".join(f"{c['path']} {c['change']}" for c in findings[:20]) + ". If the change is expected, accept it as the new baseline.")
        db.add(WorkloadReport(tenant_id=device.tenant_id, device_id=device.id, kind="fim",
                              data={"files": len(current), "truncated": result.get("truncated"), "errors": result.get("errors") or [],
                                    "manifest": current}, findings=findings))
        return
    if command.type == CONTAINER_COMMAND:
        containers = [c for c in result.get("containers") or [] if isinstance(c, dict)]
        findings = [{"container": c.get("name"), "image": c.get("image"), "risks": c.get("risks") or []} for c in containers if c.get("risks")]
        for f in findings:
            severe = [r for r in f["risks"] if r.startswith(SEVERE_RISKS)]
            if severe:
                _alert(db, device, ALERT_CONTAINER, f"container:{device.id}:{f['container']}:{','.join(sorted(severe))}",
                       f"{device.hostname}: container {f['container']} is {', '.join(severe)}", "high",
                       f"Image {f['image']}. A container with these settings can take over the host. All risks: {', '.join(f['risks'])}.")
        db.add(WorkloadReport(tenant_id=device.tenant_id, device_id=device.id, kind="containers",
                              data={"runtime": result.get("runtime"), "containers": containers, "error": result.get("error")}, findings=findings))


def accept_baseline(db: Session, device: Device, actor: str) -> FimBaseline:
    last = db.scalars(select(WorkloadReport).where(WorkloadReport.device_id == device.id, WorkloadReport.kind == "fim")
                      .order_by(WorkloadReport.created_at.desc())).first()
    if last is None:
        raise WorkloadError("No file integrity scan yet")
    baseline = db.scalars(select(FimBaseline).where(FimBaseline.device_id == device.id)).first()
    if baseline is None:
        baseline = FimBaseline(tenant_id=device.tenant_id, device_id=device.id)
        db.add(baseline)
    baseline.manifest, baseline.set_by, baseline.set_at = last.data.get("manifest") or {}, actor, utcnow()
    for a in db.scalars(select(Alert).where(Alert.device_id == device.id, Alert.rule_id == ALERT_FIM, Alert.status.in_(("new", "triaged")))).all():
        a.status, a.updated_at = "resolved", utcnow()
    audit.record(db, actor, "workload.fim_baseline_accepted", device.id, device.tenant_id, files=len(baseline.manifest), report=last.id)
    return baseline


def tick(db: Session) -> int:
    """Daily scans for devices of tenants that turned workload monitoring on."""
    done = 0
    for tenant in db.scalars(select(Tenant)).all():
        conf = ((tenant.settings or {}).get("workloadMonitoring") or {})
        if not (conf.get("fim") or conf.get("containers")):
            continue
        for device in db.scalars(select(Device).where(Device.tenant_id == tenant.id, Device.platform.in_(SUPPORTED))).all():
            for kind, on in (("fim", conf.get("fim")), ("containers", conf.get("containers"))):
                if not on:
                    continue
                last = db.scalars(select(WorkloadReport).where(WorkloadReport.device_id == device.id, WorkloadReport.kind == kind)
                                  .order_by(WorkloadReport.created_at.desc())).first()
                if last is None or utcnow() - last.created_at >= EVERY:
                    request(db, device, kind, "system:workload")
                    done += 1
    db.commit()
    return done
