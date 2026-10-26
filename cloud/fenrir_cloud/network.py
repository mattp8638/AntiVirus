"""Bounded TCP service checks from the cloud server's network."""
import ipaddress
import socket
import time
from datetime import timedelta
from sqlalchemy import select, update
from . import events
from .models import Alert, Command, Device, NetworkMonitor, utcnow

PROBE_COMMAND = "network.probe"
PROBE_TIMEOUT = timedelta(minutes=10)  # a probe device that has not answered by then is reported as not reporting

def validate_address(address):
    ip = ipaddress.ip_address(address)
    if (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved
            or (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None)):
        raise ValueError("Use a reachable service IP; local, metadata and multicast addresses are not supported")
    return str(ip)

def probe(address, port):
    started = time.monotonic()
    try:
        with socket.create_connection((validate_address(address), port), timeout=2):
            return True, round((time.monotonic() - started) * 1000, 2)
    except (OSError, ValueError):
        return False, None

def check(db, monitor):
    db.execute(update(NetworkMonitor).where(NetworkMonitor.id == monitor.id).values(enabled=NetworkMonitor.enabled))
    db.refresh(monitor)
    if monitor.probe_device_id:
        request_probes(db, [monitor])
        db.flush()
        return monitor
    up, latency = probe(monitor.address, monitor.port)
    return record_result(db, monitor, up, latency)


def record_result(db, monitor, up, latency, source="cloud"):
    now, previous = utcnow(), monitor.state
    monitor.state = "up" if up else "down"
    monitor.failures = 0 if up else monitor.failures + 1
    monitor.checked_at, monitor.next_check_at = now, now + timedelta(seconds=monitor.interval_seconds)
    monitor.samples = ((monitor.samples or []) + [{"at": now.isoformat() + "Z", "up": up, "latencyMs": latency, "from": source}])[-100:]
    rule_id = "network:" + monitor.id
    if not up and monitor.failures == 3:
        db.add(Alert(tenant_id=monitor.tenant_id, rule_id=rule_id, title="Service unavailable: " + monitor.name,
                     severity="medium", details={"monitorId": monitor.id, "address": monitor.address, "port": monitor.port}))
        events.publish(db, "network.down", {"monitorId": monitor.id}, monitor.tenant_id)
    elif up and previous == "down":
        for alert in db.scalars(select(Alert).where(Alert.tenant_id == monitor.tenant_id, Alert.rule_id == rule_id, Alert.status.in_(["new", "triaged"]))):
            alert.status, alert.updated_at = "resolved", now
        events.publish(db, "network.recovered", {"monitorId": monitor.id}, monitor.tenant_id)
    db.flush()
    return monitor

def tick(db):
    now = utcnow()
    candidates = select(NetworkMonitor.id).where(NetworkMonitor.enabled.is_(True), NetworkMonitor.next_check_at <= now).order_by(NetworkMonitor.next_check_at).limit(10)
    if db.get_bind().dialect.name == "postgresql":
        candidates = candidates.with_for_update(skip_locked=True)
    ids = db.scalars(update(NetworkMonitor).where(NetworkMonitor.id.in_(candidates), NetworkMonitor.next_check_at <= now)
                     .values(next_check_at=now + timedelta(seconds=300)).returning(NetworkMonitor.id)
                     .execution_options(synchronize_session=False)).all()
    agent_probed = []
    for ident in ids:
        monitor = db.get(NetworkMonitor, ident, populate_existing=True)
        if monitor.probe_device_id:
            agent_probed.append(monitor)
        else:
            check(db, monitor)
    request_probes(db, agent_probed)
    return len(ids)


def request_probes(db, monitors):
    """Ask each probe device to check its due monitors: one network.probe command per device, never stacked."""
    by_device: dict[str, list] = {}
    for monitor in monitors:
        by_device.setdefault(monitor.probe_device_id, []).append(monitor)
    now = utcnow()
    for device_id, group in by_device.items():
        device = db.get(Device, device_id)
        if device is None or device.tenant_id != group[0].tenant_id:
            for monitor in group:
                monitor.state = "no_probe"
            continue
        waiting = db.scalars(select(Command).where(Command.device_id == device.id, Command.type == PROBE_COMMAND,
                                                   Command.status.in_(("pending", "dispatched")))).first()
        if waiting is not None:
            if now - waiting.created_at > PROBE_TIMEOUT:
                waiting.status, waiting.updated_at = "expired", now
                for monitor in group:
                    monitor.state = "probe_offline"
                    monitor.checked_at = now
            continue
        db.add(Command(tenant_id=device.tenant_id, device_id=device.id, type=PROBE_COMMAND, issued_by="system:network",
                       payload={"targets": [{"monitorId": m.id, "address": m.address, "port": m.port} for m in group[:100]]},
                       reason="Scheduled network monitor checks"))
        db.info.setdefault("wake_devices", set()).add(device.id)


def apply_probe_results(db, device, command):
    """Fold a probe device's results into its monitors (ignores monitors that are not assigned to it)."""
    if command.status != "completed":
        return 0
    applied = 0
    for result in (command.result or {}).get("results") or []:
        if not isinstance(result, dict):
            continue
        monitor = db.get(NetworkMonitor, str(result.get("monitorId") or ""))
        if monitor is None or monitor.probe_device_id != device.id or monitor.tenant_id != device.tenant_id:
            continue
        latency = result.get("latencyMs")
        record_result(db, monitor, bool(result.get("up")), float(latency) if isinstance(latency, (int, float)) else None,
                      source=device.hostname)
        applied += 1
    return applied
