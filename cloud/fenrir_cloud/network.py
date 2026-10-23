"""Bounded TCP service checks from the cloud server's network."""
import ipaddress
import socket
import time
from datetime import timedelta
from sqlalchemy import select, update
from . import events
from .models import NetworkMonitor, Alert, utcnow

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
    up, latency = probe(monitor.address, monitor.port)
    now, previous = utcnow(), monitor.state
    monitor.state = "up" if up else "down"
    monitor.failures = 0 if up else monitor.failures + 1
    monitor.checked_at, monitor.next_check_at = now, now + timedelta(seconds=monitor.interval_seconds)
    monitor.samples = ((monitor.samples or []) + [{"at": now.isoformat() + "Z", "up": up, "latencyMs": latency}])[-100:]
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
    for ident in ids:
        check(db, db.get(NetworkMonitor, ident, populate_existing=True))
    return len(ids)
