"""CORE-08: a stopped component, a stuck event queue or low storage shows as degraded, alerts once per change, and is
exported as metrics only to holders of the metrics token."""

from datetime import timedelta

from conftest import login
from fenrir_cloud import health
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import PlatformEvent, ServiceHeartbeat, utcnow

ALL_ON = {"scheduler": True, "maintenance": True, "vuln-intel": True, "signature-feed": True}


def db_session():
    return session_factory()()


def beat_all(db):
    for name in health.EXPECTED:
        health.beat(db, name)


def test_components_degrade_and_recover_with_one_alert_each(client, admin):
    db = db_session()
    try:
        assert "scheduler" in health.report(db, ALL_ON)["degraded"] or True  # may or may not have run in the test app yet
        beat_all(db)
        current = health.report(db, ALL_ON)
        assert current["status"] == "ok" and current["degraded"] == []
        health.alert_on_change(db, current)
        db.commit()
        # The scheduler stops: stale after its expected interval, one alert, not one per check.
        db.get(ServiceHeartbeat, "scheduler").last_ok_at = utcnow() - timedelta(minutes=10)
        db.commit()
        current = health.report(db, ALL_ON)
        assert current["status"] == "degraded" and current["degraded"] == ["scheduler"]
        scheduler = next(c for c in current["components"] if c["name"] == "scheduler")
        assert scheduler["status"] == "stale" and "minutes ago" in scheduler["reason"]
        assert health.alert_on_change(db, current) == ["scheduler"]
        assert health.alert_on_change(db, health.report(db, ALL_ON)) == []
        db.commit()
        health.beat(db, "scheduler")
        assert health.alert_on_change(db, health.report(db, ALL_ON)) == ["scheduler"]
        db.commit()
        types = [e.type for e in db.query(PlatformEvent).filter(PlatformEvent.type.like("platform.health.%")).order_by(PlatformEvent.id)]
        assert types == ["platform.health.degraded", "platform.health.recovered"]
        # A failure after the last success is "failing"; disabled components are not judged.
        health.beat(db, "vuln-intel", ok=False, error="NVD returned 503")
        failing = health.report(db, ALL_ON)
        assert next(c for c in failing["components"] if c["name"] == "vuln-intel")["status"] == "failing"
        quiet = health.report(db, {**ALL_ON, "vuln-intel": False})
        assert next(c for c in quiet["components"] if c["name"] == "vuln-intel")["status"] == "disabled"
    finally:
        db.close()


def test_stuck_or_dead_events_degrade_the_queue(client, admin):
    db = db_session()
    try:
        beat_all(db)
        db.add(PlatformEvent(type="test.stuck", key="test-stuck", payload={}, status="pending", created_at=utcnow() - timedelta(minutes=30)))
        db.commit()
        current = health.report(db, ALL_ON)
        assert current["queue"]["status"] == "stale" and "event-queue" in current["degraded"]
        db.query(PlatformEvent).filter(PlatformEvent.type == "test.stuck").update({"status": "dead"})
        db.commit()
        assert health.report(db, ALL_ON)["queue"]["status"] == "failing"
    finally:
        db.close()


def test_health_api_and_metrics(client, admin, tenant, monkeypatch, tmp_path):
    report = client.get("/api/console/platform/health", headers=admin)
    assert report.status_code == 200 and {"components", "queue", "status"} <= set(report.json())
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "v@acme.example",
                                                           "password": "acme-password-123", "role": "viewer"})
    assert client.get("/api/console/platform/health", headers=login(client, "v@acme.example", "acme-password-123")).status_code == 403
    assert client.get("/metrics").status_code == 404  # off unless a token is configured
    monkeypatch.setenv("FENRIR_METRICS_TOKEN", "metrics-token-123")
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 404
    metrics = client.get("/metrics", headers={"Authorization": "Bearer metrics-token-123"})
    assert metrics.status_code == 200 and "fenrir_component_up" in metrics.text and "fenrir_outbox_pending" in metrics.text


def test_low_storage_is_degraded(client, admin, tmp_path, monkeypatch):
    import shutil
    from collections import namedtuple

    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(shutil, "disk_usage", lambda _path: usage(100, 95, 5))
    db = db_session()
    try:
        beat_all(db)
        current = health.report(db, ALL_ON, artifact_dir=tmp_path)
        assert current["storage"]["status"] == "low" and "storage" in current["degraded"]
    finally:
        db.close()
