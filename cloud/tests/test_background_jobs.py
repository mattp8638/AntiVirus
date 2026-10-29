import json

import httpx
from sqlalchemy import select

from fenrir_cloud import db as database, events, main, services
from fenrir_cloud.models import BackgroundJob, PlatformEvent, utcnow


def test_a_failing_background_job_is_recorded_and_does_not_stop_the_next(client, admin):
    ran = []

    def broken(db):
        raise RuntimeError("provider unreachable")

    with database.session_factory()() as db:
        assert main._run_job(db, "test.broken", broken) is False
        assert main._run_job(db, "test.broken", broken) is False
        assert main._run_job(db, "test.fine", lambda db: ran.append("fine")) is True
        row = db.get(BackgroundJob, "test.broken")
        assert not row.ok and row.failures == 2 and "provider unreachable" in row.error and row.last_ok_at is None
        assert db.get(BackgroundJob, "test.fine").ok
    assert ran == ["fine"]
    jobs = {j["name"]: j for j in client.get("/api/console/platform/status", headers=admin).json()["jobs"]}
    assert jobs["test.broken"]["failures"] == 2 and not jobs["test.broken"]["ok"] and jobs["test.fine"]["ok"]


def test_every_scheduled_job_has_its_own_name(client):
    names = [name for name, _, _ in main._scheduled_jobs()] + [name for name, _ in main._maintenance_jobs(main.get_settings())]
    assert len(names) == len(set(names))
    assert names.index("rmm") < names.index("events.outbox")  # events raised by the RMM pass go out in the same pass


def test_webhooks_are_delivered_from_the_outbox_and_retried(client, admin, tenant, monkeypatch):
    hook = client.post("/api/console/webhooks", headers=admin,
                       json={"url": "https://hooks.example/fenrir", "events": ["incident.created"], "tenantId": tenant["id"]}).json()
    answers, sent = [500, 204], []

    def fake_post(url, content=None, headers=None, timeout=None):
        sent.append({"url": url, "signature": headers.get("X-Fenrir-Signature", ""), "body": json.loads(content)})
        return httpx.Response(answers.pop(0))

    monkeypatch.setattr(services.httpx, "post", fake_post)
    with database.session_factory()() as db:
        assert services.fire_webhooks(db, tenant["id"], "incident.created", {"title": "Ransomware on PC1", "severity": "critical"}) == 1
        assert services.fire_webhooks(db, tenant["id"], "monitor.triggered", {"title": "Disk full"}) == 0  # not subscribed
        db.commit()
        assert sent == []  # nothing leaves inside the request that raised it
        events.process(db)
        db.commit()
        row = db.execute(select(PlatformEvent).where(PlatformEvent.type == "webhook.delivery")).scalar_one()
        assert row.status == "pending" and "HTTP 500" in row.last_error  # retried later with back-off
        row.next_attempt_at = utcnow()
        db.commit()
        events.process(db)
        db.commit()
        db.refresh(row)
        assert row.status == "done"
    assert [s["url"] for s in sent] == [hook["url"]] * 2
    assert sent[-1]["body"] == {"event": "incident.created", "data": {"title": "Ransomware on PC1", "severity": "critical"}}
    assert sent[-1]["signature"].startswith("sha256=")
