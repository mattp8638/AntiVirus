import dataclasses
import json
import time
from datetime import timedelta

import pytest

from fenrir_cloud import config, db as database, main, worker
from fenrir_cloud.models import BackgroundJob, Command, Event, PlatformEvent, RuleMatch, utcnow
from fenrir_cloud.remote import hub


def test_background_health_needs_both_passes_and_names_what_is_wrong(client, admin):
    response = client.get("/health/background")
    assert response.status_code == 503
    assert any("scheduler.pass has not completed yet" in p for p in response.json()["problems"])
    main._heartbeat("scheduler.pass", time.monotonic())
    main._heartbeat("maintenance.pass", time.monotonic())
    healthy = client.get("/health/background")
    assert healthy.status_code == 200 and healthy.json()["ok"] is True
    assert healthy.json()["checks"]["scheduler.pass"]["lastPassSecondsAgo"] < 60
    status = client.get("/api/console/platform/status", headers=admin).json()
    assert status["background"]["ok"] is True


def test_a_hung_job_and_a_stalled_outbox_fail_background_health(client):
    main._heartbeat("scheduler.pass", time.monotonic())
    main._heartbeat("maintenance.pass", time.monotonic())
    with database.session_factory()() as db:
        db.add(BackgroundJob(name="m365.partner", failures=0, error="token for Contoso expired",
                             running_since=utcnow() - timedelta(minutes=45)))
        db.add(PlatformEvent(type="webhook.delivery", key="late-1", payload={}, results={}, status="pending",
                             next_attempt_at=utcnow() - timedelta(minutes=20)))
        db.commit()
    response = client.get("/health/background")
    assert response.status_code == 503
    body = response.json()
    assert body["checks"]["jobs"]["stuck"] == ["m365.partner"]
    assert any(p.startswith("event outbox is") for p in body["problems"])
    assert "Contoso" not in json.dumps(body)  # no errors or customer names without sign-in


def test_a_running_job_is_marked_and_cleared(client):
    seen = {}

    def job(db):
        seen["running"] = db.get(BackgroundJob, "test.marked").running_since is not None

    with database.session_factory()() as db:
        assert main._run_job(db, "test.marked", job)
        assert seen["running"] and db.get(BackgroundJob, "test.marked").running_since is None


def test_the_web_process_wakes_agents_for_commands_queued_by_the_worker(client, admin, device, monkeypatch):
    woken_devices = []
    monkeypatch.setattr(hub, "devices", {device["deviceId"]: {object()}})
    monkeypatch.setattr(hub, "wake", lambda ids: woken_devices.append(set(ids)))
    with database.session_factory()() as db:  # what the worker does: no wake hook fires in this process
        device_row = db.get(main.Device, device["deviceId"])
        db.add(Command(id="cmd_from_worker", tenant_id=device_row.tenant_id, device_id=device_row.id, type="script.run",
                       issued_by="schedule", status="pending"))
        db.commit()
    woken: dict[str, float] = {}
    assert main._wake_pending(woken) == {device["deviceId"]}
    assert main._wake_pending(woken) == set()  # woken once per command
    assert woken_devices == [{device["deviceId"]}]


def test_retention_deletes_in_batches_and_keeps_routine_events_a_rule_matched(client, device, monkeypatch):
    monkeypatch.setattr(main, "PURGE_CHUNK", 2)
    settings = dataclasses.replace(config.get_settings(), telemetry_retention_days=90, routine_retention_days=30)
    old, ancient = utcnow() - timedelta(days=40), utcnow() - timedelta(days=100)
    with database.session_factory()() as db:
        device_row = db.get(main.Device, device["deviceId"])

        def event(event_id, category, at, severity="info"):
            row = Event(tenant_id=device_row.tenant_id, device_id=device_row.id, event_id=event_id, event_type=f"{category}.x",
                        category=category, severity=severity, occurred_at=at, fields={})
            db.add(row)
            return row

        for i in range(5):
            event(f"routine-{i}", "image_load", old)
        matched = event("routine-matched", "process", old)
        event("finding-40d", "malware", old, severity="high")
        event("routine-recent", "process", utcnow() - timedelta(days=2))
        event("anything-100d", "malware", ancient, severity="high")
        db.flush()
        db.add(RuleMatch(tenant_id=device_row.tenant_id, rule_id="r1", device_id=device_row.id, event_pk=matched.id,
                         group_key="", at=old))
        db.commit()
        removed = main._purge_telemetry(db, settings)
        left = {e for (e,) in db.execute(main.select(Event.event_id).where(Event.device_id == device_row.id))}
    assert removed["events"] == 1 and removed["routine"] == 5
    assert left >= {"routine-matched", "finding-40d", "routine-recent"}
    assert not left & {"anything-100d", "routine-0", "routine-4"}


def test_worker_check_reports_background_health(client, monkeypatch, capsys):
    monkeypatch.setattr(main, "create_app", lambda settings=None: None)  # the test database is already set up
    assert worker.main(["--check"]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
    main._heartbeat("scheduler.pass", time.monotonic())
    main._heartbeat("maintenance.pass", time.monotonic())
    assert worker.main(["--check"]) == 0


def test_an_unknown_role_refuses_to_start():
    with pytest.raises(RuntimeError, match="FENRIR_ROLE"):
        main.create_app(dataclasses.replace(config.get_settings(), role="both"))
