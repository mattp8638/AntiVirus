"""CORE-08: the health watch alerts the MSP once when the platform degrades and once when it recovers; /metrics."""
import dataclasses
import time

import pytest

from fenrir_cloud import config, db as database, health, main, services
from fenrir_cloud.models import AuditLog, BackgroundJob, PlatformEvent, Tenant, Webhook

TOKEN = "metrics-token-0123456789abcdef"


@pytest.fixture()
def sent(client, monkeypatch):
    calls = []
    monkeypatch.setattr(services, "_post", lambda url, payload, secret: calls.append((url, payload)))
    with database.session_factory()() as db:
        msp = db.query(Tenant).filter(Tenant.kind == "msp").one()
        db.add(Webhook(tenant_id=msp.id, name="On-call", url="https://hooks.msp-test.net/fenrir", kind="generic",
                       events=["platform.health.degraded", "platform.health.recovered"]))
        db.add(Webhook(tenant_id=msp.id, name="Tickets only", url="https://hooks.msp-test.net/tickets",
                       events=["ticket.created"]))
        db.commit()
    return calls


def healthy():
    main._heartbeat("scheduler.pass", time.monotonic())
    main._heartbeat("maintenance.pass", time.monotonic())


def watch():
    with database.session_factory()() as db:
        return health.watch_once(db, config.get_settings())


def test_degraded_is_sent_once_then_recovered(sent):
    assert watch() == "platform.health.degraded"  # nothing has completed yet
    assert len(sent) == 1
    url, payload = sent[0]
    assert url.endswith("/fenrir")  # not the webhook that only wants tickets
    assert payload["event"] == "platform.health.degraded"
    assert any("scheduler.pass" in p for p in payload["data"]["problems"])

    assert watch() is None  # still degraded, and the ages in the problem text changed: no second alert
    assert len(sent) == 1

    healthy()
    assert watch() == "platform.health.recovered"
    assert sent[-1][1]["event"] == "platform.health.recovered"
    assert set(sent[-1][1]["data"]["resolved"]) == {"maintenance.pass", "scheduler.pass"}
    assert watch() is None and len(sent) == 2
    with database.session_factory()() as db:
        actions = [a.action for a in db.query(AuditLog).filter(AuditLog.actor == "system:health-watch")]
    assert actions == ["platform.health.degraded", "platform.health.recovered"]


def test_a_job_failing_repeatedly_is_alerted_and_a_new_problem_alerts_again(sent):
    healthy()
    assert watch() is None  # healthy from the start: nothing to say
    with database.session_factory()() as db:
        db.add(BackgroundJob(name="m365.partner", failures=3, error="token expired for Contoso"))
        db.commit()
    assert watch() == "platform.health.degraded"
    body = sent[-1][1]["data"]
    assert body["new"] == ["failing:m365.partner"]
    assert "Contoso" not in str(body)  # job names, never errors or customer names
    with database.session_factory()() as db:
        db.get(BackgroundJob, "m365.partner").running_since = health.utcnow() - health.STUCK_AFTER * 2
        db.commit()
    assert watch() == "platform.health.degraded"
    assert sent[-1][1]["data"]["new"] == ["stuck:m365.partner"]


def test_an_unreachable_webhook_is_queued_for_retry(client, monkeypatch, sent):
    def down(url, payload, secret):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(services, "_post", down)
    assert watch() == "platform.health.degraded"
    with database.session_factory()() as db:
        queued = db.query(PlatformEvent).filter(PlatformEvent.type == "webhook.delivery").all()
    assert [q.payload["event"] for q in queued] == ["platform.health.degraded"]
    assert watch() is None  # the state was saved before sending: no repeat while it is down


def test_low_artifact_storage_fails_background_health(client, monkeypatch):
    healthy()
    gib = 1024**3
    monkeypatch.setattr(health, "storage_usage", lambda path: {"freeBytes": 3 * gib, "totalBytes": 100 * gib})
    response = client.get("/health/background")
    assert response.status_code == 503
    assert "artifact storage is nearly full: 3.0 GiB free (3%)" in response.json()["problems"]
    # 4% of a large disk is still plenty of room
    monkeypatch.setattr(health, "storage_usage", lambda path: {"freeBytes": 12 * gib, "totalBytes": 300 * gib})
    assert client.get("/health/background").status_code == 200
    # a small disk is never allowed under 1 GiB, whatever the percentage
    monkeypatch.setattr(health, "storage_usage", lambda path: {"freeBytes": gib // 2, "totalBytes": 8 * gib})
    assert client.get("/health/background").status_code == 503


@pytest.fixture()
def metrics_token(client):
    original = config.get_settings()
    config.set_settings(dataclasses.replace(original, metrics_token=TOKEN))
    yield TOKEN
    config.set_settings(original)


def test_metrics_need_the_token(client, metrics_token):
    assert client.get("/metrics").status_code == 404
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong-token-0123456789abcdef"}).status_code == 404
    assert client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200


def test_metrics_are_off_without_a_long_enough_token(client):
    config.set_settings(dataclasses.replace(config.get_settings(), metrics_token="short"))
    try:
        assert client.get("/metrics", headers={"Authorization": "Bearer short"}).status_code == 404
    finally:
        config.set_settings(dataclasses.replace(config.get_settings(), metrics_token=""))


def test_metrics_content(client, device, metrics_token):
    healthy()
    with database.session_factory()() as db:
        db.add(BackgroundJob(name="m365.partner", failures=2, error="token expired for Contoso", duration_ms=1500))
        db.commit()
    response = client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    text = response.text
    assert response.headers["content-type"].startswith("text/plain")
    for line in ("fenrir_up 1", "fenrir_background_ok 1", f"fenrir_schema_version {database.LATEST_MIGRATION}",
                 'fenrir_job_consecutive_failures{job="m365.partner"} 2', 'fenrir_job_duration_seconds{job="m365.partner"} 1.5',
                 'fenrir_devices{state="enrolled"} 1', 'fenrir_devices{state="seen_15m"} 1',
                 'fenrir_outbox_events{state="dead"} 0'):
        assert line in text, line
    assert "Contoso" not in text and "ACME-WS-01" not in text and "Acme Dental" not in text
    for line in text.splitlines():  # every sample line parses as Prometheus text
        if line and not line.startswith("#"):
            name_and_labels, value = line.rsplit(" ", 1)
            float(value)


def test_vulnerability_intelligence_failures_are_recorded_and_alerted(sent, monkeypatch):
    from fenrir_cloud import cveintel

    def broken(db, client):
        raise RuntimeError("NVD answered 503")

    monkeypatch.setattr(cveintel, "run_once", broken)
    healthy()
    with database.session_factory()() as db:
        for _ in range(3):
            assert cveintel.run_recorded(db) is False
        row = db.get(BackgroundJob, "vuln.intel")
        assert row.failures == 3 and "NVD answered 503" in row.error
    assert watch() == "platform.health.degraded"
    assert sent[-1][1]["data"]["new"] == ["failing:vuln.intel"]


def test_an_expiring_code_signing_certificate_is_reported(client, monkeypatch, tmp_path):
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def cert(days_left):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fenrir Test Signing")])
        now = datetime.now(timezone.utc)
        built = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                 .serial_number(1).not_valid_before(now - timedelta(days=365)).not_valid_after(now + timedelta(days=days_left))
                 .sign(key, hashes.SHA256()))
        path = tmp_path / f"cert-{days_left}.cer"
        path.write_bytes(built.public_bytes(serialization.Encoding.DER))
        return path

    healthy()
    monkeypatch.setattr(health, "CODE_SIGNING_CERT", cert(200))
    assert client.get("/health/background").status_code == 200
    monkeypatch.setattr(health, "CODE_SIGNING_CERT", cert(10))
    body = client.get("/health/background").json()
    assert any("code-signing certificate expires in" in p for p in body["problems"])
    assert "code-signing" in health.problem_keys(body)
    monkeypatch.setattr(health, "CODE_SIGNING_CERT", tmp_path / "missing.cer")  # an unsigned lab build: nothing to say
    assert client.get("/health/background").status_code == 200


def test_azure_trusted_signing_short_lived_certificates_are_not_reported(client, monkeypatch, tmp_path):
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fenrir Test Signing")])
    now = datetime.now(timezone.utc)
    built = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
             .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=2))
             .sign(key, hashes.SHA256()))
    cer = tmp_path / "fenrir-codesign.cer"
    cer.write_bytes(built.public_bytes(serialization.Encoding.DER))
    healthy()
    monkeypatch.setattr(health, "CODE_SIGNING_CERT", cer)
    body = client.get("/health/background").json()
    assert any("code-signing certificate expires in" in p for p in body["problems"])  # a .pfx this close is a problem
    (tmp_path / "build.json").write_text('{"signed": true, "method": "azure-trusted-signing"}')
    body = client.get("/health/background").json()
    assert not any("code-signing" in p for p in body["problems"])
    assert body["checks"]["codeSigning"] == {"ok": True, "method": "azure-trusted-signing"}
