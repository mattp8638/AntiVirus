"""Agents upload forensic/support bundles; responders download them (audited); old bundles expire."""
import hashlib
import json
from datetime import timedelta

import pytest

from fenrir_cloud import db as database
from fenrir_cloud.config import get_settings
from fenrir_cloud.models import AuditLog, DeviceArtifact, utcnow
from fenrir_cloud.routers import artifacts


@pytest.fixture(autouse=True)
def store(client, tmp_path, monkeypatch):
    import dataclasses
    from fenrir_cloud import config
    monkeypatch.setattr(config, "_active", dataclasses.replace(get_settings(), artifact_dir=tmp_path / "artifacts",
                                                                artifact_max_bytes=1024))
    (tmp_path / "artifacts").mkdir()
    return tmp_path / "artifacts"


def _issue(client, admin, device, kind="forensics.collect"):
    response = client.post(f"/api/console/devices/{device['deviceId']}/commands", headers=admin, json={"type": kind, "reason": "IR"})
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _upload(client, device, command_id, body, **params):
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return client.post(f"/api/v1/devices/{device['deviceId']}/commands/{command_id}/artifact?{query}",
                       headers={**device["headers"], "Content-Type": "application/octet-stream"}, content=body)


def test_bundle_upload_and_audited_download(client, admin, device, store):
    command_id = _issue(client, admin, device)
    body = b"tar-bytes" * 10
    assert _upload(client, device, command_id, body, filename="triage.tar.gz", sha256="0" * 64).status_code == 400
    assert list(store.iterdir()) == []  # a bad upload leaves nothing behind
    uploaded = _upload(client, device, command_id, body, filename="../../etc/triage.tar.gz", sha256=hashlib.sha256(body).hexdigest())
    assert uploaded.status_code == 200, uploaded.text
    assert _upload(client, device, command_id, body).status_code == 409  # one per command
    [row] = client.get(f"/api/console/devices/{device['deviceId']}/artifacts", headers=admin).json()
    assert row["filename"] == "ACME-WS-01-etc_triage.tar.gz" and row["size"] == len(body) and "storageName" not in row
    download = client.get(f"/api/console/artifacts/{row['id']}/download", headers=admin)
    assert download.status_code == 200 and download.content == body
    assert download.headers["x-content-sha256"] == hashlib.sha256(body).hexdigest()
    session = database.session_factory()()
    try:
        assert session.query(AuditLog).filter_by(action="artifact.downloaded").count() == 1
    finally:
        session.close()
    # Completed commands no longer accept uploads.
    client.post(f"/api/v1/devices/{device['deviceId']}/commands/{command_id}/complete", headers=device["headers"],
                json={"status": "completed", "resultJson": json.dumps({"artifactId": uploaded.json()["artifactId"]})})
    second = _issue(client, admin, device, "support.bundle")
    client.post(f"/api/v1/devices/{device['deviceId']}/commands/{second}/complete", headers=device["headers"],
                json={"status": "completed", "resultJson": "{}"})
    assert _upload(client, device, second, b"x").status_code == 409


def test_upload_limits_and_command_checks(client, admin, device, store):
    command_id = _issue(client, admin, device)
    assert _upload(client, device, command_id, b"x" * 2048).status_code == 413
    assert _upload(client, device, command_id, b"").status_code == 400
    assert list(store.iterdir()) == []
    other = _issue(client, admin, device, "inventory.refresh")
    assert _upload(client, device, other, b"x").status_code == 400
    assert client.post(f"/api/v1/devices/{device['deviceId']}/commands/{command_id}/artifact", content=b"x").status_code == 401


def test_viewer_cannot_download_and_old_bundles_expire(client, admin, device, store):
    from conftest import ADMIN_PASSWORD, login
    command_id = _issue(client, admin, device)
    artifact_id = _upload(client, device, command_id, b"evidence").json()["artifactId"]
    client.post("/api/console/users", headers=admin, json={"email": "viewer@msp.example", "password": ADMIN_PASSWORD, "role": "viewer"})
    viewer = login(client, "viewer@msp.example")
    assert client.get(f"/api/console/artifacts/{artifact_id}/download", headers=viewer).status_code == 403
    session = database.session_factory()()
    try:
        session.get(DeviceArtifact, artifact_id).created_at = utcnow() - timedelta(days=31)
        session.commit()
        assert artifacts.purge_expired(session) == 1
        session.commit()
    finally:
        session.close()
    assert list(store.iterdir()) == []
    assert client.get(f"/api/console/artifacts/{artifact_id}/download", headers=admin).status_code == 404
