"""Reinstatement installers really build (no stubbed builder) and decommissioned devices can be deleted."""
import hashlib
import json
import re

from conftest import ADMIN_PASSWORD, enroll

from fenrir_cloud import db as database, deployment_installers as installers
from fenrir_cloud.models import AuditLog, Device, Event, Ticket


def _reauth(client, admin):
    proof = client.post("/api/console/auth/reauth", headers=admin, json={"password": ADMIN_PASSWORD}).json()["reauthToken"]
    return {**admin, "X-Fenrir-Reauth": proof}


def test_reinstatement_installer_builds_and_reconnects_the_device(client, admin, tenant, monkeypatch, tmp_path):
    monkeypatch.setattr(installers, "DOWNLOADS", tmp_path)
    for arch in ("amd64", "arm64"):
        (tmp_path / f"fenrir-agent-linux-{arch}").write_bytes(b"linux-binary-" + arch.encode())
    device = enroll(client, admin, tenant, hostname="LNX-01", os_version="Ubuntu 24.04", serial="LNX-SN")
    assert client.delete(f"/api/console/devices/{device['deviceId']}", headers=admin).status_code == 200
    response = client.post("/api/console/enrollment-installers", headers=admin, json={
        "os": "linux", "tenantId": tenant["id"], "reinstateDeviceId": device["deviceId"]})
    assert response.status_code == 200, response.text
    token = re.search(r"token='?(fet_rs-[A-Za-z0-9_-]+)'?", response.text).group(1)
    assert token.startswith(f"fet_rs-{device['deviceId']}-")
    # The Windows setup accepts only fet_ tokens made of letters, digits, "_" and "-".
    assert re.fullmatch(r"fet_[A-Za-z0-9_-]+", token)
    enrolled = client.post("/api/v1/enroll", json={"hostname": "LNX-01", "osVersion": "Ubuntu 24.04", "serialNumber": "LNX-SN",
                                                   "enrollmentToken": token})
    assert enrolled.status_code == 200, enrolled.text
    assert enrolled.json()["deviceId"] == device["deviceId"]
    assert client.post("/api/v1/enroll", json={"hostname": "LNX-01", "osVersion": "Ubuntu 24.04", "serialNumber": "LNX-SN",
                                               "enrollmentToken": token}).status_code in (401, 403)  # one use


def test_windows_reinstatement_installer_embeds_valid_token(client, admin, tenant, device, monkeypatch, tmp_path):
    monkeypatch.setattr(installers, "DOWNLOADS", tmp_path)
    (tmp_path / "windows").mkdir()
    binary = b"MZ" + b"fixture"
    (tmp_path / "windows" / "FenrirSetup.exe").write_bytes(binary)
    (tmp_path / "windows" / "build.json").write_text(json.dumps({"sha256": hashlib.sha256(binary).hexdigest()}))
    client.delete(f"/api/console/devices/{device['deviceId']}", headers=admin)
    response = client.post("/api/console/enrollment-installers", headers=admin, json={
        "os": "windows", "tenantId": tenant["id"], "reinstateDeviceId": device["deviceId"]})
    assert response.status_code == 200, response.text
    overlay = response.content[len(binary):].decode("ascii", "ignore")
    assert f"fet_rs-{device['deviceId']}-" in overlay


def test_ordinary_token_cannot_pose_as_reinstatement(client, admin, tenant, device):
    client.delete(f"/api/console/devices/{device['deviceId']}", headers=admin)
    token = client.post("/api/console/enrollment-tokens", headers=admin, json={"tenantId": tenant["id"], "label": "x"}).json()["token"]
    forged = "fet_rs-" + device["deviceId"] + "-" + token[4:]
    response = client.post("/api/v1/enroll", json={"hostname": "ACME-WS-01", "osVersion": "Windows 11", "serialNumber": "SN-1",
                                                   "enrollmentToken": forged})
    assert response.status_code in (401, 403, 409)


def test_purge_deletes_a_decommissioned_device_and_keeps_tickets(client, admin, tenant, device):
    send = client.post(f"/api/v1/devices/{device['deviceId']}/telemetry", headers=device["headers"], json={"events": [
        {"eventId": "e1", "eventType": "process.started", "occurredAt": "2030-01-01T00:00:00Z", "payloadJson": "{}"}]})
    assert send.status_code == 200
    ticket = client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "Laptop slow",
                                                                     "deviceId": device["deviceId"]}).json()
    url = f"/api/console/devices/{device['deviceId']}/purge"
    body = {"confirmHostname": "ACME-WS-01"}
    assert client.post(url, headers=_reauth(client, admin), json=body).status_code == 409  # not decommissioned yet
    client.delete(f"/api/console/devices/{device['deviceId']}", headers=admin)
    assert client.post(url, headers=admin, json=body).status_code == 403  # needs a fresh password check
    assert client.post(url, headers=_reauth(client, admin), json={"confirmHostname": "wrong"}).status_code == 422
    done = client.post(url, headers=_reauth(client, admin), json=body)
    assert done.status_code == 200, done.text
    assert done.json()["removed"]["events"] == 1
    assert client.get(f"/api/console/devices/{device['deviceId']}", headers=admin).status_code == 404
    session = database.session_factory()()
    try:
        assert session.get(Device, device["deviceId"]) is None
        assert session.query(Event).filter_by(device_id=device["deviceId"]).count() == 0
        kept = session.get(Ticket, ticket["id"])
        assert kept is not None and kept.device_id is None
        assert session.query(AuditLog).filter_by(action="device.purged").count() == 1
    finally:
        session.close()
