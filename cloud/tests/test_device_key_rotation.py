"""CORE-04: device API key rotation in two steps, so an agent can never lock itself out."""
import dataclasses
from datetime import timedelta

from fenrir_cloud import config, db as database
from fenrir_cloud.models import AuditLog, Device, utcnow


def beat(client, device_id, key):
    return client.post(f"/api/v1/devices/{device_id}/heartbeat", json={}, headers={"X-Device-Api-Key": key})


def test_rotation_keeps_the_old_key_until_the_new_one_is_used(client, admin, device):
    device_id, old = device["deviceId"], device["deviceApiKey"]
    assert beat(client, device_id, old).json()["rotateKey"] is False

    assert client.post(f"/api/console/devices/{device_id}/rotate-key", headers=admin).json()["keyRotationRequested"]
    assert beat(client, device_id, old).json()["rotateKey"] is True

    reply = client.post(f"/api/v1/devices/{device_id}/rotate-key", headers={"X-Device-Api-Key": old})
    assert reply.status_code == 200
    new = reply.json()["deviceApiKey"]
    assert new != old and reply.json()["commandChannelUrl"].endswith(f"deviceApiKey={new}")
    assert reply.json()["realtimeUrl"].endswith(f"/api/v1/devices/{device_id}/realtime")

    # The agent has not used the new key yet (it might not have saved it): the old one still works.
    assert beat(client, device_id, old).status_code == 200

    # First use of the new key completes the rotation; the old key is refused from then on.
    after = beat(client, device_id, new)
    assert after.status_code == 200 and after.json()["rotateKey"] is False
    assert beat(client, device_id, old).status_code == 401
    assert client.get(f"/api/v1/devices/{device_id}/commands/pending", headers={"X-Device-Api-Key": old}).status_code == 401

    view = client.get(f"/api/console/devices/{device_id}", headers=admin).json()["device"]
    assert view["apiKeyRotatedAt"] and view["keyRotationRequested"] is False
    assert "pendingApiKeyHash" not in view and "apiKeyHash" not in view
    with database.session_factory()() as db:
        assert db.query(AuditLog).filter(AuditLog.action == "device.key_rotated", AuditLog.target == device_id).count() == 1


def test_asking_again_replaces_an_unused_pending_key(client, device):
    device_id, old = device["deviceId"], device["deviceApiKey"]
    first = client.post(f"/api/v1/devices/{device_id}/rotate-key", headers={"X-Device-Api-Key": old}).json()["deviceApiKey"]
    # The agent crashed before saving it, still has the old key, and asks again.
    second = client.post(f"/api/v1/devices/{device_id}/rotate-key", headers={"X-Device-Api-Key": old}).json()["deviceApiKey"]
    assert beat(client, device_id, first).status_code == 401
    assert beat(client, device_id, second).status_code == 200
    assert beat(client, device_id, old).status_code == 401


def test_a_pending_key_completes_rotation_on_command_endpoints_too(client, admin, device):
    device_id, old = device["deviceId"], device["deviceApiKey"]
    new = client.post(f"/api/v1/devices/{device_id}/rotate-key", headers={"X-Device-Api-Key": old}).json()["deviceApiKey"]
    command = client.post(f"/api/console/devices/{device_id}/commands", headers=admin,
                          json={"type": "scan.quick", "payload": {}}).json()
    done = client.post(f"/api/v1/devices/{device_id}/commands/{command['id']}/complete", json={"status": "completed"},
                       headers={"X-Device-Api-Key": new})
    assert done.status_code == 200, done.text
    assert beat(client, device_id, old).status_code == 401


def test_old_keys_are_rotated_by_age(client, device):
    device_id, key = device["deviceId"], device["deviceApiKey"]
    with database.session_factory()() as db:
        row = db.get(Device, device_id)
        row.api_key_rotated_at = utcnow() - timedelta(days=91)
        db.commit()
    assert beat(client, device_id, key).json()["rotateKey"] is True
    original = config.get_settings()
    config.set_settings(dataclasses.replace(original, device_key_max_age_days=0))
    try:
        assert beat(client, device_id, key).json()["rotateKey"] is False
    finally:
        config.set_settings(original)


def test_a_decommissioned_device_cannot_come_back_with_a_pending_key(client, admin, device):
    device_id, old = device["deviceId"], device["deviceApiKey"]
    new = client.post(f"/api/v1/devices/{device_id}/rotate-key", headers={"X-Device-Api-Key": old}).json()["deviceApiKey"]
    assert client.delete(f"/api/console/devices/{device_id}", headers=admin).status_code == 200
    assert beat(client, device_id, new).status_code == 401
    assert beat(client, device_id, old).status_code == 401
    assert client.post(f"/api/console/devices/{device_id}/rotate-key", headers=admin).status_code == 409


def test_a_key_cannot_rotate_another_device(client, admin, tenant, device):
    from conftest import enroll

    other = enroll(client, admin, tenant, hostname="ACME-WS-02", serial="SN-2")
    reply = client.post(f"/api/v1/devices/{other['deviceId']}/rotate-key", headers={"X-Device-Api-Key": device["deviceApiKey"]})
    assert reply.status_code == 401
