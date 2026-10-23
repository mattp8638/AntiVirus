"""Phase-1 control-plane smoke test.

An API simulation checks tenant-bound enrollment, heartbeats and command
results. It is NOT a substitute for running a Windows agent through a reboot.
"""
import json

from fenrir_cloud import db as database
from fenrir_cloud.models import Device
from sqlalchemy import select


def test_enroll_heartbeat_command_and_reconnect_preserves_device_record(client, admin, tenant):
    token_response = client.post("/api/console/enrollment-tokens", headers=admin, json={
        "tenantId": tenant["id"], "label": "Phase1 lab enrollment", "expiresInDays": 1,
    })
    assert token_response.status_code == 200, token_response.text
    raw_token = token_response.json()["token"]

    enrollment = client.post("/api/v1/enroll", json={
        "hostname": "PHASE1-LAB-WIN11", "platform": "windows", "osVersion": "Windows 11 Pro",
        "serialNumber": "PHASE1-STABLE-SERIAL",
        "enrollmentToken": raw_token,
    })
    assert enrollment.status_code == 200, enrollment.text
    identity = enrollment.json()
    assert identity["approved"] is True
    device_id = identity["deviceId"]
    device_auth = {"X-Device-Api-Key": identity["deviceApiKey"]}
    device_url = f"/api/v1/devices/{device_id}"

    for uptime in (120, 400):
        heartbeat = client.post(f"{device_url}/heartbeat", headers=device_auth, json={
            "agentVersion": "phase1-test", "healthState": "healthy", "metrics": {
                "cpuPercent": 8, "memoryPercent": 21,
                "uptimeSeconds": uptime, "disks": [],
            }
        })
        assert heartbeat.status_code == 200, heartbeat.text

    queued = client.post(f"/api/console/devices/{device_id}/commands", headers=admin, json={
        "type": "scan.targeted", "targetPath": "C:\\Users\\Public",
    })
    assert queued.status_code == 200, queued.text
    polled = client.get(f"{device_url}/commands/pending", headers=device_auth)
    assert polled.status_code == 200
    [command] = polled.json()["items"]
    assert command["type"] == "scan.targeted"
    completion = client.post(f"{device_url}/commands/{command['id']}/complete", headers=device_auth,
                             json={"status": "completed", "resultJson": json.dumps({"findings": 0})})
    assert completion.status_code == 200, completion.text

    # Repeated heartbeats after a simulated agent reconnection must not create
    # extra customer devices or alter the enrolled tenant/identity.
    assert client.post(f"{device_url}/heartbeat", headers=device_auth,
                       json={"agentVersion": "phase1-test", "healthState": "healthy"}).status_code == 200
    session = database.session_factory()()
    try:
        device = session.get(Device, device_id)
        assert device is not None
        assert device.tenant_id == tenant["id"]
        assert device.hostname == "PHASE1-LAB-WIN11"
        records = session.scalars(select(Device).where(
            Device.tenant_id == tenant["id"], Device.serial_number == "PHASE1-STABLE-SERIAL")).all()
        assert len(records) == 1
    finally:
        session.close()
    history = client.get(f"/api/console/commands?device_id={device_id}", headers=admin)
    assert history.status_code == 200
    assert history.json()[0]["status"] == "completed"
