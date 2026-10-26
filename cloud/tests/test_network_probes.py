"""Network monitors probed by an enrolled device on the customer's LAN."""
import json
from datetime import timedelta

from fenrir_cloud import db as database, network
from fenrir_cloud.models import Alert, Command, NetworkMonitor, utcnow


def _poll(client, device):
    return client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]


def _complete(client, device, command, results):
    response = client.post(f"/api/v1/devices/{device['deviceId']}/commands/{command['id']}/complete", headers=device["headers"],
                           json={"status": "completed", "resultJson": json.dumps({"results": results})})
    assert response.status_code == 200, response.text


def _tick():
    session = database.session_factory()()
    try:
        for monitor in session.query(NetworkMonitor):
            monitor.next_check_at = utcnow() - timedelta(seconds=1)
        session.commit()
        count = network.tick(session)
        session.commit()
        return count
    finally:
        session.close()


def test_device_probes_lan_services_and_raises_alerts(client, admin, tenant, device):
    created = client.post("/api/console/network/monitors", headers=admin, json={
        "tenantId": tenant["id"], "name": "Reception printer", "address": "192.168.1.50", "port": 9100, "probeDeviceId": device["deviceId"]})
    assert created.status_code == 200, created.text
    monitor = created.json()
    assert monitor["probeDeviceId"] == device["deviceId"]
    assert client.post("/api/console/network/monitors", headers=admin, json={
        "tenantId": tenant["id"], "name": "x", "address": "10.0.0.1", "port": 80, "probeDeviceId": "dev_other"}).status_code == 404

    assert _tick() == 1
    [command] = [c for c in _poll(client, device) if c["type"] == "network.probe"]
    targets = json.loads(command["payloadJson"])["targets"]
    assert targets == [{"monitorId": monitor["id"], "address": "192.168.1.50", "port": 9100}]
    _tick()  # an unanswered probe is never stacked
    assert len([c for c in _poll(client, device) if c["type"] == "network.probe"]) == 1
    _complete(client, device, command, [{"monitorId": monitor["id"], "up": True, "latencyMs": 3.2},
                                        {"monitorId": "net_forged", "up": False}])
    row = client.get("/api/console/network/monitors", headers=admin).json()[0]
    assert row["state"] == "up" and row["samples"][-1]["from"] == "ACME-WS-01"

    for _ in range(3):
        _tick()
        [command] = [c for c in _poll(client, device) if c["type"] == "network.probe"]
        _complete(client, device, command, [{"monitorId": monitor["id"], "up": False, "error": "connection refused"}])
    session = database.session_factory()()
    try:
        alerts = session.query(Alert).filter(Alert.rule_id == "network:" + monitor["id"]).all()
        assert len(alerts) == 1 and alerts[0].status == "new"
    finally:
        session.close()


def test_silent_probe_device_is_reported_offline(client, admin, tenant, device):
    monitor = client.post("/api/console/network/monitors", headers=admin, json={
        "tenantId": tenant["id"], "name": "NAS", "address": "10.1.1.20", "port": 445, "probeDeviceId": device["deviceId"]}).json()
    _tick()
    session = database.session_factory()()
    try:
        command = session.query(Command).filter_by(type="network.probe").one()
        command.created_at = utcnow() - timedelta(minutes=11)
        session.commit()
    finally:
        session.close()
    _tick()
    row = client.get("/api/console/network/monitors", headers=admin).json()[0]
    assert row["id"] == monitor["id"] and row["state"] == "probe_offline"
    # Switching back to cloud probing resets the state.
    switched = client.patch(f"/api/console/network/monitors/{monitor['id']}", headers=admin, json={"probeDeviceId": None}).json()
    assert switched["probeDeviceId"] is None and switched["state"] == "unknown"
