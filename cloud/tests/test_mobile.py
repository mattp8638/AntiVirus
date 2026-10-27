from datetime import timedelta

from conftest import ADMIN_PASSWORD, enroll

from fenrir_cloud.models import utcnow
from fenrir_cloud.routers.mobile import distance_m


def _stepup(client, admin):
    proof = client.post("/api/console/auth/reauth", headers=admin, json={"password": ADMIN_PASSWORD}).json()["reauthToken"]
    return {**admin, "X-Fenrir-Reauth": proof}


def _phone(client, admin, tenant):
    return enroll(client, admin, tenant, hostname="Pixel-8-Jo", os_version="Android 15 (Google Pixel 8)", serial="PX8-1")


def _iso(minutes_ago: float) -> str:
    return (utcnow() - timedelta(minutes=minutes_ago)).isoformat() + "Z"


def test_distance():
    assert abs(distance_m((51.5007, -0.1246), (51.5014, -0.1419)) - 1200) < 50  # Big Ben to Buckingham Palace


def test_phone_enrols_as_android_and_reports_locations(client, admin, tenant):
    phone = _phone(client, admin, tenant)
    console = f"/api/console/devices/{phone['deviceId']}"
    assert client.get(console, headers=admin).json()["device"]["platform"] == "android"

    url = f"/api/v1/devices/{phone['deviceId']}/location"
    assert client.post(url, json={"points": [{"lat": 1, "lon": 1}]}).status_code == 401
    assert client.post(url, headers=phone["headers"], json={"points": []}).status_code == 422
    result = client.post(url, headers=phone["headers"], json={"points": [
        {"lat": 51.5007, "lon": -0.1246, "accuracy": 12, "source": "gps", "battery": 80, "at": _iso(30)},
        {"lat": 51.5014, "lon": -0.1419, "accuracy": 20, "source": "network", "reason": "locate", "at": _iso(5)},
        {"lat": 200, "lon": 0}, {"lat": 0, "lon": 0}, "junk", {"lat": 51.5, "lon": -0.12, "at": _iso(-60)},  # skipped
    ]}).json()
    assert result == {"stored": 2}

    view = client.get(console + "/locations", headers=admin, params={"hours": 24}).json()
    assert [p["source"] for p in view["points"]] == ["gps", "network"]  # oldest first
    assert view["latest"]["reason"] == "locate" and view["latest"]["lat"] == 51.5014
    assert 1100 < view["travelledMeters"] < 1300
    assert view["lostMode"]["enabled"] is False


def test_lost_mode_round_trip(client, admin, tenant, device):
    phone = _phone(client, admin, tenant)
    console = f"/api/console/devices/{phone['deviceId']}"
    # Desktops have no lost mode; it can only be set from the Location tab, not as a raw command.
    assert client.post(f"/api/console/devices/{device['deviceId']}/lost-mode", headers=admin, json={"enabled": True}).status_code == 400
    assert client.post(console + "/commands", headers=admin, json={"type": "device.lostmode"}).status_code == 400

    on = client.post(console + "/lost-mode", headers=admin, json={"enabled": True, "phone": "+44 7700 900123"}).json()
    assert on["lostMode"]["enabled"] and on["lostMode"]["message"] and on["lostMode"]["since"]
    beat = client.post(f"/api/v1/devices/{phone['deviceId']}/heartbeat", headers=phone["headers"], json={"healthState": "healthy"}).json()
    assert beat["lostMode"] == {"enabled": True, "message": on["lostMode"]["message"], "phone": "+44 7700 900123"}
    pending = client.get(f"/api/v1/devices/{phone['deviceId']}/commands/pending", headers=phone["headers"]).json()
    assert any(c["type"] == "device.lostmode" for c in pending["items"])

    off = client.post(console + "/lost-mode", headers=admin, json={"enabled": False}).json()
    assert off["lostMode"]["enabled"] is False and off["lostMode"]["phone"] == ""
    beat = client.post(f"/api/v1/devices/{phone['deviceId']}/heartbeat", headers=phone["headers"], json={}).json()
    assert beat["lostMode"]["enabled"] is False
    # Desktops are not told about lost mode at all.
    assert "lostMode" not in client.post(f"/api/v1/devices/{device['deviceId']}/heartbeat", headers=device["headers"], json={}).json()


def test_phone_actions(client, admin, tenant, device):
    phone = _phone(client, admin, tenant)
    console = f"/api/console/devices/{phone['deviceId']}"
    for kind in ("device.locate", "device.lock", "device.alarm", "device.message"):
        assert client.post(console + "/commands", headers=admin, json={"type": kind, "payload": {"seconds": 30}}).status_code == 200, kind
    # Erase needs the password again, and never runs in bulk or on a desktop.
    assert client.post(console + "/commands", headers=admin, json={"type": "device.wipe"}).status_code == 403
    assert client.post(console + "/commands", headers=_stepup(client, admin), json={"type": "device.wipe"}).status_code == 200
    assert client.post("/api/console/commands/bulk", headers=admin, json={"type": "device.wipe", "deviceIds": [phone["deviceId"]]}).status_code == 400
    assert client.post(f"/api/console/devices/{device['deviceId']}/commands", headers=admin, json={"type": "device.lock"}).status_code == 400
    assert client.post("/api/console/rmm/jobs", headers=admin, json={"commandType": "device.wipe", "targets": {"deviceIds": [phone["deviceId"]]}}).status_code == 400
