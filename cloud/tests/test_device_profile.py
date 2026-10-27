from datetime import timedelta

from conftest import ADMIN_PASSWORD

from fenrir_cloud.models import utcnow
from fenrir_cloud.routers.device_profile import findings


def _stepup(client, admin):
    proof = client.post("/api/console/auth/reauth", headers=admin, json={"password": ADMIN_PASSWORD}).json()["reauthToken"]
    return {**admin, "X-Fenrir-Reauth": proof}


PROFILE = {
    "hardware": {"manufacturer": "Intel", "model": "NUC13", "serial": "SN-123", "cpu": {"name": "i7-1360P", "cores": 12},
                 "tpm": {"present": True, "ready": True, "version": "2.0"}, "secureBoot": True},
    "os": {"name": "Windows 11 Pro", "build": "26100", "lastBoot": (utcnow() - timedelta(days=40)).isoformat() + "Z",
           "rebootPending": True, "rebootReasons": ["Windows Update"], "activation": "Licensed"},
    "disks": [{"model": "Samsung 990", "health": "Warning", "wearPercent": 91, "temperatureC": 48, "readErrors": 0}],
    "volumes": [{"mount": "C:", "sizeGb": 476, "freeGb": 12, "system": True,
                 "encryption": {"status": "FullyDecrypted", "protection": "Off"}}],
    "battery": {"present": True, "healthPercent": 52},
    "users": {"local": [{"name": "Administrator", "enabled": True, "admin": True, "passwordLastSet": "2026-01-01"},
                        {"name": "jo", "enabled": True, "admin": True}, {"name": "it", "enabled": True, "admin": True}]},
    "security": {"antivirus": [{"name": "Microsoft Defender", "enabled": True, "upToDate": False}],
                 "firewall": [{"profile": "Public", "enabled": False}], "smb1": False, "uac": True,
                 "wifiPassword": "should-be-dropped"},
    "events": {"unexpectedShutdowns7d": 3, "diskErrors7d": 0},
}


def test_profile_findings():
    titles = [f["title"] for f in findings(PROFILE)]
    assert titles[0].startswith(("Samsung 990: health Warning", "C: (system drive)")) or "high" == findings(PROFILE)[0]["severity"]
    for expected in ["Samsung 990: health Warning", "Samsung 990: 91% worn", "C: (system drive) is not encrypted",
                     "C: is nearly full", "Battery at 52% of its design capacity", "Not restarted for 40 days",
                     "A restart is pending", "Microsoft Defender definitions are out of date", "Firewall off for the Public profile",
                     "3 enabled local administrator accounts", "3 unexpected shutdowns in the last 7 days"]:
        assert expected in titles, expected
    severities = [f["severity"] for f in findings(PROFILE)]
    assert severities == sorted(severities, key=["high", "medium", "low"].index)
    assert findings({}) == []


def test_profile_and_recovery_keys(client, admin, device):
    agent = f"/api/v1/devices/{device['deviceId']}/profile"
    console = f"/api/console/devices/{device['deviceId']}"
    assert client.post(agent, json={"profile": PROFILE}).status_code == 401
    assert client.post(agent, headers=device["headers"], json={"profile": "nope"}).status_code == 422
    key = {"volume": "C:", "keyId": "{8B1C-0001}", "recoveryPassword": "111111-222222-333333-444444-555555-666666-777777-888888"}
    result = client.post(agent, headers=device["headers"], json={"profile": PROFILE, "recoveryKeys": [key]}).json()
    assert result == {"stored": True, "recoveryKeys": 1}

    view = client.get(console + "/profile", headers=admin).json()
    assert view["profile"]["hardware"]["model"] == "NUC13" and view["collectedAt"]
    assert "wifiPassword" not in view["profile"]["security"]  # secrets never stored in the profile
    assert view["findings"] and view["findings"][0]["severity"] == "high"
    assert len(view["recoveryKeys"]) == 1 and "recoveryPassword" not in str(view)
    rk = view["recoveryKeys"][0]
    assert client.post(f"{console}/recovery-keys/{rk['id']}/reveal", headers=admin).status_code == 403  # needs re-authentication
    shown = client.post(f"{console}/recovery-keys/{rk['id']}/reveal", headers=_stepup(client, admin))
    assert shown.json()["recoveryPassword"] == key["recoveryPassword"] and shown.headers["Cache-Control"] == "no-store"

    # The device summary follows the profile.
    detail = client.get(f"/api/console/devices/{device['deviceId']}", headers=admin).json()
    assert detail["device"]["inventory"]["model"] == "NUC13"

    # A protector that disappears stays escrowed but is marked removed.
    client.post(agent, headers=device["headers"], json={"profile": PROFILE, "recoveryKeys": []})
    assert client.get(console + "/profile", headers=admin).json()["recoveryKeys"][0]["status"] == "removed"

    refresh = client.post(console + "/profile/refresh", headers=admin)
    assert refresh.status_code == 200 and refresh.json()["commandId"]
