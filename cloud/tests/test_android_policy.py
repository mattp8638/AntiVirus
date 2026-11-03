"""Android phones: the policy section reaches the phone, compliance reports raise and close one alert per phone, and
remote sessions on phones are screen sharing only."""
from conftest import enroll
from fenrir_cloud import db as database
from fenrir_cloud.models import Alert, Device


def phone(client, admin, tenant):
    return enroll(client, admin, tenant, hostname="Pixel-8-Jo", os_version="Android 15 (Google Pixel 8)", serial="PX8-1")


def beat(client, dev, compliance, mode="work_profile"):
    reply = client.post(f"/api/v1/devices/{dev['deviceId']}/heartbeat", headers=dev["headers"], json={
        "agentVersion": "0.2.0", "metrics": {"batteryPercent": 80, "compliance": compliance, "managementMode": mode}})
    assert reply.status_code == 200, reply.text


def alerts(device_id):
    with database.session_factory()() as db:
        return [(a.status, a.details.get("failing")) for a in db.query(Alert).filter(Alert.device_id == device_id, Alert.rule_id == "android:noncompliant")]


def test_policy_section_reaches_the_phone(client, admin, tenant):
    dev = phone(client, admin, tenant)
    doc = client.post(f"/api/v1/devices/{dev['deviceId']}/policy-check-in", headers=dev["headers"], json={}).json()["policy"]
    android = doc["modules"]["android"]
    assert android["passcodeComplexity"] == "none" and android["minSecurityPatchDays"] == 90 and android["blockUnknownSources"] is True


def test_non_compliant_phone_raises_one_alert_and_it_closes_when_fixed(client, admin, tenant):
    dev = phone(client, admin, tenant)
    failing = [{"key": "passcode", "label": "Passcode", "ok": False, "detail": "no screen lock", "enforced": True},
               {"key": "encryption", "label": "Encryption", "ok": True}]
    beat(client, dev, failing)
    beat(client, dev, failing)
    assert alerts(dev["deviceId"]) == [("new", ["passcode"])]
    with database.session_factory()() as db:
        metrics = db.get(Device, dev["deviceId"]).metrics
        assert metrics["managementMode"] == "work_profile" and metrics["compliant"] is False and len(metrics["compliance"]) == 2
    beat(client, dev, [{"key": "passcode", "label": "Passcode", "ok": True}])
    assert alerts(dev["deviceId"]) == [("resolved", ["passcode"])]


def test_phone_remote_sessions_are_screen_sharing_only(client, admin, tenant):
    dev = phone(client, admin, tenant)
    from test_documentation_vault import stepup

    for mode in ("terminal", "files"):
        reply = client.post("/api/console/remote/sessions", headers=admin, json={"deviceId": dev["deviceId"], "mode": mode})
        assert reply.status_code in (400, 422), reply.text
    reply = client.post("/api/console/remote/sessions", headers=admin, json={"deviceId": dev["deviceId"], "mode": "desktop"})
    assert reply.status_code in (200, 201), reply.text
