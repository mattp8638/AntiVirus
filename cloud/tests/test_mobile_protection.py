"""Phone app protection: the phone's app assessments become verdicts, alerts, removals and suspensions."""

import json
from datetime import timedelta

import pytest

from conftest import enroll, login
from fenrir_cloud import db as database
from fenrir_cloud.models import Command, Device, MobileApp, utcnow

TROJAN_SHA = "a" * 64
GAME_SHA = "b" * 64
SIGNER = "c" * 64
counter = {"n": 0}


@pytest.fixture()
def phone(client, admin, tenant):
    return enroll(client, admin, tenant, hostname="Pixel-8-Jo", os_version="Android 15 (Google Pixel 8)", serial="PX8-1")


def app(package, label, level="low", score=0, reasons=(), sha=None, installer="com.android.vending", **abilities):
    return {"package": package, "label": label, "version": "1.0", "installer": installer,
            "sideloaded": installer not in ("com.android.vending",), "system": False, "sha256": sha, "signer": SIGNER,
            "permissions": ["android.permission.READ_SMS"] if abilities.get("sms") else [],
            "accessibility": bool(abilities.get("accessibility")), "deviceAdmin": False, "notificationAccess": False,
            "hidden": bool(abilities.get("hidden")), "risk": {"score": score, "level": level, "reasons": list(reasons)}}


TROJAN = app("com.flashplayer.update", "Flash Player Update", "high", 90,
             ["Installed from outside an app store (by com.android.chrome)", "Can see and control the screen (accessibility service is on)",
              "Matches banking trojans: sideloaded, controls the screen and reads texts or draws over apps"],
             sha=TROJAN_SHA, installer="com.android.chrome", accessibility=True, sms=True)
GAME = app("com.example.game", "Puzzle Game", sha=GAME_SHA)


def report(client, phone, apps, full=True):
    counter["n"] += 1
    event = {"eventId": f"m-{counter['n']}", "eventType": "mobile.apps.assessed", "source": "android",
             "summary": "apps checked", "occurredAt": (utcnow() - timedelta(seconds=5)).isoformat() + "Z",
             "payloadJson": json.dumps({"full": full, "apps": apps})}
    reply = client.post(f"/api/v1/devices/{phone['deviceId']}/telemetry", headers=phone["headers"], json={"events": [event]})
    assert reply.status_code == 200, reply.text


def apps_view(client, admin, phone):
    reply = client.get(f"/api/console/devices/{phone['deviceId']}/mobile-apps", headers=admin)
    assert reply.status_code == 200, reply.text
    return reply.json()


def mobile_alerts(client, admin, phone, **params):
    """Open alerts unless a status is asked for."""
    rows = client.get("/api/console/alerts", headers=admin, params={"device_id": phone["deviceId"], **params}).json()
    return [a for a in rows if a["ruleId"].startswith("mobile:") and ("status" in params or a["status"] in ("new", "triaged"))]


def test_a_banking_trojan_pattern_is_alerted_and_a_store_game_is_not(client, admin, phone):
    report(client, phone, [TROJAN, GAME])
    body = apps_view(client, admin, phone)
    assert [a["package"] for a in body["apps"]] == ["com.flashplayer.update", "com.example.game"]  # worst first
    assert body["apps"][0]["verdict"] == "risky" and body["apps"][1]["verdict"] == "clean" and body["counts"]["risky"] == 1
    alerts = mobile_alerts(client, admin, phone)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["title"] == "Risky app on Pixel-8-Jo: Flash Player Update" and alert["severity"] == "high"
    assert alert["details"]["installer"] == "com.android.chrome" and "banking trojans" in alert["details"]["description"]
    report(client, phone, [TROJAN, GAME])  # the daily check again: still one alert
    assert len(mobile_alerts(client, admin, phone)) == 1
    inbox = client.get("/api/console/triage/items", headers=admin).json()["items"]
    assert any(i["title"] == "Risky app on Pixel-8-Jo: Flash Player Update" for i in inbox)


def test_threat_intelligence_on_the_apk_makes_any_app_malicious(client, admin, phone):
    report(client, phone, [GAME])
    assert mobile_alerts(client, admin, phone) == []
    added = client.post("/api/console/intel/indicators", headers=admin, json={"values": [GAME_SHA], "verdict": "malicious",
                                                                            "source": "MalwareBazaar"})
    assert added.status_code == 200, added.text
    game = apps_view(client, admin, phone)["apps"][0]
    assert game["verdict"] == "malicious" and "MalwareBazaar" in game["verdictReason"]  # reassessed without waiting for the phone
    alert = mobile_alerts(client, admin, phone)[0]
    assert alert["severity"] == "critical" and alert["title"].startswith("Malicious app on Pixel-8-Jo")


def test_a_package_indicator_is_written_android_prefixed(client, admin, phone):
    report(client, phone, [GAME])
    client.post("/api/console/intel/indicators", headers=admin, json={"values": ["android:com.example.game"], "verdict": "malicious"})
    assert apps_view(client, admin, phone)["apps"][0]["verdict"] == "malicious"


def test_removed_apps_resolve_their_alert(client, admin, phone):
    report(client, phone, [TROJAN, GAME])
    report(client, phone, [GAME])  # the next full list no longer has it
    assert mobile_alerts(client, admin, phone) == []
    assert [a["package"] for a in apps_view(client, admin, phone)["apps"]] == ["com.example.game"]
    resolved = mobile_alerts(client, admin, phone, snoozed="all", status="resolved")
    assert resolved and resolved[0]["details"]["autoResolved"] == "The app was removed from the phone."


def test_trusting_an_app_resolves_it_and_follows_the_same_apk_elsewhere(client, admin, tenant, phone):
    report(client, phone, [TROJAN])
    trusted = client.post(f"/api/console/devices/{phone['deviceId']}/mobile-apps/trust", headers=admin,
                          json={"package": "com.flashplayer.update"})
    assert trusted.status_code == 200, trusted.text
    assert apps_view(client, admin, phone)["apps"][0]["verdict"] == "trusted" and mobile_alerts(client, admin, phone) == []
    second = enroll(client, admin, tenant, hostname="Galaxy-S24", os_version="Android 14 (Samsung)", serial="S24-1")
    report(client, second, [TROJAN])
    assert apps_view(client, admin, second)["apps"][0]["verdict"] == "trusted"  # same APK, same customer


def test_policy_decides_which_verdicts_alert(client, admin, tenant, phone):
    policy = client.post("/api/console/policies", headers=admin, json={"tenantId": tenant["id"], "name": "Quiet phones",
                                                                     "settings": {"mobile": {"alertOn": "malicious"}}}).json()
    client.patch(f"/api/console/devices/{phone['deviceId']}", headers=admin, json={"policyId": policy["id"]})
    report(client, phone, [TROJAN])
    assert apps_view(client, admin, phone)["apps"][0]["verdict"] == "risky" and mobile_alerts(client, admin, phone) == []


def test_malicious_apps_are_suspended_on_company_owned_phones_when_policy_says(client, admin, tenant, phone):
    policy = client.post("/api/console/policies", headers=admin, json={"tenantId": tenant["id"], "name": "Company phones",
                                                                     "settings": {"mobile": {"suspendMalicious": True}}}).json()
    client.patch(f"/api/console/devices/{phone['deviceId']}", headers=admin, json={"policyId": policy["id"]})
    with database.session_factory()() as db:
        db.get(Device, phone["deviceId"]).metrics = {"deviceOwner": True}
        db.commit()
    client.post("/api/console/intel/indicators", headers=admin, json={"values": [TROJAN_SHA], "verdict": "malicious"})
    report(client, phone, [TROJAN])
    with database.session_factory()() as db:
        command = db.query(Command).filter_by(device_id=phone["deviceId"], type="app.suspend").one()
        assert json.loads(json.dumps(command.payload)) == {"package": "com.flashplayer.update", "suspended": True}
        command_id = command.id
    done = client.post(f"/api/v1/devices/{phone['deviceId']}/commands/{command_id}/complete", headers=phone["headers"],
                       json={"status": "completed", "resultJson": json.dumps({"suspended": True})})
    assert done.status_code == 200
    assert apps_view(client, admin, phone)["apps"][0]["suspended"] is True


def test_phone_app_commands_are_offered_for_phones_only(client, admin, tenant, phone):
    queued = client.post(f"/api/console/devices/{phone['deviceId']}/commands", headers=admin,
                         json={"type": "app.uninstall", "reason": "test", "payload": {"package": "com.flashplayer.update"}})
    assert queued.status_code == 200, queued.text
    pc = enroll(client, admin, tenant, hostname="ACME-PC", serial="SN-PC")
    refused = client.post(f"/api/console/devices/{pc['deviceId']}/commands", headers=admin, json={"type": "app.scan", "reason": "t"})
    assert refused.status_code == 400


def test_another_customers_phone_is_out_of_scope(client, admin, tenant, phone):
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    client.post("/api/console/users", headers=admin, json={"tenantId": other["id"], "email": "ops@other.example",
                                                           "password": "other-password-123", "role": "tenant_admin"})
    ops = login(client, "ops@other.example", "other-password-123")
    report(client, phone, [TROJAN])
    assert client.get(f"/api/console/devices/{phone['deviceId']}/mobile-apps", headers=ops).status_code in (403, 404)
    assert client.post(f"/api/console/devices/{phone['deviceId']}/mobile-apps/trust", headers=ops,
                       json={"package": "com.flashplayer.update"}).status_code in (403, 404)
    with database.session_factory()() as db:
        assert db.query(MobileApp).count() == 1
