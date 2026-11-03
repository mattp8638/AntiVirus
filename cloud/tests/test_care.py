"""Looked-after phones: SOS, gone quiet, low battery, location off, acknowledgement, escalation, tracking levels and the
carer role (which reaches only the Care page)."""
from datetime import timedelta

import pytest

from conftest import enroll, login

from fenrir_cloud import care, db, webpush
from fenrir_cloud.models import Device, utcnow

PASSWORD = "carer-password-123"


@pytest.fixture()
def phone(client, admin, tenant):
    return enroll(client, admin, tenant, hostname="Nans-Phone", os_version="Android 14 (Samsung A15)", serial="A15-9")


@pytest.fixture()
def pushes(monkeypatch):
    sent = []
    monkeypatch.setattr(webpush, "notify_users", lambda db, users, title, body, url="/", tag="", tenant_id=None: sent.append((sorted(users), title)) or len(users))
    return sent


@pytest.fixture()
def carer(client, admin, tenant):
    user = client.post("/api/console/users", headers=admin, json={"email": "daughter@example.com", "name": "Daughter", "role": "carer",
                                                                 "tenantId": tenant["id"], "password": PASSWORD})
    assert user.status_code == 200, user.text
    return {"id": user.json()["id"], "headers": login(client, "daughter@example.com", PASSWORD)}


def _care(client, admin, phone, **body):
    response = client.put(f"/api/console/devices/{phone['deviceId']}/care", headers=admin, json=body)
    assert response.status_code == 200, response.text
    return response.json()


def _beat(client, phone, **metrics):
    return client.post(f"/api/v1/devices/{phone['deviceId']}/heartbeat", headers=phone["headers"], json={"metrics": metrics}).json()


def _tick():
    with db.session_factory()() as session:
        care.tick(session)
        session.commit()


def _age(phone, minutes):
    with db.session_factory()() as session:
        device = session.get(Device, phone["deviceId"])
        device.last_seen_at = utcnow() - timedelta(minutes=minutes)
        session.commit()


def test_tracking_levels_reach_the_phone(client, admin, phone):
    assert _beat(client, phone)["tracking"] == {"mode": "default", "intervalSeconds": 900, "adaptive": False, "sos": False}
    _care(client, admin, phone)
    assert _beat(client, phone)["tracking"]["mode"] == "standard"
    _care(client, admin, phone, tracking="close")
    assert _beat(client, phone)["tracking"] == {"mode": "close", "intervalSeconds": 60, "adaptive": True, "sos": False}
    _care(client, admin, phone, tracking="saver")
    assert _beat(client, phone)["tracking"]["intervalSeconds"] == 900
    assert client.put(f"/api/console/devices/{phone['deviceId']}/care", headers=admin, json={"tracking": "fast"}).status_code == 400
    assert client.put(f"/api/console/devices/{phone['deviceId']}/care", headers=admin, json={"quietMinutes": 3}).status_code == 400


def test_sos_alerts_tracks_closely_and_ends_on_acknowledge(client, admin, phone, carer, pushes):
    _care(client, admin, phone, carers=[carer["id"]])
    sos = client.post(f"/api/v1/devices/{phone['deviceId']}/sos", headers=phone["headers"],
                      json={"lat": 51.5007, "lon": -0.1246, "accuracy": 12}).json()
    assert sos["sos"] is True and sos["alertId"]
    assert pushes[-1] == ([carer["id"]], "Nans-Phone asked for help")
    assert _beat(client, phone)["tracking"] == {"mode": "close", "intervalSeconds": 60, "adaptive": False, "sos": True}

    people = client.get("/api/console/care/people", headers=carer["headers"]).json()
    assert [p["name"] for p in people] == ["Nans-Phone"] and people[0]["sos"]["active"]
    assert people[0]["latest"]["lat"] == 51.5007 and people[0]["alerts"][0]["severity"] == "critical"
    assert "care" not in people[0]  # carers see the person, not the settings

    ack = client.post(f"/api/console/care/alerts/{sos['alertId']}/ack", headers=carer["headers"], json={}).json()
    assert ack["acknowledgedBy"] == "daughter@example.com" and ack["status"] == "triaged"
    assert _beat(client, phone)["tracking"]["sos"] is False


def test_the_person_can_say_they_are_ok(client, admin, phone, carer, pushes):
    _care(client, admin, phone, carers=[carer["id"]])
    client.post(f"/api/v1/devices/{phone['deviceId']}/sos", headers=phone["headers"], json={})
    assert client.post(f"/api/v1/devices/{phone['deviceId']}/sos", headers=phone["headers"], json={"cancel": True}).json() == {"sos": False}
    assert pushes[-1][1] == "Nans-Phone is OK"
    people = client.get("/api/console/care/people", headers=carer["headers"]).json()
    assert people[0]["alerts"] == [] and not people[0]["sos"]["active"]


def test_quiet_battery_and_location_off(client, admin, phone, carer, pushes):
    _care(client, admin, phone, carers=[carer["id"]], quietMinutes=20, lowBattery=15)
    _age(phone, 30)
    _tick()
    _tick()  # one alert, not one a minute
    titles = [a["title"] for a in client.get("/api/console/care/people", headers=carer["headers"]).json()[0]["alerts"]]
    assert titles == ["Nans-Phone has gone quiet"]
    _beat(client, phone, batteryPercent=12, charging=False, locationEnabled=False)
    titles = sorted(a["title"] for a in client.get("/api/console/care/people", headers=carer["headers"]).json()[0]["alerts"])
    assert titles == ["Location is turned off on Nans-Phone", "Nans-Phone's battery is low (12%)"]  # quiet cleared by the check-in
    _beat(client, phone, batteryPercent=13, charging=True, locationEnabled=True)
    assert client.get("/api/console/care/people", headers=carer["headers"]).json()[0]["alerts"] == []
    assert [t for _, t in pushes] == ["Nans-Phone has gone quiet", "Nans-Phone's battery is low (12%)", "Location is turned off on Nans-Phone"]


def test_unacknowledged_alerts_escalate_once(client, admin, phone, carer, pushes):
    me = client.get("/api/console/auth/me", headers=admin).json()["user"]["id"]
    _care(client, admin, phone, carers=[carer["id"]], escalateAfter=10, escalateTo=[me])
    sos = client.post(f"/api/v1/devices/{phone['deviceId']}/sos", headers=phone["headers"], json={}).json()
    _tick()
    assert all(not t.startswith("Nobody has responded") for _, t in pushes)
    from fenrir_cloud.models import Alert

    with db.session_factory()() as session:
        session.get(Alert, sos["alertId"]).created_at = utcnow() - timedelta(minutes=11)
        session.commit()
    _tick()
    _tick()
    escalations = [(u, t) for u, t in pushes if t.startswith("Nobody has responded")]
    assert escalations == [([me], "Nobody has responded: Nans-Phone asked for help")]


def test_carers_reach_only_the_care_page(client, admin, tenant, phone, carer, device):
    _care(client, admin, phone, carers=[carer["id"]])
    headers = carer["headers"]
    assert client.get("/api/console/devices", headers=headers).status_code == 403
    assert client.get("/api/console/alerts", headers=headers).status_code == 403
    assert client.get(f"/api/console/devices/{phone['deviceId']}/locations", headers=headers).status_code == 403
    assert client.get("/api/console/auth/me", headers=headers).status_code == 200
    assert client.get("/api/console/push/key", headers=headers).status_code == 200
    assert client.get(f"/api/console/care/people/{phone['deviceId']}/locations", headers=headers).status_code == 200
    # Only phones with care set up, never computers, and only their own customer.
    assert [p["id"] for p in client.get("/api/console/care/people", headers=headers).json()] == [phone["deviceId"]]
    assert client.get(f"/api/console/care/people/{device['deviceId']}/locations", headers=headers).status_code == 404
    assert client.post(f"/api/console/care/people/{phone['deviceId']}/locate", headers=headers).status_code == 200


def test_carers_of_another_customer_see_nothing(client, admin, phone, pushes):
    other = client.post("/api/console/tenants", json={"name": "Other family", "template": "balanced"}, headers=admin).json()
    client.post("/api/console/users", headers=admin, json={"email": "stranger@example.com", "role": "carer", "tenantId": other["id"],
                                                           "password": PASSWORD})
    stranger = login(client, "stranger@example.com", PASSWORD)
    _care(client, admin, phone)
    assert client.get("/api/console/care/people", headers=stranger).json() == []
    assert client.get(f"/api/console/care/people/{phone['deviceId']}/locations", headers=stranger).status_code == 404
    me = client.get("/api/console/auth/me", headers=stranger).json()["user"]["id"]
    assert client.put(f"/api/console/devices/{phone['deviceId']}/care", headers=admin, json={"carers": [me]}).status_code == 400
