"""Safe zones on phones: crossings raise alerts and push notifications; GPS drift at the edge and old fixes do not."""
import json
from datetime import datetime, timedelta

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from conftest import enroll

from fenrir_cloud import geofence, webpush
from fenrir_cloud.models import Geofence, utcnow

HOME = (51.5007, -0.1246)
NEAR = (51.5010, -0.1250)       # ~45 m from home: inside a 200 m zone
EDGE = (51.5027, -0.1246)       # ~222 m: just past the edge, within GPS uncertainty
AWAY = (51.5100, -0.1246)       # ~1 km away


def _iso(minutes_ago: float) -> str:
    return (utcnow() - timedelta(minutes=minutes_ago)).isoformat() + "Z"


@pytest.fixture()
def phone(client, admin, tenant):
    return enroll(client, admin, tenant, hostname="Grandmas-Phone", os_version="Android 14 (Samsung A15)", serial="A15-1")


def _report(client, phone, where, minutes_ago, accuracy=15):
    return client.post(f"/api/v1/devices/{phone['deviceId']}/location", headers=phone["headers"], json={"points": [
        {"lat": where[0], "lon": where[1], "accuracy": accuracy, "at": _iso(minutes_ago)}]}).json()


def _zone(client, admin, phone, **extra):
    body = {"name": "Home", "latitude": HOME[0], "longitude": HOME[1], "radius": 200, **extra}
    response = client.post(f"/api/console/devices/{phone['deviceId']}/geofences", headers=admin, json=body)
    assert response.status_code == 200, response.text
    return response.json()


def _alerts(client, admin, phone):
    rows = client.get("/api/console/alerts", headers=admin, params={"device_id": phone["deviceId"]}).json()
    rows = rows.get("items", rows) if isinstance(rows, dict) else rows
    return [a for a in rows if a.get("ruleId", a.get("rule_id")) == geofence.RULE]


def test_leaving_and_coming_back(client, admin, phone):
    zone = _zone(client, admin, phone)
    assert zone["state"] == "unknown"
    assert _report(client, phone, NEAR, 30)["crossings"] == []          # first fix sets the state
    zones = client.get(f"/api/console/devices/{phone['deviceId']}/geofences", headers=admin).json()["geofences"]
    assert zones[0]["state"] == "inside"

    assert _report(client, phone, EDGE, 25, accuracy=40)["crossings"] == []  # within GPS uncertainty: no change
    assert _report(client, phone, AWAY, 20)["crossings"] == [{"geofenceId": zone["id"], "crossing": "exit"}]
    alerts = _alerts(client, admin, phone)
    assert len(alerts) == 1 and alerts[0]["title"] == "Grandmas-Phone left Home" and alerts[0]["severity"] == "high"

    assert _report(client, phone, AWAY, 15)["crossings"] == []          # still out: nothing new
    assert _report(client, phone, NEAR, 10)["crossings"][0]["crossing"] == "enter"
    alerts = _alerts(client, admin, phone)
    assert len(alerts) == 1 and alerts[0]["status"] == "resolved"      # the "left" alert closes; no arrival alert


def test_imprecise_and_old_fixes_are_ignored(client, admin, phone):
    _zone(client, admin, phone)
    _report(client, phone, NEAR, 30)
    assert _report(client, phone, AWAY, 25, accuracy=2000)["crossings"] == []   # a cell-tower guess
    assert _report(client, phone, AWAY, 40)["crossings"] == []                  # older than what we know
    assert _alerts(client, admin, phone) == []


def test_arrival_alerts_and_validation(client, admin, phone):
    url = f"/api/console/devices/{phone['deviceId']}/geofences"
    assert client.post(url, headers=admin, json={"name": "", "latitude": 1, "longitude": 1}).status_code == 400
    assert client.post(url, headers=admin, json={"name": "X", "latitude": 1, "longitude": 1, "radius": 5}).status_code == 400
    assert client.post(url, headers=admin, json={"name": "X", "latitude": 1, "longitude": 1, "notify": {"users": ["usr_nobody"]}}).status_code == 400
    _zone(client, admin, phone, name="School", alertOn="enter", severity="medium")
    _report(client, phone, AWAY, 30)
    assert _report(client, phone, NEAR, 20)["crossings"][0]["crossing"] == "enter"
    alerts = _alerts(client, admin, phone)
    assert [a["title"] for a in alerts] == ["Grandmas-Phone arrived at School"] and alerts[0]["severity"] == "medium"


def test_the_phone_gets_its_zones_in_the_heartbeat(client, admin, phone):
    zone = _zone(client, admin, phone, notify={"phone": True})
    beat = client.post(f"/api/v1/devices/{phone['deviceId']}/heartbeat", headers=phone["headers"], json={}).json()
    assert beat["geofences"] == [{"id": zone["id"], "name": "Home", "lat": HOME[0], "lon": HOME[1], "radius": 200.0, "notifyPhone": True}]
    client.patch(f"/api/console/devices/{phone['deviceId']}/geofences/{zone['id']}", headers=admin, json={"enabled": False})
    beat = client.post(f"/api/v1/devices/{phone['deviceId']}/heartbeat", headers=phone["headers"], json={}).json()
    assert beat["geofences"] == []
    assert client.delete(f"/api/console/devices/{phone['deviceId']}/geofences/{zone['id']}", headers=admin).json() == {"ok": True}


def test_computers_cannot_have_zones(client, admin, device):
    response = client.post(f"/api/console/devices/{device['deviceId']}/geofences", headers=admin,
                           json={"name": "Office", "latitude": 1, "longitude": 1})
    assert response.status_code == 400


def _active(schedule, when):
    fence = Geofence(tenant_id="t", schedule=schedule)

    class Db:  # regional.get with no tenant settings falls back to UTC
        def get(self, *_):
            return None

        def execute(self, *_):
            raise AssertionError

    from fenrir_cloud import regional

    original = regional.get
    regional.get = lambda db, tenant_id: {"timeZone": "UTC"}
    try:
        return geofence.active(fence, Db(), when)
    finally:
        regional.get = original


def test_active_hours_including_overnight():
    monday_9 = datetime(2026, 11, 2, 9, 0)
    assert _active({}, monday_9)
    assert _active({"days": [0, 1, 2, 3, 4], "start": "08:00", "end": "16:00"}, monday_9)
    assert not _active({"days": [5, 6], "start": "08:00", "end": "16:00"}, monday_9)
    night = {"days": [0], "start": "22:00", "end": "07:00"}
    assert _active(night, datetime(2026, 11, 2, 23, 0))       # Monday 23:00
    assert _active(night, datetime(2026, 11, 3, 6, 0))        # into Tuesday morning
    assert not _active(night, datetime(2026, 11, 3, 23, 0))   # Tuesday night is not in the window


def test_crossings_outside_active_hours_do_not_alert(client, admin, phone):
    now = utcnow()
    closed = {"days": [(now.weekday() + 3) % 7], "start": "00:00", "end": "00:01"}
    _zone(client, admin, phone, schedule=closed)
    _report(client, phone, NEAR, 30)
    assert _report(client, phone, AWAY, 20)["crossings"] == []
    assert _alerts(client, admin, phone) == []


def _decrypt(receiver: ec.EllipticCurvePrivateKey, auth: bytes, body: bytes) -> bytes:
    salt, length = body[:16], body[20]
    server_bytes = body[21:21 + length]
    receiver_bytes = receiver.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    shared = receiver.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_bytes))
    ikm = HKDF(hashes.SHA256(), 32, auth, b"WebPush: info\x00" + receiver_bytes + server_bytes).derive(shared)
    cek = HKDF(hashes.SHA256(), 16, salt, b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(hashes.SHA256(), 12, salt, b"Content-Encoding: nonce\x00").derive(ikm)
    plain = AESGCM(cek).decrypt(nonce, body[21 + length:], None)
    assert plain.endswith(b"\x02")
    return plain[:-1]


def test_push_encryption_round_trip():
    receiver = ec.generate_private_key(ec.SECP256R1())
    auth = b"0123456789abcdef"
    p256dh = webpush.b64url(receiver.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
    body = webpush.encrypt(p256dh, webpush.b64url(auth), b'{"title":"hi"}')
    assert _decrypt(receiver, auth, body) == b'{"title":"hi"}'


def test_vapid_header_is_a_valid_es256_token():
    key = ec.generate_private_key(ec.SECP256R1())
    header = webpush.vapid_header(key, "https://fcm.googleapis.com/fcm/send/abc", "https://fenrir.test")
    token = header.split("t=")[1].split(",")[0]
    head, claims, signature = token.split(".")
    assert json.loads(webpush.unb64url(claims))["aud"] == "https://fcm.googleapis.com"
    raw = webpush.unb64url(signature)
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    key.public_key().verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                            f"{head}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))


def test_crossing_pushes_to_the_chosen_people(client, admin, phone, monkeypatch):
    receiver = ec.generate_private_key(ec.SECP256R1())
    auth = b"fedcba9876543210"
    subscription = {"endpoint": "https://push.example.net/send/abc", "keys": {
        "p256dh": webpush.b64url(receiver.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)),
        "auth": webpush.b64url(auth)}}
    assert client.post("/api/console/push/subscriptions", headers=admin, json={"subscription": subscription, "label": "My phone"}).status_code == 200
    assert client.get("/api/console/push/key", headers=admin).json()["publicKey"]
    me = client.get("/api/console/auth/me", headers=admin).json()["user"]["id"]

    sent = []

    class Response:
        status_code = 201

    def post(url, content, headers, timeout):
        sent.append((url, json.loads(_decrypt(receiver, auth, content)), headers))
        return Response()

    monkeypatch.setattr(webpush.httpx, "post", post)
    zones = client.get(f"/api/console/devices/{phone['deviceId']}/geofences", headers=admin).json()
    assert any(p["id"] == me and p["pushDevices"] == 1 for p in zones["recipients"])
    _zone(client, admin, phone, notify={"users": [me]})
    _report(client, phone, NEAR, 30)
    _report(client, phone, AWAY, 20)

    from fenrir_cloud import db, events

    with db.session_factory()() as session:
        events.process(session)
        session.commit()
    assert sent, "a push was delivered"
    url, message, headers = sent[-1]
    assert url == subscription["endpoint"] and message["title"] == "Grandmas-Phone left Home"
    assert message["url"] == f"/devices/{phone['deviceId']}?tab=location"
    assert headers["Content-Encoding"] == "aes128gcm" and headers["Authorization"].startswith("vapid t=")


def test_gone_subscriptions_are_removed(client, admin, monkeypatch):
    receiver = ec.generate_private_key(ec.SECP256R1())
    subscription = {"endpoint": "https://push.example.net/send/gone", "keys": {
        "p256dh": webpush.b64url(receiver.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)),
        "auth": webpush.b64url(b"0000000000000000")}}
    client.post("/api/console/push/subscriptions", headers=admin, json={"subscription": subscription})

    class Gone:
        status_code = 410

    monkeypatch.setattr(webpush.httpx, "post", lambda *a, **k: Gone())
    assert client.post("/api/console/push/test", headers=admin).json() == {"queued": 1}
    from fenrir_cloud import db, events

    with db.session_factory()() as session:
        events.process(session)
        session.commit()
    assert client.get("/api/console/push/subscriptions", headers=admin).json() == []
    assert client.post("/api/console/push/subscriptions", headers=admin, json={"endpoint": "http://x", "keys": {}}).status_code == 400
