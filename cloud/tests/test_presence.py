"""One rule for whether a device is up, used by every page; live-connection pings count as check-ins."""

from datetime import timedelta

from conftest import enroll
from fenrir_cloud import db as database
from fenrir_cloud import presence
from fenrir_cloud.models import Device, utcnow


def seen(device_id, ago: timedelta | None):
    with database.session_factory()() as db:
        db.get(Device, device_id).last_seen_at = None if ago is None else utcnow() - ago
        db.commit()


def listed(client, admin, status):
    return {d["hostname"]: d["presence"] for d in client.get("/api/console/devices", headers=admin, params={"status": status}).json()}


def test_agents_are_online_for_two_minutes_and_phones_sleep_before_going_offline():
    now = utcnow()
    pc = Device(id="d1", hostname="pc", platform="windows", api_key_hash="h1", dns_token="t1", tenant_id="x")
    phone = Device(id="d2", hostname="phone", platform="android", api_key_hash="h2", dns_token="t2", tenant_id="x")
    iphone = Device(id="d3", hostname="iphone", platform="ios", api_key_hash="profile-x", dns_token="t3", tenant_id="x",
                    metrics={"agentless": True})
    for device, ago, expected in [(pc, 90, "online"), (pc, 150, "offline"), (phone, 90, "online"), (phone, 20 * 60, "asleep"),
                                  (phone, 31 * 60, "offline"), (iphone, 10 * 60, "online"), (iphone, 16 * 60, "idle")]:
        device.last_seen_at = now - timedelta(seconds=ago)
        assert presence.state(device, now) == expected, (device.hostname, ago)
    pc.api_key_hash = "retired-d1"
    assert presence.state(pc, now) == "retired"
    pc.api_key_hash, pc.last_seen_at = "h1", None
    assert presence.state(pc, now) == "offline" and not presence.is_up(pc, now)


def test_every_list_and_total_uses_the_same_rule(client, admin, tenant):
    pc = enroll(client, admin, tenant, hostname="PC-1", serial="S1")
    quiet = enroll(client, admin, tenant, hostname="PC-2", serial="S2")
    phone = enroll(client, admin, tenant, hostname="Pixel", os_version="Android 15", serial="P1")
    seen(pc["deviceId"], timedelta(seconds=30))
    seen(quiet["deviceId"], timedelta(minutes=5))
    seen(phone["deviceId"], timedelta(minutes=12))  # in Doze between wake-ups
    assert listed(client, admin, "online") == {"PC-1": "online", "Pixel": "asleep"}
    assert listed(client, admin, "offline") == {"PC-2": "offline"}
    detail = client.get(f"/api/console/devices/{phone['deviceId']}", headers=admin).json()["device"]
    assert detail["online"] is True and detail["presence"] == "asleep"
    assert client.get("/api/console/protection/health", headers=admin).json()["totals"]["online"] == 2


def test_a_ping_on_the_live_connection_is_a_check_in(client, admin, tenant):
    pc = enroll(client, admin, tenant)
    with client.websocket_connect(f"/api/v1/devices/{pc['deviceId']}/realtime", headers={"X-Device-Api-Key": pc["deviceApiKey"]}) as ws:
        assert ws.receive_json()["type"] == "hello"
        seen(pc["deviceId"], timedelta(minutes=5))  # as if the last heartbeat was a while ago
        # The connection itself wrote a check-in when it opened; the first ping after TOUCH_EVERY writes again.
        presence_window = presence.TOUCH_EVERY
        presence.TOUCH_EVERY = timedelta(0)
        try:
            ws.send_text("ping")
            assert ws.receive_text() == "pong"
            ws.send_text("ping")
            assert ws.receive_text() == "pong"
        finally:
            presence.TOUCH_EVERY = presence_window
    with database.session_factory()() as db:
        assert utcnow() - db.get(Device, pc["deviceId"]).last_seen_at < timedelta(seconds=30)


def test_check_ins_are_written_at_most_every_twenty_seconds():
    device = Device(id="d1", hostname="pc", platform="windows", api_key_hash="h", dns_token="t", tenant_id="x")
    now = utcnow()
    assert presence.touch(device, now) is True
    assert presence.touch(device, now + timedelta(seconds=5)) is False
    assert presence.touch(device, now + timedelta(seconds=25)) is True and device.last_seen_at == now + timedelta(seconds=25)
