"""Direct (peer-to-peer) remote sessions: the server's own STUN responder, ICE settings, and the relay passing set-up."""

import ipaddress
import json
import socket
import struct

from fenrir_cloud import remote, stun


def _request(transaction=b"0123456789ab"):
    return struct.pack("!HHI", stun.BINDING_REQUEST, 0, stun.MAGIC) + transaction


def _mapped(reply):
    kind, length, cookie = struct.unpack("!HHI", reply[:8])
    assert kind == stun.BINDING_SUCCESS and cookie == stun.MAGIC
    attr, size = struct.unpack("!HH", reply[20:24])
    assert attr == stun.XOR_MAPPED_ADDRESS
    family, port = reply[25], struct.unpack("!H", reply[26:28])[0] ^ (stun.MAGIC >> 16)
    if family == 1:
        return str(ipaddress.IPv4Address(struct.unpack("!I", reply[28:32])[0] ^ stun.MAGIC)), port
    mask = struct.pack("!I", stun.MAGIC) + reply[8:20]
    return str(ipaddress.IPv6Address(bytes(a ^ b for a, b in zip(reply[28:44], mask)))), port


def test_binding_response_reflects_the_senders_address():
    assert _mapped(stun.response(_request(), ("203.0.113.7", 54321))) == ("203.0.113.7", 54321)
    assert _mapped(stun.response(_request(), ("2001:db8::5", 4000))) == ("2001:db8::5", 4000)
    assert _mapped(stun.response(_request(), ("::ffff:198.51.100.2", 9))) == ("198.51.100.2", 9)
    assert stun.response(b"junk", ("1.2.3.4", 1)) is None
    assert stun.response(struct.pack("!HHI", 0x0111, 0, stun.MAGIC) + b"x" * 12, ("1.2.3.4", 1)) is None  # not a request


def test_the_udp_server_answers(monkeypatch):
    import asyncio

    async def run():
        transport = await stun.serve(0, "127.0.0.1")
        port = transport.get_extra_info("sockname")[1]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.sendto(_request(), ("127.0.0.1", port))
        loop = asyncio.get_running_loop()
        data = await asyncio.wait_for(loop.sock_recv(sock, 512), 3)
        transport.close()
        sock.close()
        return data, sock

    data, _ = asyncio.run(run())
    host, _ = _mapped(data)
    assert host == "127.0.0.1"


def test_ice_servers_point_at_this_server(monkeypatch):
    monkeypatch.setenv("FENRIR_STUN_PORT", "3478")
    assert stun.ice_servers("https://rmm.example.com") == [{"urls": ["stun:rmm.example.com:3478"]}]
    assert stun.ice_servers("http://127.0.0.1:8080") == []
    monkeypatch.setenv("FENRIR_STUN_PORT", "0")
    assert stun.ice_servers("https://rmm.example.com") == []


def test_sessions_offer_direct_unless_recorded(client, admin, device):
    started = client.post("/api/console/remote/sessions", headers=admin, json={"deviceId": device["deviceId"], "mode": "desktop"})
    assert started.status_code == 200, started.text
    pending = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]
    payload = json.loads(next(c for c in pending if c["type"] == "remote.session.start")["payloadJson"])
    assert payload["direct"] is True and payload["iceServers"] == [{"urls": ["stun:fenrir.test:3478"]}]
    token = client.post(f"/api/console/remote/sessions/{started.json()['id']}/viewer-token", headers=admin).json()
    assert token["iceServers"] == payload["iceServers"]


def test_relay_passes_connection_setup_but_mode_rules_still_apply():
    hub = remote.RelayHub()
    desktop = remote.Room(session_id="s1", view_only=False, allow={}, mode="desktop")
    assert hub.filter_viewer_message(desktop, json.dumps({"ch": "rtc", "t": "offer", "sdp": "v=0"}))[0] is True
    tunnel = remote.Room(session_id="s2", view_only=False, allow={}, mode="tunnel")
    assert hub.filter_viewer_message(tunnel, json.dumps({"ch": "rtc", "t": "offer", "sdp": "v=0"}))[0] is False
