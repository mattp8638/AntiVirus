"""Zero-trust remote administration: backstage sessions, tunnels to agentless devices, Intel AMT and session routing."""

import hashlib
import json
import re

import httpx
import pytest

from conftest import enroll
from test_documentation_vault import stepup
from test_remote import agent_command
from fenrir_cloud import amt
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import Command, NetworkNode


def set_remote_policy(client, admin, tenant, **settings):
    response = client.put(f"/api/console/policies/{tenant['defaultPolicyId']}", headers=admin, json={"settings": {"remoteAccess": settings}})
    assert response.status_code == 200, response.text


def test_backstage_is_silent_gated_and_recorded(client, admin, tenant, device):
    body = {"deviceId": device["deviceId"], "mode": "backstage", "reason": "Clear the print queue"}
    assert client.post("/api/console/remote/sessions", headers=stepup(client, admin), json=body).status_code == 403  # policy off
    set_remote_policy(client, admin, tenant, backstage="on")
    assert client.post("/api/console/remote/sessions", headers=admin, json=body).json()["detail"] == "reauth_required"
    proof = stepup(client, admin)
    assert client.post("/api/console/remote/sessions", headers=proof, json={**body, "reason": "x"}).status_code == 422
    response = client.post("/api/console/remote/sessions", headers=proof, json=body)
    assert response.status_code == 200, response.text
    session = response.json()
    assert session["consent"] == "not_required" and session["recorded"] is True
    payload = json.loads(agent_command(client, device)["payloadJson"])
    assert payload["mode"] == "backstage" and payload["consent"] == "never" and payload["showBanner"] is False

    viewer = client.post(f"/api/console/remote/sessions/{session['id']}/viewer-token", headers=admin).json()
    with client.websocket_connect(f"/ws/remote/{session['id']}/agent?token={payload['token']}") as agent:
        with client.websocket_connect(f"{viewer['path']}?token={viewer['token']}") as browser:
            assert json.loads(browser.receive_text())["mode"] == "backstage"
            agent.receive_text()  # viewer.joined
            for blocked in ({"ch": "screen", "t": "start"}, {"ch": "input", "t": "kd", "code": "KeyA"}, {"ch": "chat", "t": "msg", "text": "hi"}):
                browser.send_text(json.dumps(blocked))
            browser.send_text(json.dumps({"ch": "term", "t": "open", "cols": 80, "rows": 24}))
            assert json.loads(agent.receive_text()) == {"ch": "term", "t": "open", "cols": 80, "rows": 24}  # the others never arrived
            browser.send_text(json.dumps({"ch": "sys", "t": "end"}))
        agent.receive_text()


def test_tunnel_reaches_only_allowed_private_targets(client, admin, tenant, device):
    with session_factory()() as db:
        node = NetworkNode(tenant_id=tenant["id"], key="ip:192.168.10.50", ip="192.168.10.50", subnet="192.168.10.0/24", kind="server", open_ports=[3389, 445],
                           seen_by=[device["deviceId"]])
        db.add(node)
        db.commit()
        node_id = node.id
    proof = stepup(client, admin)
    body = {"deviceId": device["deviceId"], "mode": "tunnel", "targetNodeId": node_id, "targetPort": 3389, "reason": "RDP to the file server"}
    assert client.post("/api/console/remote/sessions", headers=proof, json=body).status_code == 403  # tunnels off by default
    set_remote_policy(client, admin, tenant, allowTunnels=True)
    public = {**body, "targetNodeId": None, "targetHost": "8.8.8.8"}
    assert client.post("/api/console/remote/sessions", headers=proof, json=public).status_code == 422
    assert client.post("/api/console/remote/sessions", headers=proof, json={**body, "targetPort": 445}).status_code == 403
    session = client.post("/api/console/remote/sessions", headers=proof, json=body).json()
    payload = json.loads(agent_command(client, device)["payloadJson"])
    assert (payload["targetHost"], payload["targetPort"], payload["showBanner"]) == ("192.168.10.50", 3389, False)

    viewer = client.post(f"/api/console/remote/sessions/{session['id']}/viewer-token", headers=admin).json()
    with client.websocket_connect(f"/ws/remote/{session['id']}/agent?token={payload['token']}") as agent:
        with client.websocket_connect(f"{viewer['path']}?token={viewer['token']}") as browser:
            assert json.loads(browser.receive_text())["target"] == "192.168.10.50:3389"
            agent.receive_text()
            browser.send_text(json.dumps({"ch": "term", "t": "open"}))  # a tunnel carries nothing else
            browser.send_bytes(b"\x03\x00\x00\x00\x01upload")
            browser.send_text(json.dumps({"ch": "tunnel", "t": "open", "id": 1}))
            assert json.loads(agent.receive_text()) == {"ch": "tunnel", "t": "open", "id": 1}
            browser.send_bytes(b"\x05\x00\x00\x00\x01rdp-bytes")
            assert agent.receive_bytes() == b"\x05\x00\x00\x00\x01rdp-bytes"
            agent.send_bytes(b"\x05\x00\x00\x00\x01reply")
            assert browser.receive_bytes() == b"\x05\x00\x00\x00\x01reply"
            browser.send_text(json.dumps({"ch": "sys", "t": "end"}))
        agent.receive_text()
    events = client.get(f"/api/console/remote/sessions/{session['id']}", headers=admin).json()["events"]
    assert "tunnel.open" in {e["type"] for e in events}


class FakeAmt:
    """An AMT engine: HTTP Digest (MD5, qop=auth) and the few WS-Management calls Fenrir makes."""

    realm, password = "Digest:ABC123", "Amt-P4ssw0rd!"

    def __init__(self):
        self.power = 8
        self.actions = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Digest ") or not self._valid(request, auth):
            return httpx.Response(401, headers={"WWW-Authenticate": f'Digest realm="{self.realm}", nonce="n0nce", qop="auth", stale="false"'})
        body = request.content.decode()
        if "<wsmid:Identify/>" in body:
            return httpx.Response(200, text=self._wrap("<wsmid:IdentifyResponse xmlns:wsmid='x'><wsmid:ProductVersion>AMT 16.1</wsmid:ProductVersion></wsmid:IdentifyResponse>"))
        if "RequestPowerStateChange_INPUT" in body:
            state = int(re.search(r"<p:PowerState>(\d+)</p:PowerState>", body).group(1))
            self.actions.append(state)
            self.power = 2 if state in (2, 5, 10) else 8
            return httpx.Response(200, text=self._wrap("<g:RequestPowerStateChange_OUTPUT xmlns:g='x'><g:ReturnValue>0</g:ReturnValue></g:RequestPowerStateChange_OUTPUT>"))
        if "CIM_AssociatedPowerManagementService" in body:
            return httpx.Response(200, text=self._wrap(f"<e:EnumerateResponse xmlns:e='x'><w:Items xmlns:w='y'><h:CIM_AssociatedPowerManagementService xmlns:h='z'>"
                                                       f"<h:PowerState>{self.power}</h:PowerState></h:CIM_AssociatedPowerManagementService></w:Items></e:EnumerateResponse>"))
        if "AMT_GeneralSettings" in body:
            return httpx.Response(200, text=self._wrap("<g:AMT_GeneralSettings xmlns:g='x'><g:HostName>acme-ws-01</g:HostName><g:DomainName>acme.lan</g:DomainName></g:AMT_GeneralSettings>"))
        return httpx.Response(400, text=self._wrap("<f:Fault xmlns:f='x'><f:Text>unsupported</f:Text></f:Fault>"))

    def _valid(self, request, header):
        fields = dict(re.findall(r'(\w+)="?([^",]+)"?', header[len("Digest "):]))
        md5 = lambda text: hashlib.md5(text.encode()).hexdigest()  # noqa: E731 - RFC 2617 test oracle
        ha1 = md5(f"{fields['username']}:{self.realm}:{self.password}")
        ha2 = md5(f"POST:{fields['uri']}")
        return fields["response"] == md5(f"{ha1}:{fields['nonce']}:{fields['nc']}:{fields['cnonce']}:{fields['qop']}:{ha2}")

    @staticmethod
    def _wrap(inner):
        return f"<?xml version='1.0'?><a:Envelope xmlns:a='http://www.w3.org/2003/05/soap-envelope'><a:Header/><a:Body>{inner}</a:Body></a:Envelope>"


@pytest.fixture
def fake_amt(monkeypatch):
    fake = FakeAmt()
    monkeypatch.setattr(amt, "http_client", lambda endpoint: httpx.Client(transport=httpx.MockTransport(fake)))
    return fake


def test_amt_direct_check_and_power(client, admin, tenant, device, fake_amt):
    body = {"tenantId": tenant["id"], "name": "ACME-WS-01 vPro", "host": "192.168.10.21", "port": 16992, "route": "direct",
            "deviceId": device["deviceId"], "password": FakeAmt.password}
    assert client.post("/api/console/oob/amt", headers=admin, json=body).json()["detail"] == "reauth_required"
    endpoint = client.post("/api/console/oob/amt", headers=stepup(client, admin), json=body).json()
    assert endpoint["hasPassword"] and "password" not in json.dumps(endpoint).lower().replace("haspassword", "")
    checked = client.post(f"/api/console/oob/amt/{endpoint['id']}/check", headers=admin).json()
    assert checked["version"] == "AMT 16.1" and checked["powerState"] == "off"
    assert checked["endpoint"]["status"] == "online" and checked["endpoint"]["settings"]["hostName"] == "acme-ws-01"
    on = client.post(f"/api/console/oob/amt/{endpoint['id']}/power", headers=admin, json={"action": "on"}).json()
    assert on["result"] == "completed" and on["powerState"] == "on" and fake_amt.actions == [2]
    assert client.post(f"/api/console/oob/amt/{endpoint['id']}/power", headers=admin, json={"action": "explode"}).status_code == 422

    client.patch(f"/api/console/oob/amt/{endpoint['id']}", headers=stepup(client, admin), json={"password": "wrong"})
    failed = client.post(f"/api/console/oob/amt/{endpoint['id']}/check", headers=admin).json()
    assert failed["error"] and failed["endpoint"]["status"] == "auth_failed"
    routes = client.get("/api/console/remote/routes", params={"device_id": device["deviceId"]}, headers=admin).json()
    assert [r["kind"] for r in routes][:1] == ["agent"] and any(r["kind"] == "amt" for r in routes)


def test_amt_through_an_agent_never_puts_the_password_in_the_command(client, admin, tenant, device, fake_amt):
    other = enroll(client, admin, tenant, hostname="ACME-WS-09", serial="OOB-9")
    endpoint = client.post("/api/console/oob/amt", headers=stepup(client, admin), json={
        "tenantId": tenant["id"], "host": "192.168.10.22", "route": "agent", "probeDeviceId": device["deviceId"],
        "password": FakeAmt.password}).json()
    queued = client.post(f"/api/console/oob/amt/{endpoint['id']}/check", headers=admin).json()
    assert queued["queued"] and queued["endpoint"]["status"] == "pending"
    items = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]
    command = next(i for i in items if i["type"] == "amt.wsman")
    assert FakeAmt.password not in command["payloadJson"] and "Identify" in command["payloadJson"]

    # Only the device the command went to gets the credential, and only once.
    url = f"/api/v1/devices/{{}}/commands/{command['id']}/amt-credential"
    assert client.post(url.format(other["deviceId"]), headers=other["headers"]).status_code == 404
    creds = client.post(url.format(device["deviceId"]), headers=device["headers"]).json()
    assert creds == {"host": "192.168.10.22", "port": 16992, "tls": False, "tlsInsecure": False, "username": "admin", "password": FakeAmt.password}
    assert client.post(url.format(device["deviceId"]), headers=device["headers"]).status_code == 404

    # The agent performs the calls with digest auth and returns the raw responses.
    requests = json.loads(command["payloadJson"])["requests"]
    with httpx.Client(transport=httpx.MockTransport(fake_amt)) as http:
        responses = [{"name": r["name"], "status": 200, "body": http.post("http://192.168.10.22:16992/wsman", content=r["body"].encode(),
                                                                         auth=httpx.DigestAuth("admin", FakeAmt.password)).text} for r in requests]
    done = client.post(f"/api/v1/devices/{device['deviceId']}/commands/{command['id']}/complete", headers=device["headers"],
                       json={"status": "completed", "resultJson": json.dumps({"responses": responses})})
    assert done.status_code == 200, done.text
    view = next(e for e in client.get("/api/console/oob/amt", headers=admin).json() if e["id"] == endpoint["id"])
    assert view["status"] == "online" and view["amtVersion"] == "AMT 16.1" and view["powerState"] == "off"
    assert client.post(f"/api/console/devices/{device['deviceId']}/commands", headers=admin,
                       json={"type": "amt.wsman", "payload": {}}).status_code == 400  # never issued by hand
    with session_factory()() as db:
        assert db.get(Command, command["id"]).payload.get("credentialReleased")


def test_routes_for_an_agentless_node(client, admin, tenant, device):
    set_remote_policy(client, admin, tenant, allowTunnels=True)
    with session_factory()() as db:
        node = NetworkNode(tenant_id=tenant["id"], key="ip:192.168.10.60", ip="192.168.10.60", subnet="192.168.10.0/24", kind="server",
                           open_ports=[22, 16993, 9100], seen_by=[device["deviceId"]])
        db.add(node)
        db.commit()
        node_id = node.id
    routes = client.get("/api/console/remote/routes", params={"node_id": node_id}, headers=admin).json()
    tunnel = next(r for r in routes if r["kind"] == "tunnel")
    assert tunnel["available"] and tunnel["via"] == "ACME-WS-01" and {p["port"] for p in tunnel["ports"]} == {22, 16993}
    suggestion = next(r for r in routes if r["kind"] == "amt")
    assert suggestion["suggestHost"] == "192.168.10.60" and suggestion["suggestPort"] == 16993 and not suggestion["available"]
