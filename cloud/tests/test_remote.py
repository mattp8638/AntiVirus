import json

import pytest
from starlette.websockets import WebSocketDisconnect

from conftest import enroll


def start(client, admin, device, **extra):
    response = client.post("/api/console/remote/sessions", headers=admin, json={"deviceId": device["deviceId"], **extra})
    assert response.status_code == 200, response.text
    return response.json()


def agent_command(client, device):
    items = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]
    return next(i for i in items if i["type"] == "remote.session.start")


def test_session_relays_frames_and_input(client, admin, tenant, device):
    session = start(client, admin, device, mode="desktop")
    assert session["status"] == "waiting" and session["viewerPath"] == f"/remote/{session['id']}"
    command = agent_command(client, device)
    payload = json.loads(command["payloadJson"])
    assert payload["relayUrl"] == f"wss://fenrir.test/ws/remote/{session['id']}/agent"
    assert payload["consent"] == "when_user_present" and payload["maxFps"] == 15

    viewer = client.post(f"/api/console/remote/sessions/{session['id']}/viewer-token", headers=admin).json()
    agent_path = f"/ws/remote/{session['id']}/agent?token={payload['token']}"
    with client.websocket_connect(agent_path) as agent:
        with client.websocket_connect(f"{viewer['path']}?token={viewer['token']}") as browser:
            hello = json.loads(browser.receive_text())
            assert hello["t"] == "hello" and hello["agentConnected"] is True and hello["viewOnly"] is False
            joined = json.loads(agent.receive_text())
            assert joined["t"] == "viewer.joined" and joined["by"] == "admin@fenrir.local"
            frame = b"\x01" + b"\x00" * 8 + b"JPEGDATA"
            agent.send_bytes(frame)
            assert browser.receive_bytes() == frame
            browser.send_text(json.dumps({"ch": "input", "t": "mm", "x": 10, "y": 20}))
            assert json.loads(agent.receive_text())["t"] == "mm"
            browser.send_text(json.dumps({"ch": "files", "t": "get", "path": "C:\\Users\\jo\\report.docx"}))
            assert json.loads(agent.receive_text())["t"] == "get"
            live = client.get(f"/api/console/remote/sessions/{session['id']}", headers=admin).json()
            assert live["status"] == "connected" and live["agentConnected"]
            browser.send_text(json.dumps({"ch": "sys", "t": "end"}))
        end = json.loads(agent.receive_text())
        assert end == {"ch": "sys", "t": "end"} or end.get("t") == "end"
    detail = client.get(f"/api/console/remote/sessions/{session['id']}", headers=admin).json()
    assert detail["status"] == "ended"
    kinds = [e["type"] for e in detail["events"]]
    assert "agent.connected" in kinds and "files.get" in kinds and "ended" in kinds
    assert detail["bytesRelayed"] > 0
    logs = client.get("/api/console/audit", headers=admin).json()
    actions = {row["action"] for row in (logs["items"] if isinstance(logs, dict) else logs)}
    assert "remote.files.get" in actions and "remote.session.requested" in actions


def test_view_only_drops_input_and_bad_tokens_are_refused(client, admin, tenant, device):
    session = start(client, admin, device, viewOnly=True)
    payload = json.loads(agent_command(client, device)["payloadJson"])
    viewer = client.post(f"/api/console/remote/sessions/{session['id']}/viewer-token", headers=admin).json()
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/remote/{session['id']}/agent?token={viewer['token']}") as ws:
            ws.receive_text()
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/remote/{session['id']}/viewer?token={payload['token']}") as ws:
            ws.receive_text()
    with client.websocket_connect(f"/ws/remote/{session['id']}/agent?token={payload['token']}") as agent:
        with client.websocket_connect(f"{viewer['path']}?token={viewer['token']}") as browser:
            assert json.loads(browser.receive_text())["viewOnly"] is True
            agent.receive_text()  # viewer.joined
            browser.send_text(json.dumps({"ch": "input", "t": "kd", "code": "KeyA"}))
            browser.send_text(json.dumps({"ch": "screen", "t": "ack"}))
            # Input never arrives; the next thing the agent sees is the frame ack.
            assert json.loads(agent.receive_text())["t"] == "ack"


def test_policy_can_disable_remote_access_and_terminal(client, admin, tenant, device):
    policy_id = tenant["defaultPolicyId"]
    response = client.put(f"/api/console/policies/{policy_id}", headers=admin,
                            json={"settings": {"remoteAccess": {"allowTerminal": False}}})
    assert response.status_code == 200, response.text
    blocked = client.post("/api/console/remote/sessions", headers=admin, json={"deviceId": device["deviceId"], "mode": "terminal"})
    assert blocked.status_code == 403 and "terminal" in blocked.text
    session = start(client, admin, device)
    payload = json.loads(agent_command(client, device)["payloadJson"])
    viewer = client.post(f"/api/console/remote/sessions/{session['id']}/viewer-token", headers=admin).json()
    with client.websocket_connect(f"/ws/remote/{session['id']}/agent?token={payload['token']}") as agent:
        with client.websocket_connect(f"{viewer['path']}?token={viewer['token']}") as browser:
            assert json.loads(browser.receive_text())["allowTerminal"] is False
            agent.receive_text()
            browser.send_text(json.dumps({"ch": "term", "t": "open"}))
            browser.send_text(json.dumps({"ch": "screen", "t": "ack"}))
            assert json.loads(agent.receive_text())["ch"] == "screen"
    client.put(f"/api/console/policies/{policy_id}", headers=admin, json={"settings": {"remoteAccess": {"enabled": False}}})
    assert client.post("/api/console/remote/sessions", headers=admin, json={"deviceId": device["deviceId"]}).status_code == 403


def test_end_session_logs_time_to_ticket(client, admin, tenant, device):
    ticket = client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "Outlook crashing"}).json()
    session = start(client, admin, device, ticketId=ticket["id"])
    payload = json.loads(agent_command(client, device)["payloadJson"])
    with client.websocket_connect(f"/ws/remote/{session['id']}/agent?token={payload['token']}"):
        pass
    result = client.post(f"/api/console/remote/sessions/{session['id']}/end", headers=admin,
                         json={"logTime": True, "notes": "Repaired Office install"}).json()
    assert result["session"]["status"] == "ended"
    assert result["timeEntry"]["remoteSessionId"] == session["id"] and result["timeEntry"]["hours"] > 0
    detail = client.get(f"/api/console/tickets/{ticket['id']}", headers=admin).json()
    assert detail["timeEntries"] and any("Repaired Office" in c["text"] for c in detail["comments"])


def test_realtime_channel_wakes_agent_on_new_command(client, admin, tenant, device):
    path = f"/api/v1/devices/{device['deviceId']}/realtime"
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(path, headers={"X-Device-Api-Key": "wrong"}) as ws:
            ws.receive_text()
    with client.websocket_connect(path, headers=device["headers"]) as ws:
        assert json.loads(ws.receive_text())["type"] == "hello"
        ws.send_text("ping")
        assert ws.receive_text() == "pong"
        client.post(f"/api/console/devices/{device['deviceId']}/commands", headers=admin, json={"type": "inventory.refresh"})
        assert json.loads(ws.receive_text()) == {"type": "commands"}
        sessions = client.get("/api/console/remote/sessions", headers=admin, params={"deviceId": device["deviceId"]}).json()
        assert sessions == []


def test_other_tenants_cannot_connect(client, admin, tenant, device):
    from conftest import login

    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Co", "template": "balanced"}).json()
    client.post("/api/console/users", headers=admin, json={"email": "tech@other.test", "password": "a-long-password-2", "name": "T",
                                                           "role": "tenant_admin", "tenantId": other["id"]})
    outsider = login(client, "tech@other.test", "a-long-password-2")
    response = client.post("/api/console/remote/sessions", headers=outsider, json={"deviceId": device["deviceId"]})
    assert response.status_code == 404
    session = start(client, admin, device)
    assert client.post(f"/api/console/remote/sessions/{session['id']}/viewer-token", headers=outsider).status_code == 404
    linux = enroll(client, admin, tenant, hostname="lx", os_version="Ubuntu 24.04", serial="LX")
    assert start(client, admin, linux, mode="terminal")["mode"] == "terminal"
