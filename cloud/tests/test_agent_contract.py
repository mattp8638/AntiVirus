"""The control-plane contract the shipped Windows agent depends on (ControlPlaneClient.cpp)."""

import json
from urllib.parse import parse_qs, urlparse

from conftest import enroll

WINDOWS_POLICY_KEYS = {
    "id", "name", "revision", "realtimeProtection", "cloudLookup", "scriptInspection", "networkContainment",
    "quarantineOnMalicious", "scanMaliciousBlockThreshold", "realtimeExecuteBlockThreshold", "suppressionPathRoots",
    "destinationProtectionEnabled", "phishingBlockThreshold",
}


def test_enroll_returns_what_the_windows_agent_requires(client, device):
    for key in ("deviceId", "issuedAt", "commandChannelUrl", "policy"):
        assert device[key]
    # The Windows agent pulls its key out of the command channel URL's query string.
    key = parse_qs(urlparse(device["commandChannelUrl"]).query)["deviceApiKey"][0]
    assert key == device["deviceApiKey"]
    assert WINDOWS_POLICY_KEYS <= set(device["policy"])
    assert device["approved"] is True


def test_open_enrollment_lands_in_unassigned_pending(client, admin):
    response = client.post("/api/v1/enroll", json={"hostname": "STRAY-01", "osVersion": "Ubuntu 22.04", "serialNumber": ""})
    assert response.status_code == 200
    assert response.json()["approved"] is False
    pending = client.get("/api/console/devices?status=pending", headers=admin).json()
    assert [d["hostname"] for d in pending] == ["STRAY-01"]
    assert pending[0]["platform"] == "linux"


def test_bad_enrollment_token_rejected(client):
    response = client.post("/api/v1/enroll", json={"hostname": "x"}, headers={"X-Fenrir-Token": "fet_nope"})
    assert response.status_code == 403


def test_heartbeat_policy_and_device_auth(client, device):
    url = f"/api/v1/devices/{device['deviceId']}"
    assert client.post(f"{url}/heartbeat", json={}).status_code == 401
    assert client.post(f"{url}/heartbeat", json={}, headers={"X-Device-Api-Key": "wrong"}).status_code == 401
    beat = client.post(f"{url}/heartbeat", json={"agentVersion": "1.4.0", "platformVersion": "1.4.0", "healthState": "healthy",
                                                 "isolated": False}, headers=device["headers"]).json()
    assert beat["effectivePolicyRevision"] == device["policy"]["revision"]
    assert beat["commandsPending"] == 0
    check = client.post(f"{url}/policy-check-in", json={"currentPolicyRevision": device["policy"]["revision"]},
                        headers=device["headers"]).json()
    assert check["changed"] is False
    assert set(check) == {"retrievedAt", "changed", "policy"}


def test_command_round_trip(client, admin, device):
    issued = client.post(f"/api/console/devices/{device['deviceId']}/commands",
                         json={"type": "scan.targeted", "targetPath": "C:\\Users\\Public"}, headers=admin)
    assert issued.status_code == 200, issued.text
    url = f"/api/v1/devices/{device['deviceId']}"
    polled = client.get(f"{url}/commands/pending?limit=10", headers=device["headers"]).json()
    item = polled["items"][0]
    assert {"id", "type", "issuedBy", "createdAt", "updatedAt", "targetPath", "recordId", "payloadJson"} <= set(item)
    assert item["type"] == "scan.targeted"
    done = client.post(f"{url}/commands/{item['id']}/complete",
                       json={"status": "completed", "resultJson": json.dumps({"findings": 0})}, headers=device["headers"])
    assert done.json()["status"] == "completed"
    commands = client.get(f"/api/console/commands?device_id={device['deviceId']}", headers=admin).json()
    assert commands[0]["result"] == {"findings": 0}


def test_command_validation(client, admin, device):
    url = f"/api/console/devices/{device['deviceId']}/commands"
    assert client.post(url, json={"type": "process.terminate"}, headers=admin).status_code == 400  # needs targetPath
    assert client.post(url, json={"type": "rm -rf"}, headers=admin).status_code == 400


def test_isolation_state_follows_agent(client, admin, device):
    client.post(f"/api/console/devices/{device['deviceId']}/commands", json={"type": "device.isolate"}, headers=admin)
    url = f"/api/v1/devices/{device['deviceId']}"
    item = client.get(f"{url}/commands/pending", headers=device["headers"]).json()["items"][0]
    client.post(f"{url}/commands/{item['id']}/complete", json={"status": "completed"}, headers=device["headers"])
    detail = client.get(f"/api/console/devices/{device['deviceId']}", headers=admin).json()
    assert detail["device"]["isolated"] is True


def test_signature_bundle_matches_agent_parser(client, admin, device):
    sha = "a" * 64
    client.post("/api/console/intel/indicators", json={"tenantId": None, "values": [sha, "evil.example", "http://bad.example/x"]},
                headers=admin)
    bundle = client.get("/api/v1/agent/bundle?hashesLimit=10", headers=device["headers"]).json()
    assert bundle["signatureVersion"]
    assert {"type": "sha256", "value": sha, "category": "malware"}.items() <= bundle["hashes"][0].items()
    assert any(u["host"] == "evil.example" for u in bundle["urls"])
    rep = client.get(f"/api/v1/reputation/{sha}").json()
    assert rep["verdict"] == "malicious"


def test_pua_classification():
    from fenrir_cloud.intel import is_pua

    assert is_pua("pua", "")
    assert is_pua("malware", "PUA:Win32/Presenoker")
    assert is_pua(None, "Win32/Adware.Agent.X")
    assert is_pua("", "not-a-virus:HEUR:AdWare.Win32.X")
    assert not is_pua("malware", "Trojan.Emotet")
    assert not is_pua("malware", "Puabot")  # a word containing "pua" is not a PUA label


def test_update_check(client, admin):
    client.post("/api/console/releases", json={"platform": "windows", "version": "1.5.0", "url": "https://dl/x.json",
                                               "sha256": "b" * 64}, headers=admin)
    offers = client.post("/api/v1/update-check", json={"agentVersion": "1.4.2", "platform": "windows"}).json()["updates"]
    assert offers[0]["targetVersion"] == "1.5.0"
    assert {"packageType", "targetVersion", "manifestPath"} <= set(offers[0])
    none = client.post("/api/v1/update-check", json={"agentVersion": "1.5.0", "platform": "windows"}).json()["updates"]
    assert none == []


def test_reenroll_same_serial_rotates_key(client, admin, tenant, device):
    again = enroll(client, admin, tenant, serial="SN-1")
    assert again["deviceId"] == device["deviceId"]
    assert again["deviceApiKey"] != device["deviceApiKey"]
    old = client.post(f"/api/v1/devices/{device['deviceId']}/heartbeat", json={}, headers=device["headers"])
    assert old.status_code == 401
