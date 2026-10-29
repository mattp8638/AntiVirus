"""Strict process-chain and hash EDR exclusions (edr_exclusions.py)."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from conftest import enroll, login
from fenrir_cloud import edr_exclusions

AGENT = r"C:\Program Files\Acme RMM\acme-agent.exe"
AGENT_SHA = "a" * 64
OTHER_SHA = "b" * 64
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def encoded_powershell(event_id, parent=AGENT, parent_sha=AGENT_SHA):
    payload = {"processImagePath": POWERSHELL, "commandLine": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
               "parentProcessImagePath": parent, "pid": 3100}
    if parent_sha:
        payload["parentSha256"] = parent_sha
    return {"eventId": event_id, "eventType": "process.start", "source": "etw", "summary": "",
            "occurredAt": datetime.now(timezone.utc).isoformat(), "payloadJson": json.dumps(payload)}


def send(client, device, events):
    response = client.post(f"/api/v1/devices/{device['deviceId']}/telemetry", json={"events": events}, headers=device["headers"])
    assert response.status_code == 200, response.text
    return response.json()


def profile(client, admin, tenant, **overrides):
    body = {"tenantId": tenant["id"], "name": "Acme RMM", "platform": "windows", "agentImage": AGENT, "agentSha256": [AGENT_SHA],
            "reason": "Our RMM agent runs approved maintenance scripts", **overrides}
    return client.post("/api/console/edr/exclusions/rmm-profile", json=body, headers=admin)


def test_path_matching_is_strict():
    assert edr_exclusions.path_matches(r"C:\Program Files\Acme\agent-*.exe", "c:/program files/acme/AGENT-2.4.exe")
    assert not edr_exclusions.path_matches(r"C:\Program Files\Acme\agent-*.exe", r"C:\Users\bob\agent-2.4.exe")
    assert not edr_exclusions.path_matches(r"C:\Program Files\Acme\agent.exe", r"C:\Program Files\Acme\sub\agent.exe")
    rule = {"kind": "process-chain", "parentImage": AGENT, "parentSha256": [AGENT_SHA], "childImage": POWERSHELL,
            "childSha256": [], "commandLineContains": ""}
    assert edr_exclusions.matches(rule, image=POWERSHELL, parent_image=AGENT, parent_sha256=AGENT_SHA)
    # A renamed or tampered parent at the same path is not trusted, and neither is a missing hash.
    assert not edr_exclusions.matches(rule, image=POWERSHELL, parent_image=AGENT, parent_sha256=OTHER_SHA)
    assert not edr_exclusions.matches(rule, image=POWERSHELL, parent_image=AGENT, parent_sha256="")
    assert not edr_exclusions.matches(rule, image=r"C:\Windows\System32\cmd.exe", parent_image=AGENT, parent_sha256=AGENT_SHA)


@pytest.mark.parametrize("body,message", [
    ({"kind": "process-chain", "name": "x", "parentImage": "acme-agent.exe", "parentSha256": [AGENT_SHA], "reason": "long enough reason"},
     "full path"),
    ({"kind": "process-chain", "name": "x", "parentImage": r"C:\Program Files\*\agent.exe", "parentSha256": [AGENT_SHA],
      "reason": "long enough reason"}, "full path"),
    ({"kind": "process-chain", "name": "x", "parentImage": AGENT, "reason": "long enough reason"}, "parent SHA-256"),
    ({"kind": "hash", "name": "x", "reason": "long enough reason"}, "at least one SHA-256"),
    ({"kind": "process-chain", "name": "x", "parentImage": AGENT, "parentSha256": [AGENT_SHA], "reason": "short"}, "Explain"),
    ({"kind": "process-chain", "name": "x", "parentImage": AGENT, "parentSha256": ["not-a-hash"], "reason": "long enough reason"},
     "not a SHA-256"),
    ({"kind": "process-chain", "name": "x", "parentImage": AGENT, "parentSha256": [AGENT_SHA], "scopes": ["antimalware"],
      "reason": "long enough reason"}, "child's SHA-256"),
])
def test_loose_rules_are_rejected(client, admin, tenant, body, message):
    response = client.post("/api/console/edr/exclusions", json={**body, "tenantId": tenant["id"]}, headers=admin)
    assert response.status_code == 422 and message in response.json()["detail"]


def test_rmm_profile_suppresses_alerts_only_for_the_hashed_parent(client, admin, tenant, device):
    # Without an exclusion the RMM agent's encoded PowerShell raises an alert.
    assert send(client, device, [encoded_powershell("e-1")])["alerts"] >= 1
    rules = profile(client, admin, tenant)
    assert rules.status_code == 200, rules.text
    assert {r["childImage"] for r in rules.json()} >= {POWERSHELL, r"C:\Windows\System32\cmd.exe"}

    # Fresh devices, so earlier alerts cannot absorb the events through de-duplication.
    trusted = enroll(client, admin, tenant, hostname="ACME-WS-02", serial="SN-2")
    assert send(client, trusted, [encoded_powershell("e-2")])["alerts"] == 0
    # Same path, different hash (a replaced binary) and an unknown hash still alert.
    replaced = enroll(client, admin, tenant, hostname="ACME-WS-03", serial="SN-3")
    assert send(client, replaced, [encoded_powershell("e-3", parent_sha=OTHER_SHA)])["alerts"] >= 1
    unknown = enroll(client, admin, tenant, hostname="ACME-WS-04", serial="SN-4")
    assert send(client, unknown, [encoded_powershell("e-4", parent_sha="")])["alerts"] >= 1
    listed = client.get("/api/console/edr/exclusions", params={"tenant_id": tenant["id"]}, headers=admin).json()
    powershell_rule = next(r for r in listed if r["childImage"] == POWERSHELL)
    assert powershell_rule["hits"] == 1 and powershell_rule["profile"] == "Acme RMM"

    # The agent receives the behaviour-scoped rules in its policy, and they change the revision.
    policy = client.post(f"/api/v1/devices/{device['deviceId']}/policy-check-in", json={}, headers=device["headers"]).json()["policy"]
    shipped = policy["modules"]["edrExclusions"]["rules"]
    assert any(r["parentSha256"] == [AGENT_SHA] and r["childImage"] == POWERSHELL for r in shipped)

    # Agent-reported hits count on the rule.
    send(client, device, [{"eventId": "hit-1", "eventType": "edr.exclusion.applied", "source": "process-guard",
                           "payloadJson": json.dumps({"exclusionId": powershell_rule["id"], "rule": "attackSurface.blockObfuscatedScripts"})}])
    listed = client.get("/api/console/edr/exclusions", params={"tenant_id": tenant["id"]}, headers=admin).json()
    assert next(r for r in listed if r["id"] == powershell_rule["id"])["hits"] == 2


def test_expired_and_disabled_rules_stop_applying(client, admin, tenant, device):
    rules = profile(client, admin, tenant, interpreters=[POWERSHELL],
                    expiresAt=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat()).json()
    assert rules[0]["expired"] is True
    assert send(client, device, [encoded_powershell("x-1")])["alerts"] >= 1
    tested = client.post("/api/console/edr/exclusions/test", json={"tenantId": tenant["id"], "image": POWERSHELL, "parentImage": AGENT,
                                                                   "parentSha256": AGENT_SHA}, headers=admin).json()
    assert tested["excluded"] is False
    live = profile(client, admin, tenant, interpreters=[POWERSHELL]).json()[0]
    assert client.post("/api/console/edr/exclusions/test", json={"tenantId": tenant["id"], "image": POWERSHELL, "parentImage": AGENT,
                                                                 "parentSha256": AGENT_SHA}, headers=admin).json()["excluded"] is True
    assert client.patch(f"/api/console/edr/exclusions/{live['id']}", json={"enabled": False}, headers=admin).status_code == 200
    assert client.post("/api/console/edr/exclusions/test", json={"tenantId": tenant["id"], "image": POWERSHELL, "parentImage": AGENT,
                                                                 "parentSha256": AGENT_SHA}, headers=admin).json()["excluded"] is False


def test_exclusions_are_scoped_to_the_customer(client, admin, tenant):
    other = client.post("/api/console/tenants", json={"name": "Other Co", "template": "balanced"}, headers=admin).json()
    other_device = enroll(client, admin, other, hostname="OTHER-1", serial="O-1")
    profile(client, admin, tenant, interpreters=[POWERSHELL])
    # Another customer's identical chain still alerts.
    assert send(client, other_device, [encoded_powershell("o-1")])["alerts"] >= 1
    policy = client.post(f"/api/v1/devices/{other_device['deviceId']}/policy-check-in", json={},
                         headers=other_device["headers"]).json()["policy"]
    assert "edrExclusions" not in policy["modules"]

    # A customer admin cannot add platform-wide rules or see/edit another customer's.
    client.post("/api/console/users", json={"email": "ta@other.test", "name": "T", "role": "tenant_admin", "tenantId": other["id"],
                                            "password": "a-long-enough-password-1"}, headers=admin)
    tenant_admin = login(client, "ta@other.test", "a-long-enough-password-1")
    assert profile(client, tenant_admin, {"id": None}).status_code == 403
    assert client.get("/api/console/edr/exclusions", headers=tenant_admin).json() == []
    mine = client.get("/api/console/edr/exclusions", params={"tenant_id": tenant["id"]}, headers=admin).json()[0]
    assert client.delete(f"/api/console/edr/exclusions/{mine['id']}", headers=tenant_admin).status_code == 404
