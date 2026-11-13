"""Privileged access: requests granted without waiting (policy rules and technician allowances), requests that can no
longer complete lapsing so asking again works, and what Windows agents are told."""
import json
from datetime import timedelta

from fenrir_cloud import db as database
from fenrir_cloud import elevation_rules
from fenrir_cloud.models import ElevationRequest, utcnow

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
OTHER_SID = "S-1-5-21-1111111111-2222222222-3333333333-1002"
TOOL = "C:\\Program Files\\Contoso\\Tools\\setup.exe"


def _policy(client, admin, tenant, privilege):
    policies = client.get(f"/api/console/policies?tenant_id={tenant['id']}", headers=admin).json()
    default = next(p for p in policies if p["id"] == tenant["defaultPolicyId"])
    response = client.put(f"/api/console/policies/{default['id']}", json={"settings": {"privilege": privilege}}, headers=admin)
    assert response.status_code == 200, response.text


def _ask(client, device, **body):
    payload = {"user": "PC1\\jo", "userSid": SID, "reason": "Install the printer driver", **body}
    return client.post(f"/api/v1/devices/{device['deviceId']}/elevation-requests", headers=device["headers"], json=payload)


def _grants(client, device):
    items = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]
    return [json.loads(c["payloadJson"]) for c in items if c["type"] == "elevation.grant"]


def _agent_privilege(client, device):
    doc = client.post(f"/api/v1/devices/{device['deviceId']}/policy-check-in", headers=device["headers"], json={}).json()["policy"]
    return doc["revision"], doc["modules"]["privilege"]


def _heartbeat_revision(client, device):
    reply = client.post(f"/api/v1/devices/{device['deviceId']}/heartbeat", headers=device["headers"], json={"agentVersion": "1.0"})
    return reply.json()["effectivePolicyRevision"]


def test_matching_helpers():
    assert elevation_rules.user_matches("jo", "PC1\\jo") and elevation_rules.user_matches("jo", "CONTOSO\\Jo")
    assert elevation_rules.user_matches("contoso\\jo", "CONTOSO\\jo") and not elevation_rules.user_matches("contoso\\jo", "PC1\\jo")
    assert elevation_rules.user_matches("", "PC1\\anyone")
    assert elevation_rules.user_matches("ignored", "PC1\\x", SID, SID) and not elevation_rules.user_matches("jo", "PC1\\jo", SID, OTHER_SID)
    assert elevation_rules.program_matches("C:\\Program Files\\Contoso\\*", TOOL)
    assert not elevation_rules.program_matches("C:\\Program Files\\Contoso\\*", "C:\\Users\\jo\\Downloads\\setup.exe")
    assert elevation_rules.program_matches(TOOL.upper(), TOOL)
    assert elevation_rules.program_matches("ab" * 32, TOOL, "AB" * 32) and not elevation_rules.program_matches("ab" * 32, TOOL, "")
    assert elevation_rules.program_matches("C:\\Apps [x86]\\*", "C:\\Apps [x86]\\a.exe")


def test_requests_no_longer_depend_on_the_master_switch(client, admin, tenant, device):
    assert _ask(client, device).status_code == 403  # off by default
    # A policy that never chose a value keeps the old behaviour: approval when Privilege management is on.
    _policy(client, admin, tenant, {"enabled": True})
    assert _ask(client, device).json()["status"] == "pending"
    # Choosing a value works without the switch.
    _policy(client, admin, tenant, {"enabled": False, "elevationRequests": "auto-approve"})
    assert _ask(client, device, kind="run", target=TOOL).json()["status"] == "approved"
    _, privilege = _agent_privilege(client, device)
    # Older agents only accept requests with the switch on; removing admin rights stays off as it was.
    assert privilege["elevationRequests"] == "auto-approve" and privilege["enabled"] is True and privilege["removeLocalAdmins"] is False


def test_a_waiting_request_is_granted_when_the_policy_changes_to_auto_approve(client, admin, tenant, device):
    _policy(client, admin, tenant, {"elevationRequests": "approval"})
    first = _ask(client, device).json()
    assert first["status"] == "pending"
    _policy(client, admin, tenant, {"elevationRequests": "auto-approve"})
    again = _ask(client, device).json()
    assert again["id"] == first["id"] and again["status"] == "approved"
    assert len(_grants(client, device)) == 1


def test_lost_approvals_and_old_requests_lapse(client, admin, tenant, device):
    _policy(client, admin, tenant, {"elevationRequests": "auto-approve"})
    first = _ask(client, device).json()
    assert _ask(client, device).json()["id"] == first["id"]  # still in flight
    with database.session_factory()() as db:
        row = db.get(ElevationRequest, first["id"])
        row.decided_at = utcnow() - timedelta(minutes=11)
        db.commit()
    second = _ask(client, device).json()
    assert second["id"] != first["id"] and second["status"] == "approved"
    rows = {r["id"]: r for r in client.get("/api/console/elevation-requests", headers=admin).json()}
    assert rows[first["id"]]["status"] == "failed"

    _policy(client, admin, tenant, {"elevationRequests": "approval"})
    waiting = _ask(client, device, kind="run", target=TOOL).json()
    with database.session_factory()() as db:
        db.get(ElevationRequest, waiting["id"]).created_at = utcnow() - timedelta(hours=25)
        db.commit()
    assert _ask(client, device, kind="run", target=TOOL).json()["id"] != waiting["id"]


def test_policy_rules_users_programs_and_publishers(client, admin, tenant, device):
    _policy(client, admin, tenant, {"elevationRequests": "approval", "autoApproveUsers": ["contoso\\sam", "jo"],
                                    "autoApprovePrograms": ["C:\\Program Files\\Contoso\\*", "cd" * 32],
                                    "autoApprovePublishers": ["Adobe Inc."]})
    session = _ask(client, device).json()
    assert session["status"] == "approved" and session["rule"] == "policy: user jo"
    other = {"user": "PC1\\kim", "userSid": OTHER_SID}
    assert _ask(client, device, **other).json()["status"] == "pending"
    assert _ask(client, device, **other, kind="run", target=TOOL).json()["rule"].startswith("policy: program")
    hashed = _ask(client, device, **other, kind="run", target="C:\\Users\\kim\\Downloads\\x.exe", sha256="CD" * 32).json()
    assert hashed["status"] == "approved"
    signed = _ask(client, device, **other, kind="run", target="C:\\Users\\kim\\Downloads\\reader.exe", publisher="adobe inc.").json()
    assert signed["status"] == "approved" and signed["rule"] == "policy: publisher Adobe Inc."
    unsigned = _ask(client, device, **other, kind="run", target="C:\\Users\\kim\\Downloads\\tool.exe", publisher="Someone Else").json()
    assert unsigned["status"] == "pending"
    detail = client.get(f"/api/console/elevation-requests/{signed['id']}", headers=admin).json()
    assert detail["publisher"] == "adobe inc." and detail["approvedByRule"] == "policy: publisher Adobe Inc."


def test_device_allowance_grants_without_approval_even_with_requests_off(client, admin, tenant, device):
    revision_before, privilege = _agent_privilege(client, device)
    assert privilege["elevationRequests"] == "off"
    created = client.post("/api/console/elevation-allowances", headers=admin, json={
        "deviceId": device["deviceId"], "user": "PC1\\jo", "userSid": SID, "minutes": 120, "hours": 8,
        "note": "Developer machine this week"})
    assert created.status_code == 200, created.text
    allowance = created.json()
    assert allowance["active"] and allowance["scope"] == "device" and allowance["expiresAt"]

    revision, privilege = _agent_privilege(client, device)
    assert privilege["elevationRequests"] == "approval" and privilege["enabled"] is True and privilege["removeLocalAdmins"] is False
    assert revision != revision_before and _heartbeat_revision(client, device) == revision

    granted = _ask(client, device).json()
    assert granted["status"] == "approved" and granted["minutes"] == 120 and granted["rule"].startswith("allowance from")
    assert _grants(client, device)[0]["minutes"] == 120
    assert _ask(client, device, user="PC1\\kim", userSid=OTHER_SID).status_code == 403  # someone else: still off
    listed = client.get(f"/api/console/elevation-allowances?device_id={device['deviceId']}", headers=admin).json()
    assert [a["id"] for a in listed] == [allowance["id"]] and listed[0]["uses"] == 1

    client.post(f"/api/console/elevation-allowances/{allowance['id']}/revoke", headers=admin)
    assert _ask(client, device, kind="run", target=TOOL).status_code == 403
    assert _agent_privilege(client, device)[1]["elevationRequests"] == "off"
    trail = [e["action"] for e in client.get("/api/console/audit", headers=admin).json()]
    assert "elevation.allowance_created" in trail and "elevation.allowance_revoked" in trail


def test_customer_wide_allowances_and_program_limits(client, admin, tenant, device):
    reply = client.post("/api/console/elevation-allowances", headers=admin, json={
        "tenantId": tenant["id"], "anyUser": True, "kinds": "run", "programs": ["C:\\Program Files\\Contoso\\*"],
        "note": "Contoso tools for everyone"})
    assert reply.status_code == 200, reply.text
    assert reply.json()["scope"] == "customer" and reply.json()["expiresAt"] is None
    assert _ask(client, device, kind="run", target=TOOL).json()["status"] == "approved"
    assert _ask(client, device, kind="run", target="C:\\Windows\\System32\\cmd.exe").status_code == 403
    assert _ask(client, device).status_code == 403  # named programs only: no general admin access
    assert _agent_privilege(client, device)[1]["elevationRequests"] == "approval"

    client.post("/api/console/elevation-allowances", headers=admin, json={"tenantId": tenant["id"], "anyUser": True, "note": "Everyone"})
    assert _agent_privilege(client, device)[1]["elevationRequests"] == "auto-approve"


def test_allowance_validation(client, admin, tenant, device):
    assert client.post("/api/console/elevation-allowances", headers=admin, json={"deviceId": device["deviceId"], "anyUser": True}).status_code == 422
    assert client.post("/api/console/elevation-allowances", headers=admin, json={"note": "no target", "anyUser": True}).status_code == 404
    # No user named and nobody signed in.
    assert client.post("/api/console/elevation-allowances", headers=admin,
                       json={"deviceId": device["deviceId"], "note": "who?"}).status_code == 422
