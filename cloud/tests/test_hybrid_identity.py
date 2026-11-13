"""Hybrid identity: users synced from Active Directory are offboarded and created on the customer's domain controller
through its agent, then finished in Microsoft 365 (mocked Microsoft: m365_fake.py; the test plays the DC's agent)."""
import json

import httpx
import pytest

from conftest import enroll
from m365_fake import GROUP, SKU, FakeTenant
from test_documentation_vault import stepup
from test_msp_modules import connection
from fenrir_cloud import db as database, m365_lifecycle
from fenrir_cloud.models import AuditLog, Command, M365Workflow

SYNCED = "00000000-0000-0000-0000-000000000099"


@pytest.fixture
def fake(monkeypatch):
    tenant = FakeTenant()
    tenant.users[SYNCED] = {"id": SYNCED, "displayName": "Sam Synced", "userPrincipalName": "sam@acme.example", "mail": "sam@acme.example",
                            "accountEnabled": True, "userType": "Member", "assignedLicenses": [{"skuId": SKU}],
                            "licenseAssignmentStates": [{"skuId": SKU, "assignedByGroup": None}], "onPremisesSyncEnabled": True,
                            "onPremisesSamAccountName": "ssynced", "createdDateTime": "2023-01-01T00:00:00Z"}
    tenant.groups[GROUP]["members"].add(SYNCED)
    monkeypatch.setattr(httpx, "Client", tenant.client)
    return tenant


def domain_controller(client, admin, tenant, entra_connect=True):
    dc = enroll(client, admin, tenant, hostname="ACME-DC", os_version="Windows Server 2022 Standard", serial="DC-1")
    role = {"kind": "domain-controller", "domain": "acme.example",
            "workloads": ["Active Directory Domain Services"] + (["Entra Connect (Azure AD Connect)"] if entra_connect else [])}
    assert client.post(f"/api/v1/devices/{dc['deviceId']}/profile", headers=dc["headers"], json={"profile": {"role": role}}).status_code == 200
    return dc


def agent_answers(client, dc, answer):
    """Play the DC's agent: take each ad.directory command, let `answer` decide its result, and complete it."""
    pending = client.get(f"/api/v1/devices/{dc['deviceId']}/commands/pending", headers=dc["headers"]).json()["items"]
    done = []
    for item in pending:
        if item["type"] != "ad.directory":
            continue
        request = json.loads(item["payloadJson"])
        assert "secretEnvelope" not in request  # the encrypted secret never travels with the command
        result = answer(item, request)
        client.post(f"/api/v1/devices/{dc['deviceId']}/commands/{item['id']}/complete", headers=dc["headers"],
                    json={"status": "completed", "resultJson": json.dumps(result)})
        done.append(request)
    return done


def run(client, proof, flow):
    response = client.post(f"/api/console/m365/workflows/{flow['id']}/run", headers=proof, json={"confirmed": True})
    assert response.status_code == 200, response.text
    return response.json()


def test_offboarding_a_synced_user_changes_ad_on_the_domain_controller(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    dc = domain_controller(client, admin, tenant)
    flow = client.post(f"/api/console/m365/connections/{conn['id']}/workflows", headers=admin, json={
        "kind": "offboard", "targetId": SYNCED,
        "options": {"adMoveOu": "OU=Leavers,DC=acme,DC=example", "hideFromAddressBook": True, "markContact": False}}).json()
    keys = [s["key"] for s in flow["steps"]]
    assert keys[:7] == ["ad_disable", "ad_scramble", "ad_remove_groups", "ad_move", "ad_hide_gal", "ad_describe", "ad_sync"]
    assert "block_signin" not in keys and "reset_password" not in keys  # Microsoft refuses these for synced users
    assert {s["where"] for s in flow["steps"][:7]} == {"ad"} and flow["steps"][0]["detail"].startswith("ssynced on ACME-DC")

    proof = stepup(client, admin)
    out = run(client, proof, flow)
    assert out["more"] and "ACME-DC" in out["waiting"]  # waits for the domain controller
    seen = []
    for _ in range(12):
        seen += agent_answers(client, dc, lambda item, req: {"ok": True, "removed": ["Sales AD"], "kept": []}
                              if req["operation"] == "remove_groups" else {"ok": True})
        out = run(client, proof, out["workflow"])
        if not out["more"]:
            break
    assert [r["operation"] for r in seen] == ["disable", "scramble", "remove_groups", "move", "hide_gal", "describe", "sync"]
    assert all(r["params"].get("identity") in (None, "ssynced") for r in seen) and seen[3]["params"]["ou"].startswith("OU=Leavers")
    final = out["workflow"]
    status = {s["key"]: s for s in final["steps"]}
    assert final["status"] == "completed", [(s["key"], s["status"], s["result"]) for s in final["steps"]]
    assert status["ad_remove_groups"]["result"] == "Removed: Sales AD"
    # Cloud-only work still happened in Microsoft 365.
    assert fake.users[SYNCED]["assignedLicenses"] == [] or "remove_licences" not in status
    assert any(m == "POST" and p.endswith("/revokeSignInSessions") for m, p, _ in fake.requests)
    assert not any(m == "PATCH" and p == f"/users/{SYNCED}" and b and "accountEnabled" in b for m, p, b in fake.requests)


def test_a_failed_ad_step_reports_the_servers_reason_and_can_be_retried(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    dc = domain_controller(client, admin, tenant, entra_connect=False)
    flow = client.post(f"/api/console/m365/connections/{conn['id']}/workflows", headers=admin, json={
        "kind": "offboard", "targetId": SYNCED, "options": {"markContact": False, "openTicket": False}}).json()
    sync = next(s for s in flow["steps"] if s["key"] == "ad_sync")
    assert sync["status"] == "skipped" and "30 minutes" in sync["result"]  # no Entra Connect server known
    proof = stepup(client, admin)
    out = run(client, proof, flow)
    agent_answers(client, dc, lambda item, req: {"ok": False, "error": "Insufficient access rights to perform the operation"})
    out = run(client, proof, out["workflow"])
    first = out["workflow"]["steps"][0]
    assert first["status"] == "failed" and "Insufficient access rights" in first["result"]


def test_without_a_domain_controller_the_ad_part_is_flagged_for_doing_by_hand(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    flow = client.post(f"/api/console/m365/connections/{conn['id']}/workflows", headers=admin, json={
        "kind": "offboard", "targetId": SYNCED, "options": {}}).json()
    manual = flow["steps"][0]
    assert manual["key"] == "ad_manual" and manual["status"] == "skipped" and "Active Directory" in manual["warning"]


def test_a_synced_user_cannot_be_blocked_in_the_cloud_and_says_why(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    response = client.post(f"/api/console/m365/connections/{conn['id']}/actions", headers=admin, json={
        "requestId": "6f1c8a2e-1111-4222-8333-944455556666", "operation": "user.signin", "targetId": SYNCED,
        "parameters": {"accountEnabled": False}})
    assert response.status_code == 400 and "synced from Active Directory" in response.json()["detail"]


def test_a_new_starter_is_created_in_ad_synced_then_licensed(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    dc = domain_controller(client, admin, tenant)
    flow = client.post(f"/api/console/m365/connections/{conn['id']}/workflows", headers=admin, json={
        "kind": "onboard", "options": {"createIn": "ad", "ad": {"sam": "nnew", "ou": "OU=Staff,DC=acme,DC=example", "groups": ["CN=Sales AD,OU=Groups,DC=acme,DC=example"]},
                                       "profile": {"displayName": "Nia New", "userPrincipalName": "nia@acme.example", "mailNickname": "nia",
                                                   "usageLocation": "GB", "givenName": "Nia", "surname": "New"},
                                       "skuIds": [SKU], "groupIds": [GROUP], "addContact": False, "openTicket": False}})
    assert flow.status_code == 200, flow.text
    flow = flow.json()
    assert [s["key"] for s in flow["steps"]] == ["ad_create", "ad_sync", "wait_cloud", "set_usage_location", "assign_licences", "add_groups"]

    proof = stepup(client, admin)
    out = run(client, proof, flow)
    password = out["secrets"][0]["password"]
    assert out["secrets"][0]["where"] == "Active Directory" and len(password) >= 16
    with database.session_factory()() as db:
        stored = db.query(Command).filter_by(type="ad.directory").one()
        assert password not in json.dumps(stored.payload) and stored.payload.get("secretEnvelope")
        assert not any(password in json.dumps(a.details) for a in db.query(AuditLog))

    def as_dc(item, request):
        if request["operation"] == "create":
            released = client.post(f"/api/v1/devices/{dc['deviceId']}/commands/{item['id']}/secret", headers=dc["headers"])
            assert released.json() == {"secret": password}
            assert client.post(f"/api/v1/devices/{dc['deviceId']}/commands/{item['id']}/secret", headers=dc["headers"]).status_code == 404
            assert request["params"]["sam"] == "nnew" and request["params"]["ou"].startswith("OU=Staff") and request["secret"] is True
            return {"ok": True, "user": {"sam": "nnew", "ou": "OU=Staff,DC=acme,DC=example"}, "notes": []}
        if request["operation"] == "sync":
            # Entra Connect brings the user across.
            fake.users["00000000-0000-0000-0000-0000000000aa"] = {"id": "00000000-0000-0000-0000-0000000000aa", "displayName": "Nia New",
                                                                   "userPrincipalName": "nia@acme.example", "userType": "Member",
                                                                   "assignedLicenses": [], "onPremisesSyncEnabled": True}
        return {"ok": True}

    for _ in range(10):
        agent_answers(client, dc, as_dc)
        out = run(client, proof, out["workflow"])
        if not out["more"]:
            break
    final = out["workflow"]
    assert final["status"] == "completed", [(s["key"], s["status"], s["result"]) for s in final["steps"]]
    new = fake.users["00000000-0000-0000-0000-0000000000aa"]
    assert new["usageLocation"] == "GB" and new["assignedLicenses"] == [{"skuId": SKU}] and new["id"] in fake.groups[GROUP]["members"]
    with database.session_factory()() as db:
        assert "secretEnvelope" not in db.query(Command).filter_by(type="ad.directory").first().payload


def test_waiting_workflows_carry_on_without_the_page_open(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    dc = domain_controller(client, admin, tenant)
    flow = client.post(f"/api/console/m365/connections/{conn['id']}/workflows", headers=admin, json={
        "kind": "offboard", "targetId": SYNCED, "options": {"markContact": False, "openTicket": False}}).json()
    out = run(client, stepup(client, admin), flow)
    assert out["more"]
    for _ in range(12):
        agent_answers(client, dc, lambda item, req: {"ok": True})
        with database.session_factory()() as db:
            m365_lifecycle.advance_waiting(db)
            if db.get(M365Workflow, flow["id"]).status == "completed":
                break
    with database.session_factory()() as db:
        done = db.get(M365Workflow, flow["id"])
        assert done.status == "completed" and done.executed_by.endswith("(continued by Fenrir)")
        assert not done.executed_by.endswith("(continued by Fenrir) (continued by Fenrir)")


def test_ad_changes_cannot_be_sent_from_the_device_command_menu(client, admin, tenant):
    dc = domain_controller(client, admin, tenant)
    response = client.post(f"/api/console/devices/{dc['deviceId']}/commands", headers=stepup(client, admin),
                           json={"type": "ad.directory", "payload": {"operation": "disable", "params": {"identity": "administrator"}}})
    assert response.status_code == 400 and "onboarding and offboarding" in response.json()["detail"]
