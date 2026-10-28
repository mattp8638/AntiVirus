"""CORE-15: two-person approval binds the exact request, needs a different person with authority over the targets,
expires, runs once, and any change - including the resolved set of devices - needs a new approval."""

from datetime import timedelta

import pytest

from conftest import enroll, login
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import ApprovalRequest, Job, utcnow
from test_documentation_vault import stepup


def set_policy(client, admin, tenant_id, two_person=True, threshold=2):
    reply = client.put(f"/api/console/tenants/{tenant_id}/approval-policy", headers=stepup(client, admin),
                       json={"twoPerson": two_person, "bulkThreshold": threshold})
    assert reply.status_code == 200, reply.text
    return reply.json()


@pytest.fixture()
def setup(client, admin, tenant):
    devices = [enroll(client, admin, tenant, hostname=f"PC-{i}", serial=f"S-{i}") for i in range(3)]
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "ops@acme.example",
                                                           "password": "acme-password-123", "role": "tenant_admin"})
    requester = login(client, "ops@acme.example", "acme-password-123")
    script = client.post("/api/console/rmm/scripts", headers=admin, json={"tenantId": tenant["id"], "name": "Cleanup", "language": "powershell",
                                                                         "body": "Write-Output 1"}).json()
    return devices, requester, script


def jobs():
    db = session_factory()()
    try:
        return db.query(Job).count()
    finally:
        db.close()


def test_policy_off_runs_at_once(client, admin, tenant, setup):
    devices, requester, script = setup
    reply = client.post(f"/api/console/rmm/scripts/{script['id']}/run", headers=requester,
                        json={"targets": {"deviceIds": [d["deviceId"] for d in devices]}})
    assert reply.status_code == 200 and "approvalRequired" not in reply.json()


def test_held_approved_once_and_bound_to_the_request(client, admin, tenant, setup):
    devices, requester, script = setup
    set_policy(client, admin, tenant["id"])
    body = {"targets": {"deviceIds": [d["deviceId"] for d in devices[:2]]}}
    run = lambda b: client.post(f"/api/console/rmm/scripts/{script['id']}/run", headers=requester, json=b)  # noqa: E731
    before = jobs()
    held = run(body)
    assert held.status_code == 202 and held.json()["approvalRequired"] is True and jobs() == before  # nothing ran
    approval = held.json()["approval"]
    assert approval["devices"] == 2 and approval["status"] == "pending"
    # The requester cannot approve their own request; an approver needs a fresh password check.
    requester_step = {**requester, "X-Fenrir-Reauth": client.post("/api/console/auth/reauth", headers=requester,
                                                                   json={"password": "acme-password-123"}).json()["reauthToken"]}
    assert client.post(f"/api/console/approvals/{approval['id']}/approve", headers=requester_step).status_code == 403
    assert client.post(f"/api/console/approvals/{approval['id']}/approve", headers=admin).json()["detail"] == "reauth_required"
    assert client.post(f"/api/console/approvals/{approval['id']}/approve", headers=stepup(client, admin)).json()["status"] == "approved"
    # A changed request is not what was approved.
    changed = run({**body, "parameters": {"x": "1"}, "approvalId": approval["id"]})
    assert changed.status_code == 409 and "changed" in changed.text
    done = run({**body, "approvalId": approval["id"]})
    assert done.status_code == 200 and jobs() == before + 1
    assert run({**body, "approvalId": approval["id"]}).status_code == 409  # only once
    actions = [e["action"] for e in client.get("/api/console/audit", headers=admin).json()]
    assert {"approval.requested", "approval.approved", "approval.executed"} <= set(actions)


def test_device_set_change_needs_new_approval(client, admin, tenant, setup):
    devices, requester, script = setup
    set_policy(client, admin, tenant["id"])
    body = {"targets": {"tenantIds": [tenant["id"]]}}  # "every device of this customer"
    held = client.post(f"/api/console/rmm/scripts/{script['id']}/run", headers=requester, json=body).json()["approval"]
    client.post(f"/api/console/approvals/{held['id']}/approve", headers=stepup(client, admin))
    enroll(client, admin, tenant, hostname="PC-NEW", serial="S-NEW")  # the customer gained a device
    resend = client.post(f"/api/console/rmm/scripts/{script['id']}/run", headers=requester, json={**body, "approvalId": held["id"]})
    assert resend.status_code == 409 and "target devices" in resend.text


def test_destructive_single_device_needs_approval_and_rejection_sticks(client, admin, tenant, setup):
    devices, requester, _ = setup
    set_policy(client, admin, tenant["id"], threshold=1000)  # destructive actions are held whatever the threshold
    route = f"/api/console/devices/{devices[0]['deviceId']}/commands"
    held = client.post(route, headers=requester, json={"type": "localadmin.reduce"})
    assert held.status_code == 202
    approval = held.json()["approval"]
    assert client.post(f"/api/console/approvals/{approval['id']}/reject", headers=admin, json={"reason": "Not during month end"}).json()["status"] == "rejected"
    again = client.post(route, headers=requester, json={"type": "localadmin.reduce", "approvalId": approval["id"]})
    assert again.status_code == 409 and "rejected" in again.text
    # Non-destructive single commands are not held.
    assert client.post(route, headers=requester, json={"type": "device.isolate"}).status_code == 200


def test_msp_policy_covers_customers_and_approvals_expire(client, admin, tenant, setup):
    devices, requester, script = setup
    msp_id = client.get("/api/console/auth/me", headers=admin).json()["user"]["tenantId"]
    set_policy(client, admin, msp_id, threshold=3)
    body = {"type": "device.isolate", "deviceIds": [d["deviceId"] for d in devices]}
    held = client.post("/api/console/commands/bulk", headers=requester, json=body)
    assert held.status_code == 202, held.text
    approval = held.json()["approval"]
    client.post(f"/api/console/approvals/{approval['id']}/approve", headers=stepup(client, admin))
    db = session_factory()()
    try:
        db.get(ApprovalRequest, approval["id"]).expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
    finally:
        db.close()
    late = client.post("/api/console/commands/bulk", headers=requester, json={**body, "approvalId": approval["id"]})
    assert late.status_code == 409 and "expired" in late.text
    # Below the threshold, nothing is held.
    assert client.post("/api/console/commands/bulk", headers=requester, json={**body, "deviceIds": body["deviceIds"][:2]}).status_code == 200


def test_approver_needs_authority_over_the_targets(client, admin, tenant, setup):
    devices, requester, script = setup
    set_policy(client, admin, tenant["id"])
    held = client.post(f"/api/console/rmm/scripts/{script['id']}/run", headers=requester,
                       json={"targets": {"deviceIds": [d["deviceId"] for d in devices[:2]]}}).json()["approval"]
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Co", "template": "balanced"}).json()
    client.post("/api/console/users", headers=admin, json={"tenantId": other["id"], "email": "boss@other.example",
                                                           "password": "other-password-123", "role": "tenant_admin"})
    outsider = login(client, "boss@other.example", "other-password-123")
    step = {**outsider, "X-Fenrir-Reauth": client.post("/api/console/auth/reauth", headers=outsider, json={"password": "other-password-123"}).json()["reauthToken"]}
    assert client.post(f"/api/console/approvals/{held['id']}/approve", headers=step).status_code == 404
    assert client.get("/api/console/approvals", headers=outsider).json() == []
    # Changing the policy needs approve + configure and a fresh password check.
    assert client.put(f"/api/console/tenants/{tenant['id']}/approval-policy", headers=admin, json={"twoPerson": False}).json()["detail"] == "reauth_required"
