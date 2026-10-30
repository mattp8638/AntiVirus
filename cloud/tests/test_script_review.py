"""Script review: with it required, a library script or remediation package reaches devices only in a version that
someone who did not write or edit it has approved."""

import pytest

from conftest import login
from fenrir_cloud import db as database, platform_security
from fenrir_cloud.models import Job
from test_documentation_vault import stepup

OPS_PASSWORD = "acme-password-123"


def _require_review(on: bool = True) -> None:
    with database.session_factory()() as db:
        platform_security.save(db, {"scriptReview": on})
        db.commit()


@pytest.fixture()
def ops(client, admin, tenant):
    """A second person (customer administrator) who can approve and run scripts."""
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "ops@acme.example",
                                                           "password": OPS_PASSWORD, "role": "tenant_admin"})
    headers = login(client, "ops@acme.example", OPS_PASSWORD)
    proof = client.post("/api/console/auth/reauth", headers=headers, json={"password": OPS_PASSWORD}).json()["reauthToken"]
    return headers, {**headers, "X-Fenrir-Reauth": proof}


def _script(client, admin, tenant, body="Write-Output 1"):
    reply = client.post("/api/console/rmm/scripts", headers=admin,
                        json={"tenantId": tenant["id"], "name": "Clean temp", "language": "powershell", "body": body})
    assert reply.status_code == 200, reply.text
    return reply.json()


def _run(client, headers, script_id, device):
    return client.post(f"/api/console/rmm/scripts/{script_id}/run", headers=headers, json={"targets": {"deviceIds": [device["deviceId"]]}})


def _review(client, headers, script_id, hash_):
    return client.post(f"/api/console/rmm/scripts/{script_id}/review", headers=headers, json={"hash": hash_})


def test_a_new_script_waits_for_someone_else_to_review_it(client, admin, tenant, device, ops):
    ops_headers, ops_stepped = ops
    _require_review()
    script = _script(client, admin, tenant)
    assert script["review"]["status"] == "pending" and script["review"]["editors"] == ["admin@fenrir.local"]
    refused = _run(client, admin, script["id"], device)
    assert refused.status_code == 400 and "nobody else has reviewed" in refused.json()["detail"]

    # The author cannot review their own script; a reviewer needs a fresh password check and the version they read.
    assert _review(client, stepup(client, admin), script["id"], script["review"]["hash"]).status_code == 403
    assert _review(client, ops_headers, script["id"], script["review"]["hash"]).status_code == 403
    assert _review(client, ops_stepped, script["id"], "0" * 64).status_code == 409
    reviewed = _review(client, ops_stepped, script["id"], script["review"]["hash"])
    assert reviewed.status_code == 200 and reviewed.json()["review"]["status"] == "reviewed"
    assert reviewed.json()["review"]["reviewedBy"] == "ops@acme.example"

    ran = _run(client, admin, script["id"], device)
    assert ran.status_code == 200, ran.text
    with database.session_factory()() as db:
        assert db.get(Job, ran.json()["id"]).payload["reviewedHash"] == script["review"]["hash"]
    actions = [e["action"] for e in client.get("/api/console/audit", headers=admin).json()]
    assert "rmm.script.reviewed" in actions


def test_a_change_to_what_runs_needs_a_new_review_and_shows_what_changed(client, admin, tenant, device, ops):
    _, ops_stepped = ops
    _require_review()
    script = _script(client, admin, tenant, "Write-Output 'old'")
    _review(client, ops_stepped, script["id"], script["review"]["hash"])

    renamed = client.patch(f"/api/console/rmm/scripts/{script['id']}", headers=admin, json={"name": "Clean temp files"}).json()
    assert renamed["review"]["status"] == "reviewed"  # a new name does not change what runs

    changed = client.patch(f"/api/console/rmm/scripts/{script['id']}", headers=admin, json={"body": "Remove-Item C:\\\\ -Recurse"}).json()
    assert changed["review"]["status"] == "pending" and changed["review"]["editors"] == ["admin@fenrir.local"]
    assert "-Write-Output 'old'" in changed["review"]["diff"] and "+Remove-Item" in changed["review"]["diff"]
    assert _run(client, admin, script["id"], device).status_code == 400

    # The reviewer edits it too: now neither of them may approve this version.
    edited = client.patch(f"/api/console/rmm/scripts/{script['id']}", headers=ops_stepped, json={"body": "Write-Output 'new'"}).json()
    assert edited["review"]["editors"] == ["admin@fenrir.local", "ops@acme.example"]
    assert _review(client, ops_stepped, script["id"], edited["review"]["hash"]).status_code == 403
    assert _review(client, stepup(client, admin), script["id"], edited["review"]["hash"]).status_code == 403

    # Changing it back to the reviewed version needs no new review.
    back = client.patch(f"/api/console/rmm/scripts/{script['id']}", headers=admin, json={"body": "Write-Output 'old'"}).json()
    assert back["review"]["status"] == "reviewed" and _run(client, admin, script["id"], device).status_code == 200


def test_scripts_shipped_with_fenrir_run_until_someone_changes_them(client, admin, device, ops):
    _require_review()
    builtin = next(s for s in client.get("/api/console/rmm/scripts", headers=admin).json()
                   if s["builtin"] and "windows" in s["platforms"] and not any(p.get("required") for p in s["parameters"]))
    assert builtin["review"]["status"] == "shipped"
    assert _run(client, admin, builtin["id"], device).status_code == 200
    edited = client.patch(f"/api/console/rmm/scripts/{builtin['id']}", headers=admin, json={"body": "Write-Output 'changed'"}).json()
    assert edited["review"]["status"] == "pending"
    assert _run(client, admin, builtin["id"], device).status_code == 400
    # Shared scripts run for every customer, so a customer's own administrator cannot approve them.
    _, ops_stepped = ops
    refused = _review(client, ops_stepped, builtin["id"], edited["review"]["hash"])
    assert refused.status_code == 403 and "platform administrator" in refused.json()["detail"]


def test_review_off_changes_nothing_but_old_unreviewed_jobs_cannot_be_retried_once_on(client, admin, tenant, device):
    script = _script(client, admin, tenant)
    assert script["review"]["required"] is False
    job = _run(client, admin, script["id"], device)
    assert job.status_code == 200
    with database.session_factory()() as db:
        row = db.get(Job, job.json()["id"])
        for command_id in (row.command_ids or {}).values():
            from fenrir_cloud.models import Command
            db.get(Command, command_id).status = "failed"
        db.commit()
    _require_review()
    retry = client.post(f"/api/console/rmm/jobs/{job.json()['id']}/retry", headers=admin)
    assert retry.status_code == 400 and "nobody reviewed" in retry.json()["detail"]


def test_a_bare_script_command_is_refused_while_review_is_required(client, admin, device):
    command = {"type": "script.run", "reason": "test", "payload": {"language": "powershell", "body": "Write-Output 1"}}
    assert client.post(f"/api/console/devices/{device['deviceId']}/commands", headers=admin, json=command).status_code == 200
    _require_review()
    refused = client.post(f"/api/console/devices/{device['deviceId']}/commands", headers=admin, json=command)
    assert refused.status_code == 400 and "from the library" in refused.json()["detail"]
    bulk = client.post("/api/console/commands/bulk", headers=admin, json={**command, "deviceIds": [device["deviceId"]]})
    assert bulk.status_code == 400


def test_remediation_packages_are_reviewed_like_scripts(client, admin, tenant, device, ops):
    _, ops_stepped = ops
    _require_review()
    created = client.post("/api/console/rmm/remediation-packages", headers=admin, json={
        "tenantId": tenant["id"], "name": "Spooler", "language": "powershell",
        "detectionScript": "exit 0", "remediationScript": "Start-Service Spooler"})
    assert created.status_code == 200, created.text
    package = created.json()
    assert package["review"]["status"] == "pending"
    refused = client.post(f"/api/console/rmm/remediation-packages/{package['id']}/run", headers=admin, json={})
    assert refused.status_code == 400 and "nobody else has reviewed" in refused.json()["detail"]
    reviewed = client.post(f"/api/console/rmm/remediation-packages/{package['id']}/review", headers=ops_stepped,
                           json={"hash": package["review"]["hash"]})
    assert reviewed.status_code == 200 and reviewed.json()["review"]["status"] == "reviewed"
    ran = client.post(f"/api/console/rmm/remediation-packages/{package['id']}/run", headers=admin, json={})
    assert ran.status_code == 200 and ran.json()["queued"] == 1

    # A built-in template enabled as shipped runs without a review.
    template = next(p for p in client.get("/api/console/rmm/remediation-packages", headers=admin).json() if p["template"])
    enabled = client.post(f"/api/console/rmm/remediation-packages/{template['id']}/enable", headers=admin,
                          json={"tenantId": tenant["id"]}).json()
    assert enabled["review"]["status"] == "shipped"


def test_turning_script_review_on_needs_a_fresh_password(client, admin):
    assert client.put("/api/console/platform/security", headers=admin, json={"scriptReview": True}).status_code == 403
    saved = client.put("/api/console/platform/security", headers=stepup(client, admin), json={"scriptReview": True})
    assert saved.status_code == 200 and saved.json()["scriptReview"] is True


def test_a_schedule_skips_an_unreviewed_script_and_says_why(client, admin, tenant, device):
    from fenrir_cloud import rmm
    from fenrir_cloud.models import ScheduledTask

    _require_review()
    script = _script(client, admin, tenant)
    task = client.post("/api/console/rmm/tasks", headers=admin, json={
        "tenantId": tenant["id"], "name": "Nightly clean", "schedule": {"type": "daily", "time": "02:00"},
        "targets": {"deviceIds": [device["deviceId"]]}, "actions": [{"type": "script", "scriptId": script["id"]}]})
    assert task.status_code == 200, task.text
    with database.session_factory()() as db:
        assert rmm.run_scheduled_task(db, db.get(ScheduledTask, task.json()["id"])) == []
        db.commit()
    held = [e for e in client.get("/api/console/audit", headers=admin).json() if e["action"] == "rmm.script.held_for_review"]
    assert held and held[0]["details"]["task"] == "Nightly clean"
