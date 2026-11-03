"""AGT-04 / AT-13: staged agent rollouts. A bad canary release must not reach the next ring; rollouts can be paused,
resumed, advanced and emergency-stopped by platform administrators only."""

import json
from datetime import timedelta

import pytest

from conftest import enroll, login
from fenrir_cloud import rollouts
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import AgentRollout, AgentRolloutDevice, utcnow


def ring(client, admin, tenant, channel):
    policies = client.get(f"/api/console/policies?tenant_id={tenant['id']}", headers=admin).json()
    default = next(p for p in policies if p["id"] == tenant["defaultPolicyId"])
    reply = client.put(f"/api/console/policies/{default['id']}", json={"settings": {"updates": {"channel": channel}}}, headers=admin)
    assert reply.status_code == 200, reply.text


def heartbeat(client, device, build):
    reply = client.post(f"/api/v1/devices/{device['deviceId']}/heartbeat", headers=device["headers"],
                        json={"agentVersion": "1.6.0", "healthState": "healthy", "isolated": False, "buildId": build})
    assert reply.status_code == 200, reply.text


def check(client, device):
    return client.get("/api/v1/agent/update/linux?arch=amd64", headers=device["headers"]).json()


def backdate(hours=0.0, minutes=0.0):
    """Move every rollout and offer into the past, as if time had passed."""
    db = session_factory()()
    try:
        delta = timedelta(hours=hours, minutes=minutes)
        for row in db.query(AgentRollout):
            row.stage_started_at -= delta
        for row in db.query(AgentRolloutDevice):
            row.offered_at -= delta
        db.commit()
    finally:
        db.close()


@pytest.fixture()
def fleet(client, admin, tenant, tmp_path, monkeypatch):
    from fenrir_cloud import deployment_installers

    rollouts._RING_CACHE.clear()
    monkeypatch.setattr(deployment_installers, "DOWNLOADS", tmp_path)
    monkeypatch.setattr(deployment_installers, "SIGNED_RELEASES", tmp_path / "none")
    (tmp_path / "fenrir-agent-linux-amd64").write_bytes(b"\x7fELF new")
    (tmp_path / "linux-build.json").write_text(json.dumps({"version": "1.7.0", "buildId": "newbuild1",
                                                           "sha256": {"amd64": "a" * 64, "arm64": "b" * 64}}))
    canary_tenant = client.post("/api/console/tenants", headers=admin, json={"name": "Canary Co", "template": "balanced"}).json()
    ring(client, admin, canary_tenant, "canary")
    canary = enroll(client, admin, canary_tenant, hostname="CANARY-1", os_version="Ubuntu 22.04.4 LTS", serial="C-1")
    stable = enroll(client, admin, tenant, hostname="STABLE-1", os_version="Ubuntu 22.04.4 LTS", serial="S-1")
    for d in (canary, stable):
        heartbeat(client, d, "oldbuild0")
    return canary, stable


def test_bad_canary_pauses_before_the_next_ring(client, admin, fleet):
    canary, stable = fleet
    assert check(client, canary)["available"] is True
    blocked = check(client, stable)
    assert blocked["available"] is False and "canary" in blocked["rollout"]
    # The canary took the update but is still reporting the old build an hour later.
    backdate(minutes=61)
    heartbeat(client, canary, "oldbuild0")
    backdate(hours=3)  # well past the canary soak time
    blocked = check(client, stable)
    assert blocked["available"] is False and "paused" in blocked["rollout"] and "CANARY-1" in blocked["rollout"]
    listing = client.get("/api/console/agent-rollouts", headers=admin).json()["rollouts"][0]
    assert listing["state"] == "paused" and listing["devices"]["failed"] == 1 and listing["stage"] == "canary"


def test_healthy_canary_advances_after_soak(client, admin, fleet):
    canary, stable = fleet
    assert check(client, canary)["available"] is True
    heartbeat(client, canary, "newbuild1")  # came back on the new build
    assert check(client, stable)["available"] is False  # still soaking
    backdate(hours=2, minutes=5)
    assert check(client, stable)["available"] is True  # beta ring is empty, so stable follows straight after canary
    heartbeat(client, stable, "newbuild1")
    view = client.get("/api/console/agent-rollouts", headers=admin).json()["rollouts"][0]
    assert view["devices"] == {"pending": 0, "updated": 2, "failed": 0}
    assert [h["action"] for h in view["history"]][:2] == ["started", "advanced"]


def test_without_rings_everyone_updates_at_once(client, admin, tenant, tmp_path, monkeypatch):
    from fenrir_cloud import deployment_installers

    rollouts._RING_CACHE.clear()
    monkeypatch.setattr(deployment_installers, "DOWNLOADS", tmp_path)
    monkeypatch.setattr(deployment_installers, "SIGNED_RELEASES", tmp_path / "none")
    (tmp_path / "fenrir-agent-linux-amd64").write_bytes(b"\x7fELF new")
    (tmp_path / "linux-build.json").write_text(json.dumps({"version": "1.7.0", "buildId": "newbuild2", "sha256": {"amd64": "a" * 64}}))
    device = enroll(client, admin, tenant, hostname="ONLY-1", os_version="Ubuntu 22.04.4 LTS", serial="O-1")
    assert check(client, device)["available"] is True


def test_admin_controls_and_permissions(client, admin, tenant, fleet):
    canary, stable = fleet
    check(client, canary)
    rollout_id = client.get("/api/console/agent-rollouts", headers=admin).json()["rollouts"][0]["id"]
    act = lambda action, headers=admin, **extra: client.post(f"/api/console/agent-rollouts/{rollout_id}/action",  # noqa: E731
                                                             headers=headers, json={"action": action, **extra})
    # Customer-side and MSP technician roles cannot touch a platform-wide rollout.
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "ta@acme.example",
                                                           "password": "acme-password-123", "role": "tenant_admin"})
    customer = login(client, "ta@acme.example", "acme-password-123")
    assert client.get("/api/console/agent-rollouts", headers=customer).status_code == 403
    assert act("stop", customer).status_code == 403
    assert act("pause", reason="Investigating reports").json()["state"] == "paused"
    assert check(client, canary)["available"] is False or check(client, canary)["buildId"] == ""
    assert act("pause").status_code == 409  # already paused
    assert act("resume").json()["state"] == "active"
    assert act("advance").json()["stage"] == "beta"
    stopped = act("stop", reason="Crash on boot")
    assert stopped.json()["state"] == "stopped" and "Crash on boot" in stopped.json()["reason"]
    assert check(client, stable)["available"] is False
    assert act("resume").status_code == 409  # a stopped rollout needs a new build
    assert act("explode").status_code == 422
    assert client.post("/api/console/agent-rollouts/rol_missing/action", headers=admin, json={"action": "pause"}).status_code == 404
    audit = client.get("/api/console/audit", headers=admin).json()
    actions = {e["action"] for e in (audit if isinstance(audit, list) else audit.get("items", []))}
    assert {"agent.rollout.pause", "agent.rollout.resume", "agent.rollout.advance", "agent.rollout.stop"} <= actions


def test_new_build_supersedes_the_old_rollout(client, admin, fleet, tmp_path):
    canary, _ = fleet
    check(client, canary)
    (tmp_path / "linux-build.json").write_text(json.dumps({"version": "1.7.1", "buildId": "newbuild3", "sha256": {"amd64": "c" * 64}}))
    check(client, canary)
    states = {r["build"]: r["state"] for r in client.get("/api/console/agent-rollouts", headers=admin).json()["rollouts"]}
    assert states["newbuild1"] == "superseded" and states["newbuild3"] == "active"


def test_agent_refusal_counts_as_failure(client, admin, fleet):
    canary, stable = fleet
    check(client, canary)
    sent = client.post(f"/api/v1/devices/{canary['deviceId']}/telemetry", headers=canary["headers"], json={"events": [
        {"eventId": "e-rej-1", "eventType": "agent.update.rejected", "source": "updater", "summary": "refused",
         "occurredAt": utcnow().isoformat() + "Z", "payloadJson": json.dumps({"reason": "release signature does not match"})}]})
    assert sent.status_code == 200, sent.text
    blocked = check(client, stable)
    assert blocked["available"] is False and "refused" in blocked["rollout"]


def test_devices_that_do_not_auto_update_do_not_fail_the_rollout(client, admin, tenant, fleet):
    canary, stable = fleet
    db = session_factory()()
    try:
        canary_tenant = db.get(__import__("fenrir_cloud.models", fromlist=["Device"]).Device, canary["deviceId"]).tenant_id
    finally:
        db.close()
    policies = client.get(f"/api/console/policies?tenant_id={canary_tenant}", headers=admin).json()
    default = next(p for p in policies if p["name"] and p.get("tenantId") == canary_tenant)
    client.put(f"/api/console/policies/{default['id']}", headers=admin,
               json={"settings": {"updates": {"channel": "canary", "autoUpdateAgent": False}}})
    assert check(client, canary)["available"] is True  # still told what exists
    backdate(minutes=90)
    heartbeat(client, canary, "oldbuild0")  # stays on the old build, as configured
    view = client.get("/api/console/agent-rollouts", headers=admin).json()["rollouts"][0]
    assert view["state"] == "active" and view["devices"]["failed"] == 0


def _linux_build(tmp_path, monkeypatch, build):
    from fenrir_cloud import deployment_installers

    rollouts._RING_CACHE.clear()
    monkeypatch.setattr(deployment_installers, "DOWNLOADS", tmp_path)
    monkeypatch.setattr(deployment_installers, "SIGNED_RELEASES", tmp_path / "none")
    (tmp_path / "fenrir-agent-linux-amd64").write_bytes(b"\x7fELF new")
    (tmp_path / "linux-build.json").write_text(json.dumps({"version": "1.7.0", "buildId": build, "sha256": {"amd64": "a" * 64}}))


def test_without_rings_a_pilot_device_goes_first(client, admin, tenant, tmp_path, monkeypatch):
    _linux_build(tmp_path, monkeypatch, "pilotbuild")
    devices = [enroll(client, admin, tenant, hostname=f"FLEET-{i}", os_version="Ubuntu 22.04.4 LTS", serial=f"F-{i}") for i in range(3)]
    for d in devices:
        heartbeat(client, d, "oldbuild0")
    first, *rest = devices
    assert check(client, first)["available"] is True
    for d in rest:  # everyone else waits for the pilot
        reply = check(client, d)
        assert reply["available"] is False and "first" in reply["rollout"]
    heartbeat(client, first, "pilotbuild")  # the pilot came back on the new build
    assert check(client, rest[0])["available"] is False  # and must keep checking in for a while
    db = session_factory()()
    try:
        for row in db.query(AgentRolloutDevice):
            row.resolved_at -= timedelta(minutes=31)
        db.commit()
    finally:
        db.close()
    assert all(check(client, d)["available"] is True for d in rest)


def test_a_device_silent_after_taking_the_build_pauses_the_rollout_early(client, admin, tenant, tmp_path, monkeypatch):
    from fenrir_cloud.models import Device

    _linux_build(tmp_path, monkeypatch, "silentbuild")
    devices = [enroll(client, admin, tenant, hostname=f"QUIET-{i}", os_version="Ubuntu 22.04.4 LTS", serial=f"Q-{i}") for i in range(2)]
    for d in devices:
        heartbeat(client, d, "oldbuild0")
    assert check(client, devices[0])["available"] is True
    backdate(minutes=25)  # offered 25 minutes ago ...
    db = session_factory()()
    try:  # ... and not heard from since just after
        row = db.get(Device, devices[0]["deviceId"])
        row.last_seen_at = utcnow() - timedelta(minutes=24)
        db.commit()
    finally:
        db.close()
    reply = check(client, devices[1])
    assert reply["available"] is False and "paused" in reply["rollout"] and "stopped checking in" in reply["rollout"]
