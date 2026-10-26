import json
from datetime import datetime, timedelta

from conftest import enroll

from fenrir_cloud import db as database, rmm
from fenrir_cloud.models import Device, PatchPolicy, utcnow


def poll(client, device):
    return client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]


def complete(client, device, command_id, result, status="completed"):
    response = client.post(f"/api/v1/devices/{device['deviceId']}/commands/{command_id}/complete",
                           json={"status": status, "resultJson": json.dumps(result)}, headers=device["headers"])
    assert response.status_code == 200, response.text


def test_builtin_library_is_seeded(client, admin):
    scripts = client.get("/api/console/rmm/scripts", headers=admin).json()
    assert any(s["name"] == "Clear temporary files" and s["builtin"] for s in scripts)
    assert any(s["language"] == "bash" for s in scripts)
    packages = client.get("/api/console/rmm/software", headers=admin).json()
    assert any(p["identifier"] == "Google.Chrome" for p in packages)
    conditions = client.get("/api/console/rmm/conditions", headers=admin).json()
    assert "cpu" in conditions["metrics"] and conditions["conditions"]


def test_script_parameters_are_quoted_and_results_reach_the_job(client, admin, tenant, device):
    script = client.post("/api/console/rmm/scripts", headers=admin, json={
        "name": "Echo", "language": "powershell", "body": "Write-Output $Message",
        "parameters": [{"name": "Message", "label": "Message", "type": "string", "required": True}]}).json()
    bad = client.post(f"/api/console/rmm/scripts/{script['id']}/run", headers=admin,
                      json={"targets": {"deviceIds": [device["deviceId"]]}, "parameters": {}})
    assert bad.status_code == 400 and "required" in bad.text
    job = client.post(f"/api/console/rmm/scripts/{script['id']}/run", headers=admin,
                      json={"targets": {"deviceIds": [device["deviceId"]]}, "parameters": {"Message": "it's'; Remove-Item C:\\ -Recurse"}}).json()
    assert job["status"] == "running" and job["summary"]["total"] == 1
    [command] = poll(client, device)
    payload = json.loads(command["payloadJson"])
    assert command["type"] == "script.run" and payload["language"] == "powershell"
    # Single quotes are doubled so the value can never break out of the string literal.
    assert payload["body"].startswith("$Message = 'it''s''; Remove-Item C:\\ -Recurse'\n")
    assert payload["environment"]["FENRIR_MESSAGE"] == "it's'; Remove-Item C:\\ -Recurse"
    assert "body" not in job["payload"]
    complete(client, device, command["id"], {"exitCode": 0, "stdout": "hello\n", "stderr": "", "durationMs": 120})
    detail = client.get(f"/api/console/rmm/jobs/{job['id']}", headers=admin).json()
    assert detail["status"] == "completed"
    assert detail["results"][0]["stdout"] == "hello\n" and detail["results"][0]["exitCode"] == 0


def test_bash_parameters_and_platform_filtering(client, admin, tenant):
    linux = enroll(client, admin, tenant, hostname="web-01", os_version="Ubuntu 24.04 LTS", serial="L1")
    windows = enroll(client, admin, tenant, hostname="WS-02", serial="W2")
    script = client.post("/api/console/rmm/scripts", headers=admin, json={
        "name": "Greet", "language": "bash", "body": "#!/bin/bash\necho \"$Name\"",
        "parameters": [{"name": "Name", "type": "string", "default": "x'y"}]}).json()
    assert script["platforms"] == ["linux", "macos"]
    job = client.post(f"/api/console/rmm/scripts/{script['id']}/run", headers=admin,
                      json={"targets": {"tenantIds": [tenant["id"]]}}).json()
    assert job["summary"]["total"] == 1 and job["summary"]["skipped"] == 1
    [command] = poll(client, linux)
    body = json.loads(command["payloadJson"])["body"]
    assert body.startswith("#!/bin/bash\nName='x'\"'\"'y'\n")
    assert poll(client, windows) == []


def test_heartbeat_metrics_trigger_and_clear_monitors(client, admin, tenant, device):
    condition = client.post("/api/console/rmm/conditions", headers=admin, json={
        "name": "Disk nearly full", "metric": "disk_free_percent", "operator": "<", "threshold": 10, "durationMinutes": 0,
        "severity": "high", "tenantId": tenant["id"], "actions": [{"type": "ticket"}]}).json()
    beat = lambda free: client.post(f"/api/v1/devices/{device['deviceId']}/heartbeat", headers=device["headers"], json={
        "agentVersion": "2.0", "healthState": "healthy",
        "metrics": {"cpuPercent": 12, "memoryPercent": 40, "uptimeSeconds": 7200, "loggedOnUser": "ACME\\jo",
                    "disks": [{"mount": "C:", "totalGb": 237, "freeGb": 237 * free / 100, "freePercent": free}]}})
    assert beat(40).status_code == 200
    assert client.get("/api/console/rmm/monitoring", headers=admin).json() == []
    beat(4)
    active = client.get("/api/console/rmm/monitoring", headers=admin).json()
    assert [a["condition"] for a in active] == ["Disk nearly full"]
    assert "C: has 4.0% free" in active[0]["message"]
    tickets = client.get("/api/console/tickets", headers=admin).json()
    assert tickets[0]["source"] == "rmm" and tickets[0]["deviceId"] == device["deviceId"]
    metrics = client.get(f"/api/console/rmm/devices/{device['deviceId']}/metrics", headers=admin).json()
    assert metrics["current"]["loggedOnUser"] == "ACME\\jo" and len(metrics["series"]) == 2
    beat(50)
    assert client.get("/api/console/rmm/monitoring", headers=admin).json() == []
    ticket = client.get(f"/api/console/tickets/{tickets[0]['id']}", headers=admin).json()
    assert ticket["status"] == "Resolved"
    alerts = client.get("/api/console/rmm/alerts", headers=admin).json()
    assert alerts[0]["status"] == "resolved" and alerts[0]["details"]["category"] == "monitoring"
    assert condition["id"]


def test_offline_monitor_runs_from_the_scheduler(client, admin, tenant, device):
    client.post("/api/console/rmm/conditions", headers=admin, json={
        "name": "Offline", "metric": "offline_minutes", "operator": ">", "threshold": 15, "tenantId": tenant["id"]})
    session = database.session_factory()()
    try:
        row = session.get(Device, device["deviceId"])
        row.last_seen_at = utcnow() - timedelta(minutes=45)
        session.commit()
        assert rmm.evaluate_offline(session) == 1
        session.commit()
    finally:
        session.close()
    active = client.get("/api/console/rmm/monitoring", headers=admin).json()
    assert active and active[0]["metric"] == "offline_minutes"


def test_patch_scan_approval_and_install(client, admin, tenant, device):
    job = client.post("/api/console/rmm/patches/scan", headers=admin, json={"targets": {"deviceIds": [device["deviceId"]]}}).json()
    [command] = poll(client, device)
    assert command["type"] == "patch.scan"
    complete(client, device, command["id"], {"rebootPending": False, "patches": [
        {"id": "KB5048685", "title": "2026-10 Cumulative Update for Windows 11", "classification": "Security Updates", "severity": "Critical"},
        {"id": "KB5049999", "title": "Feature update to Windows 11 25H2", "classification": "Upgrades"},
        {"id": "winget:Mozilla.Firefox", "title": "Firefox 131 -> 132", "source": "winget", "installedVersion": "131.0",
         "availableVersion": "132.0"},
        {"id": "KB890830", "title": "Malicious Software Removal Tool", "classification": "Updates"},
    ]})
    assert client.get(f"/api/console/rmm/jobs/{job['id']}", headers=admin).json()["status"] == "completed"
    catalogue = {p["patchKey"]: p for p in client.get("/api/console/rmm/patches", headers=admin).json()}
    assert catalogue["KB5048685"]["classification"] == "critical" and catalogue["KB5048685"]["approvalState"] == "approved"
    assert catalogue["KB5049999"]["classification"] == "feature" and catalogue["KB5049999"]["approvalState"] == "rejected"
    assert catalogue["winget:Mozilla.Firefox"]["classification"] == "third-party"
    assert catalogue["KB890830"]["approvalState"] == "pending"
    client.post("/api/console/rmm/patches/approve", headers=admin, json={"patchKeys": ["KB890830"], "decision": "approved"})
    compliance = client.get("/api/console/rmm/patches/compliance", headers=admin).json()
    assert compliance["scanned"] == 1 and compliance["missingCriticalOrSecurity"] == 1 and compliance["fullyPatched"] == 0

    install = client.post("/api/console/rmm/patches/install", headers=admin, json={"targets": {"deviceIds": [device["deviceId"]]}}).json()
    [command] = poll(client, device)
    payload = json.loads(command["payloadJson"])
    assert command["type"] == "patch.install"
    assert sorted(payload["patchIds"]) == ["KB5048685", "KB890830", "winget:Mozilla.Firefox"]
    complete(client, device, command["id"], {"rebootRequired": True, "results": [
        {"id": "KB5048685", "success": True}, {"id": "KB890830", "success": True},
        {"id": "winget:Mozilla.Firefox", "success": False, "error": "installer exit code 1603"}]})
    patches = {p["patchKey"]: p for p in client.get(f"/api/console/rmm/devices/{device['deviceId']}/patches", headers=admin).json()["patches"]}
    assert patches["KB5048685"]["status"] == "installed"
    assert patches["winget:Mozilla.Firefox"]["status"] == "failed" and "1603" in patches["winget:Mozilla.Firefox"]["error"]
    assert client.get(f"/api/console/rmm/jobs/{install['id']}", headers=admin).json()["status"] == "completed"
    detail = client.get(f"/api/console/devices/{device['deviceId']}", headers=admin).json()
    assert detail["device"]["metrics"]["rebootPending"] is True


def test_maintenance_window_queues_installs_once(client, admin, tenant, device):
    client.post("/api/console/rmm/patch-policies", headers=admin, json={
        "tenantId": tenant["id"], "name": "Weeknights", "window": {"days": [0, 1, 2, 3, 4, 5, 6], "start": "02:00",
                                                                    "durationMinutes": 120, "tz": "UTC"},
        "rings": [{"name": "Broad", "groupIds": [], "delayDays": 0}]})
    session = database.session_factory()()
    try:
        row = session.get(Device, device["deviceId"])
        rmm.ingest_patch_scan(session, row, {"patches": [{"id": "KB1", "title": "Security update", "classification": "Security Updates"}]})
        session.commit()
        inside = datetime(2026, 10, 21, 2, 30)
        outside = datetime(2026, 10, 21, 12, 0)
        assert rmm.run_patch_windows(session, outside) == 0
        assert rmm.run_patch_windows(session, inside) == 1
        assert rmm.run_patch_windows(session, inside + timedelta(minutes=10)) == 0  # same window: not again
        session.commit()
        assert session.query(PatchPolicy).one().last_window_run == "2026-10-21T02:00"
    finally:
        session.close()
    commands = [c for c in poll(client, device) if c["type"] == "patch.install"]
    assert len(commands) == 1 and json.loads(commands[0]["payloadJson"])["patchIds"] == ["KB1"]


def test_ring_delay_holds_auto_approved_patches(client, admin, tenant, device):
    session = database.session_factory()()
    try:
        policy = PatchPolicy(tenant_id=tenant["id"], name="Delayed", approvals=dict(rmm.DEFAULT_APPROVALS), window={}, reboot={},
                             rings=[{"name": "Broad", "groupIds": [], "delayDays": 7}])
        session.add(policy)
        row = session.get(Device, device["deviceId"])
        rmm.ingest_patch_scan(session, row, {"patches": [{"id": "KB2", "title": "Security", "classification": "Security Updates",
                                                          "releasedAt": (utcnow() - timedelta(days=2)).isoformat() + "Z"},
                                                         {"id": "KB3", "title": "Security", "classification": "Security Updates",
                                                          "releasedAt": (utcnow() - timedelta(days=9)).isoformat() + "Z"}]})
        session.flush()
        assert [p.patch_key for p in rmm.installable_patches(session, row, policy)] == ["KB3"]
    finally:
        session.close()


def test_schedule_maths():
    after = datetime(2026, 10, 22, 10, 0)  # Thursday
    assert rmm.next_run({"type": "daily", "at": "02:00"}, after) == datetime(2026, 10, 23, 2, 0)
    assert rmm.next_run({"type": "weekly", "at": "03:30", "days": [5]}, after) == datetime(2026, 10, 24, 3, 30)
    assert rmm.next_run({"type": "monthly", "at": "01:00", "dayOfMonth": 1}, after) == datetime(2026, 11, 1, 1, 0)
    assert rmm.next_run({"type": "interval", "everyMinutes": 30}, after) == datetime(2026, 10, 22, 10, 30)
    assert rmm.next_run({"type": "once", "date": "2026-10-01", "at": "09:00"}, after) is None
    # Europe/London is UTC+1 in October before the clocks change.
    assert rmm.next_run({"type": "daily", "at": "09:00", "tz": "Europe/London"}, after) == datetime(2026, 10, 23, 8, 0)
    inside, key = rmm.in_window({"days": [3], "start": "23:00", "durationMinutes": 180, "tz": "UTC"}, datetime(2026, 10, 23, 1, 0))
    assert inside and key == "2026-10-22T23:00"


def test_scheduled_task_and_bulk_jobs(client, admin, tenant):
    linux = enroll(client, admin, tenant, hostname="db-01", os_version="Debian 12", serial="D1")
    windows = enroll(client, admin, tenant, hostname="WS-09", serial="W9")
    script = next(s for s in client.get("/api/console/rmm/scripts", headers=admin).json() if s["name"] == "Top processes")
    task = client.post("/api/console/rmm/tasks", headers=admin, json={
        "tenantId": tenant["id"], "name": "Nightly checks", "schedule": {"type": "daily", "at": "01:00"},
        "targets": {"tenantIds": [tenant["id"]]},
        "actions": [{"type": "script", "scriptId": script["id"]}, {"type": "command", "command": "patch.scan"}]}).json()
    assert task["nextRunAt"]
    jobs = client.post(f"/api/console/rmm/tasks/{task['id']}/run", headers=admin).json()
    assert [j["summary"]["total"] for j in jobs] == [1, 2]
    assert {c["type"] for c in poll(client, linux)} == {"script.run", "patch.scan"}
    assert {c["type"] for c in poll(client, windows)} == {"patch.scan"}
    bulk = client.post("/api/console/rmm/jobs", headers=admin, json={"commandType": "device.reboot", "targets": {"deviceIds": [windows["deviceId"]]},
                                                                     "payload": {"delayMinutes": 5}}).json()
    assert bulk["summary"]["total"] == 1
    cancelled = client.post(f"/api/console/rmm/jobs/{bulk['id']}/cancel", headers=admin).json()
    assert cancelled["status"] == "cancelled"
    assert client.post("/api/console/rmm/jobs", headers=admin,
                       json={"commandType": "remote.session.start", "targets": {"deviceIds": [windows["deviceId"]]}}).status_code == 400


def test_software_deploy_targets_matching_platform(client, admin, tenant):
    linux = enroll(client, admin, tenant, hostname="app-01", os_version="Ubuntu 22.04", serial="A1")
    windows = enroll(client, admin, tenant, hostname="WS-11", serial="W11")
    chrome = next(p for p in client.get("/api/console/rmm/software", headers=admin).json() if p["identifier"] == "Google.Chrome")
    job = client.post(f"/api/console/rmm/software/{chrome['id']}/deploy", headers=admin,
                      json={"targets": {"tenantIds": [tenant["id"]]}}).json()
    assert job["summary"]["total"] == 1
    [command] = poll(client, windows)
    assert command["type"] == "software.install" and json.loads(command["payloadJson"])["identifier"] == "Google.Chrome"
    assert poll(client, linux) == []
    bad = client.post("/api/console/rmm/software", headers=admin, json={"name": "Tool", "installer": "msi",
                                                                        "identifier": "http://example.test/tool.msi"})
    assert bad.status_code == 400
    ok = client.post("/api/console/rmm/software", headers=admin, json={"name": "Tool", "installer": "msi",
                                                                       "identifier": "https://example.test/tool.msi", "sha256": "A" * 64})
    assert ok.status_code == 200 and ok.json()["sha256"] == "a" * 64


def test_overview_counts(client, admin, tenant, device):
    overview = client.get("/api/console/rmm/overview", headers=admin).json()
    assert overview["devices"] == 1 and overview["online"] == 1
    assert "compliancePercent" in overview["patching"]


def test_builtin_scripts_cannot_be_edited_by_tenant_admins(client, admin, tenant):
    from conftest import login

    client.post("/api/console/users", headers=admin, json={"email": "ta@acme.test", "password": "a-long-password-1", "name": "TA",
                                                           "role": "tenant_admin", "tenantId": tenant["id"]})
    ta = login(client, "ta@acme.test", "a-long-password-1")
    builtin = next(s for s in client.get("/api/console/rmm/scripts", headers=ta).json() if s["builtin"])
    assert client.patch(f"/api/console/rmm/scripts/{builtin['id']}", headers=ta, json={"body": "x"}).status_code == 403


def test_windows_nested_inventory_snapshot_is_recorded(client, admin, tenant, device):
    """The Windows service sends {"cycle": n, "inventory": {...installedSoftware...}} as payloadJson."""
    import json as _json

    payload = {"cycle": 1, "inventory": {"privateIpAddresses": ["10.0.0.5"], "lastLoggedOnUser": "ACME\\jo",
                                         "installedSoftware": [{"id": "7zip", "displayName": "7-Zip 23.01 (x64)", "displayVersion": "23.01",
                                                                "publisher": "Igor Pavlov"}]}}
    response = client.post(f"/api/v1/devices/{device['deviceId']}/telemetry", headers=device["headers"], json={"events": [{
        "eventId": "inv-win-1", "eventType": "device.inventory.snapshot", "source": "device-inventory", "summary": "inventory",
        "occurredAt": "2030-01-01T00:00:00Z", "payloadJson": _json.dumps(payload)}]})
    assert response.status_code == 200
    detail = client.get(f"/api/console/devices/{device['deviceId']}", headers=admin).json()
    assert [s["name"] for s in detail["software"]] == ["7-Zip 23.01 (x64)"] and detail["software"][0]["vendor"] == "Igor Pavlov"
    inventory = detail["device"]["inventory"] if "device" in detail else detail["inventory"]
    assert inventory["ipAddresses"] == ["10.0.0.5"] and inventory["loggedOnUser"] == "ACME\\jo"
    # A later snapshot without a software list (e.g. a periodic status snapshot) keeps the stored software.
    client.post(f"/api/v1/devices/{device['deviceId']}/telemetry", headers=device["headers"], json={"events": [{
        "eventId": "inv-win-2", "eventType": "device.inventory.snapshot", "occurredAt": "2030-01-01T00:01:00Z",
        "payloadJson": _json.dumps({"cycle": 2, "inventory": {"lastLoggedOnUser": "ACME\\sam"}})}]})
    detail = client.get(f"/api/console/devices/{device['deviceId']}", headers=admin).json()
    assert len(detail["software"]) == 1


def test_linux_agent_update_metadata(client, device, tmp_path, monkeypatch):
    import hashlib as _hashlib
    import json as _json

    from fenrir_cloud import deployment_installers

    monkeypatch.setattr(deployment_installers, "DOWNLOADS", tmp_path)
    assert client.get("/api/v1/agent/update/linux?arch=amd64").status_code == 401
    assert client.get("/api/v1/agent/update/linux?arch=amd64", headers=device["headers"]).json()["available"] is False
    binary = b"\x7fELF fake agent"
    (tmp_path / "fenrir-agent-linux-amd64").write_bytes(binary)
    (tmp_path / "linux-build.json").write_text(_json.dumps({"version": "1.2.0", "sha256": {"amd64": _hashlib.sha256(binary).hexdigest(),
                                                                                          "arm64": "0" * 64}}))
    info = client.get("/api/v1/agent/update/linux?arch=amd64", headers=device["headers"]).json()
    assert info == {"available": True, "version": "1.2.0", "buildId": "", "sha256": _hashlib.sha256(binary).hexdigest(),
                    "url": "/downloads/fenrir-agent-linux-amd64", "autoUpdate": True}
    assert client.get("/api/v1/agent/update/linux?arch=mips", headers=device["headers"]).status_code == 422


def test_macos_agent_update_metadata(client, device, tmp_path, monkeypatch):
    import hashlib as _hashlib
    import json as _json

    from fenrir_cloud import deployment_installers

    monkeypatch.setattr(deployment_installers, "DOWNLOADS", tmp_path)
    binary = b"macho fake agent"
    (tmp_path / "fenrir-agent-darwin-arm64").write_bytes(binary)
    (tmp_path / "linux-build.json").write_text(_json.dumps({
        "version": "1.3.0", "sha256": {"amd64": "1" * 64, "arm64": "2" * 64},
        "darwinSha256": {"amd64": "3" * 64, "arm64": _hashlib.sha256(binary).hexdigest()}}))
    info = client.get("/api/v1/agent/update/macos?arch=arm64", headers=device["headers"]).json()
    assert info == {"available": True, "version": "1.3.0", "buildId": "", "sha256": _hashlib.sha256(binary).hexdigest(),
                    "url": "/downloads/fenrir-agent-darwin-arm64", "autoUpdate": True}
    assert client.get("/api/v1/agent/update/macos?arch=amd64", headers=device["headers"]).json()["available"] is False
    assert client.get("/api/v1/agent/update/beos?arch=amd64", headers=device["headers"]).status_code == 422


def test_maintenance_window_parsing():
    assert rmm.parse_maintenance_window("daily 22:00-05:00") == {"days": [0, 1, 2, 3, 4, 5, 6], "start": "22:00", "durationMinutes": 420, "tz": "UTC"}
    assert rmm.parse_maintenance_window("weekdays 19:00-23:30", "Europe/London")["days"] == [0, 1, 2, 3, 4]
    assert rmm.parse_maintenance_window("sat,sun 02:00-06:00")["days"] == [5, 6]
    assert rmm.parse_maintenance_window("fri-mon 01:00-02:00")["days"] == [0, 4, 5, 6]
    assert rmm.parse_maintenance_window("nonsense") == {**rmm.DEFAULT_WINDOW, "tz": "UTC"}


def _protection_patch_settings(client, admin, tenant, **patch):
    response = client.put(f"/api/console/policies/{tenant['defaultPolicyId']}", headers=admin, json={"settings": {"patch": patch}})
    assert response.status_code == 200, response.text


def _report_patches(client, device, patches, released=None):
    from fenrir_cloud.models import DevicePatch

    released = released or utcnow() - timedelta(days=2)
    session = database.session_factory()()
    try:
        row = session.get(Device, device["deviceId"])
        rmm.ingest_patch_scan(session, row, {"patches": patches})
        for patch in session.query(DevicePatch).filter_by(device_id=row.id):
            patch.released_at = released
            patch.first_seen_at = released
        session.commit()
    finally:
        session.close()


def _window_run(at):
    session = database.session_factory()()
    try:
        queued = rmm.run_patch_windows(session, at)
        session.commit()
        return queued
    finally:
        session.close()


def test_protection_policy_patch_settings_drive_patching(client, admin, tenant, device):
    now = utcnow()
    monday = (now + timedelta(days=(7 - now.weekday()) % 7 or 7)).replace(hour=0, minute=0, second=0, microsecond=0)
    _report_patches(client, device, [
        {"id": "KB5048685", "title": "Cumulative Update", "classification": "Security Updates", "severity": "Critical"},
        {"id": "winget:Mozilla.Firefox", "title": "Firefox", "source": "winget", "installedVersion": "131.0", "availableVersion": "132.0"},
        {"id": "KB890830", "title": "Malicious Software Removal Tool", "classification": "Updates"},
    ], released=monday - timedelta(days=2))
    # Defaults: automatic window installs are off, so nothing is queued even inside the window.
    monday_night, tuesday_night = monday.replace(hour=23), (monday + timedelta(days=1)).replace(hour=23)
    assert _window_run(monday_night) == 0
    detail = client.get(f"/api/console/rmm/devices/{device['deviceId']}/patches", headers=admin).json()
    assert detail["policy"]["name"] == "Protection policy patch settings"
    approvals = {p["patchKey"]: p["approval"] for p in detail["patches"]}
    assert approvals == {"KB5048685": "approved", "winget:Mozilla.Firefox": "approved", "KB890830": "pending"}

    _protection_patch_settings(client, admin, tenant, installInWindow=True, maintenanceWindow="weekdays 22:00-05:00",
                               deferralDaysCritical=0, deferralDaysOther=7, rebootBehaviour="force", thirdPartyApps=True)
    assert _window_run(monday.replace(hour=12)) == 0  # outside the window
    assert _window_run(monday_night) == 1
    [command] = [c for c in poll(client, device) if c["type"] == "patch.install"]
    payload = json.loads(command["payloadJson"])
    # Critical goes now; Firefox (released 2 days ago) waits for the 7-day deferral; reboot follows "force".
    assert payload["patchIds"] == ["KB5048685"] and payload["reboot"]["mode"] == "always"
    assert _window_run(monday_night) == 0  # once per window

    # Known-exploited vulnerability in Firefox on this device: its fix skips the deferral.
    from fenrir_cloud.models import Vulnerability

    session = database.session_factory()()
    try:
        session.add(Vulnerability(tenant_id=tenant["id"], device_id=device["deviceId"], vuln_id="CVE-2030-0001", package="Mozilla.Firefox",
                                  severity="critical", known_exploited=True))
        session.commit()
    finally:
        session.close()
    complete(client, device, command["id"], {"results": [{"id": "KB5048685", "success": True}]})
    assert _window_run(tuesday_night) == 1
    install = [c for c in poll(client, device) if c["type"] == "patch.install"][-1]
    assert json.loads(install["payloadJson"])["patchIds"] == ["winget:Mozilla.Firefox"]

    # Turning third-party patching off rejects winget updates.
    _protection_patch_settings(client, admin, tenant, thirdPartyApps=False, installInWindow=True)
    detail = client.get(f"/api/console/rmm/devices/{device['deviceId']}/patches", headers=admin).json()
    assert {p["patchKey"]: p["approval"] for p in detail["patches"]}["winget:Mozilla.Firefox"] == "rejected"


def test_rmm_patch_policy_still_wins_over_protection_policy(client, admin, tenant, device):
    session = database.session_factory()()
    try:
        session.add(PatchPolicy(tenant_id=tenant["id"], name="Servers", approvals={"third-party": "reject"}))
        session.commit()
    finally:
        session.close()
    detail = client.get(f"/api/console/rmm/devices/{device['deviceId']}/patches", headers=admin).json()
    assert detail["policy"]["name"] == "Servers"


def test_missing_windows_security_updates_become_vulnerabilities(client, admin, device):
    from fenrir_cloud import exposure
    from fenrir_cloud.models import Vulnerability

    patches = [
        {"id": "KB5040001", "title": "2030-01 Cumulative Update", "classification": "Security Updates", "severity": "Important",
         "source": "windows-update", "cves": "CVE-2030-0001,CVE-2030-0002"},
        {"id": "KB5040002", "title": "Feature pack", "classification": "Feature Packs", "severity": "", "source": "windows-update"},
        {"id": "winget:Mozilla.Firefox", "title": "Firefox", "source": "winget", "availableVersion": "200"},
    ]
    old_cache = exposure._KEV_CACHE
    exposure._KEV_CACHE = (0.0, {"CVE-2030-0002"})
    session = database.session_factory()()
    try:
        row = session.get(Device, device["deviceId"])
        rmm.ingest_patch_scan(session, row, {"patches": patches})
        session.commit()
        vulns = session.query(Vulnerability).filter_by(device_id=row.id).all()
        assert [(v.vuln_id, v.package, v.source, v.status) for v in vulns] == [("KB5040001", "Windows", "windows-update", "open")]
        assert vulns[0].known_exploited and vulns[0].severity == "critical"
        assert "CVE-2030-0001" in vulns[0].summary and vulns[0].fixed_version == "KB5040001"
        # An unrelated OSV rescan must not close update-based findings.
        from fenrir_cloud import vulnmgmt
        assert vulnmgmt.verify_after_scan(session, row, utcnow() + timedelta(seconds=5)) == 0
        rmm.ingest_patch_scan(session, row, {"patches": patches[1:]})
        session.commit()
        fixed = session.query(Vulnerability).filter_by(device_id=row.id).one()
        assert fixed.status == "fixed" and fixed.verified_at is not None
    finally:
        exposure._KEV_CACHE = old_cache
        session.close()


def test_windows_agent_update_by_build_id(client, admin, tenant, device, tmp_path, monkeypatch):
    import hashlib as _hashlib
    import json as _json

    from fenrir_cloud import deployment_installers

    monkeypatch.setattr(deployment_installers, "DOWNLOADS", tmp_path)
    url = "/api/v1/agent/update/windows"
    assert client.get(url).status_code == 401
    assert client.get(url, headers=device["headers"]).json()["available"] is False
    (tmp_path / "windows").mkdir()
    setup = b"MZ fake setup"
    (tmp_path / "windows" / "FenrirSetup.exe").write_bytes(setup)
    meta = {"sha256": _hashlib.sha256(setup).hexdigest(), "platform": "windows-x64", "mode": "unsigned-hobby"}
    (tmp_path / "windows" / "build.json").write_text(_json.dumps(meta))
    # Images built before build ids existed are never offered (agents could not compare them).
    assert client.get(url, headers=device["headers"]).json()["available"] is False
    (tmp_path / "windows" / "build.json").write_text(_json.dumps({**meta, "buildId": "0123456789abcdef"}))
    info = client.get(url, headers=device["headers"]).json()
    assert info == {"available": True, "autoUpdate": True, "buildId": "0123456789abcdef", "sha256": meta["sha256"],
                    "url": "/api/v1/agent/update/windows/package"}
    assert client.get(info["url"]).status_code == 401
    package = client.get(info["url"], headers=device["headers"])
    assert package.status_code == 200 and package.content == setup
    # Turning automatic updates off in the policy is passed to the agent.
    pid = client.post("/api/console/policies", json={"name": "No auto update", "tenantId": tenant["id"],
                                                      "settings": {"updates": {"autoUpdateAgent": False}}}, headers=admin).json()["id"]
    client.patch(f"/api/console/devices/{device['deviceId']}", json={"policyId": pid}, headers=admin)
    assert client.get(url, headers=device["headers"]).json()["autoUpdate"] is False
