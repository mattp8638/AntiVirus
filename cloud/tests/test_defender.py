"""Managed Microsoft Defender: policy becomes Defender settings, Defender's state and detections come back as alerts."""

import json
from datetime import timedelta

from conftest import enroll
from fenrir_cloud import db as database, defender
from fenrir_cloud.models import Command, DefenderState, Device, utcnow

LSASS = defender.ASR_GUIDS["blockCredentialStealingLsass"]
PSEXEC = defender.ASR_GUIDS["blockPsexecWmiProcessCreation"]


def _manage(client, admin, tenant, device, **defender_settings):
    created = client.post("/api/console/policies", headers=admin, json={
        "tenantId": tenant["id"], "name": "Managed Defender",
        "settings": {"defender": {"managed": True, **defender_settings}}})
    assert created.status_code == 200, created.text
    assert client.patch(f"/api/console/devices/{device['deviceId']}", headers=admin,
                        json={"policyId": created.json()["id"]}).status_code == 200
    return created.json()


def _report(**overrides) -> dict:
    status = {"available": True, "mode": "Normal", "antivirus": True, "realTime": True, "tamper": False, "signatureAgeDays": 0,
              "signatureVersion": "1.421.0.0", "product": "4.18.25010.11", "quickScanAgeDays": 1, "cloudBlockLevel": 2, "maps": 2,
              "pua": 1, "networkProtection": 2, "controlledFolderAccess": 0,
              "asr": {guid: (2 if key in ("blockPsexecWmiProcessCreation", "blockWebshellCreation") else 1)
                      for key, guid in defender.ASR_GUIDS.items()},
              "exclusions": {"paths": [], "processes": [], "extensions": []}, "detections": [], "errors": []}
    return {**status, **overrides}


def _complete(client, device, command_id, status: dict, outcome="completed"):
    stdout = "some output\n" + defender.MARKER + json.dumps(status)
    reply = client.post(f"/api/v1/devices/{device['deviceId']}/commands/{command_id}/complete", headers=device["headers"],
                        json={"status": outcome, "resultJson": json.dumps({"exitCode": 0, "stdout": stdout})})
    assert reply.status_code == 200, reply.text


def _check(client, admin, device) -> str:
    reply = client.post(f"/api/console/devices/{device['deviceId']}/defender/check", headers=admin)
    assert reply.status_code == 200, reply.text
    return reply.json()["commandId"]


def _seen(device):
    with database.session_factory()() as db:
        db.get(Device, device["deviceId"]).last_seen_at = utcnow()
        db.commit()


def test_policy_becomes_defender_settings_and_attack_surface_rules(client, admin, tenant, device):
    _manage(client, admin, tenant, device, cloudProtection="highPlus", networkProtection="block", exclusionPaths=["C:\\Line of business"])
    command_id = _check(client, admin, device)
    with database.session_factory()() as db:
        command = db.get(Command, command_id)
        body = command.payload["body"]
        assert command.type == "script.run" and command.payload["defender"] == "apply" and command.payload["runAs"] == "system"
    assert "-CloudBlockLevel HighPlus" in body and "-EnableNetworkProtection Enabled" in body and "-PUAProtection Enabled" in body
    assert LSASS in body and "Add-MpPreference -ExclusionPath @('C:\\Line of business')" in body
    # Fenrir's own attack surface rules decide each Defender rule: PsExec/WMI is audit by default.
    ids = body.split("-AttackSurfaceReductionRules_Ids @(")[1].split(")")[0].replace("'", "").split(",")
    actions = body.split("-AttackSurfaceReductionRules_Actions @(")[1].split(")")[0].replace("'", "").split(",")
    assert dict(zip(ids, actions))[PSEXEC] == "AuditMode" and dict(zip(ids, actions))[LSASS] == "Enabled"

    _complete(client, device, command_id, _report())
    view = client.get(f"/api/console/devices/{device['deviceId']}/defender", headers=admin).json()
    assert view["managed"] and view["inSync"] and view["problems"] == [] and not view["checking"]
    assert any("Tamper protection is off" in tip for tip in view["advice"])
    assert next(r for r in view["rules"] if r["key"] == "blockCredentialStealingLsass") == {
        "key": "blockCredentialStealingLsass", "guid": LSASS, "wanted": "block", "actual": "block"}


def test_unmanaged_devices_are_only_read(client, admin, tenant, device):
    command_id = _check(client, admin, device)
    with database.session_factory()() as db:
        body = db.get(Command, command_id).payload["body"]
    assert "Set-MpPreference" not in body and "Add-MpPreference" not in body and "Get-MpComputerStatus" in body
    _complete(client, device, command_id, _report(realTime=False, detections=[
        {"id": "{D1}", "threatId": "2147519003", "name": "Virus:DOS/EICAR_Test_File", "severity": 5, "resources": ["file:_C:\\x.com"]}]))
    alerts = client.get("/api/console/alerts", headers=admin, params={"device_id": device["deviceId"]}).json()
    assert not [a for a in alerts if a["ruleId"].startswith("defender:")]  # not managed: nothing raised about Defender


def test_detections_become_alerts_once_and_reach_the_inbox(client, admin, tenant, device):
    _manage(client, admin, tenant, device)
    detection = {"id": "{6E3D}", "threatId": "2147519003", "name": "Virus:DOS/EICAR_Test_File", "severity": 5,
                 "resources": ["file:_C:\\Users\\jo\\Downloads\\eicar.com"], "actionSuccess": True, "at": utcnow().isoformat() + "Z",
                 "process": "C:\\Windows\\explorer.exe", "user": "ACME\\jo"}
    for _ in range(2):  # the same detection reported twice is one alert
        _complete(client, device, _check(client, admin, device), _report(detections=[detection]))
    alerts = [a for a in client.get("/api/console/alerts", headers=admin, params={"device_id": device["deviceId"]}).json()
              if a["ruleId"].startswith("defender:")]
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["title"] == "Microsoft Defender: Virus:DOS/EICAR_Test_File" and alert["severity"] == "critical"
    assert alert["details"]["file"] == "C:\\Users\\jo\\Downloads\\eicar.com" and alert["details"]["handled"] is True
    inbox = client.get("/api/console/triage/items", headers=admin).json()["items"]
    assert any(i["title"] == "Microsoft Defender: Virus:DOS/EICAR_Test_File" for i in inbox)


def test_defender_switched_off_or_passive_raises_a_protection_alert_until_it_is_back(client, admin, tenant, device):
    _manage(client, admin, tenant, device)
    _complete(client, device, _check(client, admin, device), _report(mode="Passive Mode", realTime=False))
    view = client.get(f"/api/console/devices/{device['deviceId']}/defender", headers=admin).json()
    assert any("Passive Mode" in p for p in view["problems"]) and any("real-time" in p for p in view["problems"])
    off = [a for a in client.get("/api/console/alerts", headers=admin, params={"device_id": device["deviceId"]}).json()
           if a["ruleId"] == defender.OFF_RULE]
    assert len(off) == 1 and off[0]["status"] == "new" and off[0]["severity"] == "high"
    _complete(client, device, _check(client, admin, device), _report())
    statuses = {a["status"] for a in client.get("/api/console/alerts", headers=admin,
                                                params={"device_id": device["deviceId"], "snoozed": "all"}).json()
                if a["ruleId"] == defender.OFF_RULE}
    assert statuses == {"resolved"}


def test_rules_overridden_on_the_device_are_reported_as_drift(client, admin, tenant, device):
    _manage(client, admin, tenant, device)
    report = _report()
    report["asr"][LSASS] = 0  # tamper protection or Intune kept it off
    _complete(client, device, _check(client, admin, device), report)
    view = client.get(f"/api/console/devices/{device['deviceId']}/defender", headers=admin).json()
    assert any("attack surface rules are not set" in p for p in view["problems"])
    assert next(r for r in view["rules"] if r["guid"] == LSASS)["actual"] == "off"


def test_the_hourly_check_follows_policy_changes_and_waits_for_the_device(client, admin, tenant, device):
    _seen(device)
    with database.session_factory()() as db:
        assert defender.tick(db)["sent"] == 1  # first check: report only
        assert defender.tick(db)["sent"] == 0  # one check in flight at a time
        state = db.get(DefenderState, device["deviceId"])
        first = state.command_id
    _complete(client, device, first, _report())
    with database.session_factory()() as db:
        assert defender.tick(db)["sent"] == 0  # checked just now
    _manage(client, admin, tenant, device)
    _seen(device)
    with database.session_factory()() as db:
        assert defender.tick(db)["sent"] == 1  # the policy changed: apply it now
        command_id = db.get(DefenderState, device["deviceId"]).command_id
        assert db.get(Command, command_id).payload["defender"] == "apply"
    _complete(client, device, command_id, _report())
    with database.session_factory()() as db:
        assert defender.tick(db)["sent"] == 0
        state = db.get(DefenderState, device["deviceId"])
        state.checked_at = utcnow() - timedelta(hours=7)
        db.commit()
        assert defender.tick(db)["sent"] == 1  # six hours on: re-apply and refresh


def test_fleet_view_and_scope(client, admin, tenant, device):
    _manage(client, admin, tenant, device)
    _complete(client, device, _check(client, admin, device), _report(tamper=True))
    body = client.get("/api/console/defender/fleet", headers=admin).json()
    row = next(r for r in body["devices"] if r["deviceId"] == device["deviceId"])
    assert row["managed"] and row["inSync"] and row["tamper"] is True and row["mode"] == "Normal"
    assert body["summary"]["managed"] >= 1 and body["summary"]["tamperOff"] == 0
    linux = enroll(client, admin, tenant, hostname="ACME-LNX", serial="SN-L")
    with database.session_factory()() as db:
        db.get(Device, linux["deviceId"]).platform = "linux"
        db.commit()
    assert client.get(f"/api/console/devices/{linux['deviceId']}/defender", headers=admin).status_code == 404


def test_defender_for_endpoint_alerts_from_microsoft_365_reach_the_device_once_and_resolve(client, admin, tenant, device):
    from fenrir_cloud import m365
    from fenrir_cloud.models import Alert, M365Connection

    graph_alert = {"id": "da637", "title": "Suspicious PowerShell command line", "severity": "high", "category": "Execution",
                   "mitreTechniques": ["T1059.001"], "alertWebUrl": "https://security.microsoft.com/alerts/da637",
                   "evidence": [{"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "acme-ws-01.acme.local"}]}
    with database.session_factory()() as db:
        connection = M365Connection(tenant_id=tenant["id"], name="Acme", directory_id="d" * 36, client_id="c" * 36,
                                    credentials_envelope={})
        db.add(connection)
        db.flush()
        assert m365.ingest_defender_alerts(db, connection, None) == {"raised": 0, "resolved": 0, "available": False}
        assert m365.ingest_defender_alerts(db, connection, [graph_alert])["raised"] == 1
        db.flush()
        assert m365.ingest_defender_alerts(db, connection, [graph_alert])["raised"] == 0  # once only
        alert = db.query(Alert).filter_by(rule_id="mde:da637").one()
        assert alert.device_id == device["deviceId"] and alert.severity == "high" and alert.mitre == ["T1059.001"]
        assert alert.title == "Defender for Endpoint: Suspicious PowerShell command line"
        assert m365.ingest_defender_alerts(db, connection, [])["resolved"] == 1  # resolved in Defender, resolved here
        assert alert.status == "resolved"
        db.commit()


def test_defender_not_running_is_reported_alerted_and_never_counted_as_applied(client, admin, tenant, device):
    _manage(client, admin, tenant, device)
    _complete(client, device, _check(client, admin, device),
              {"available": False, "error": "Operation failed with the following error: 0x800106ba", "errors": []})
    view = client.get(f"/api/console/devices/{device['deviceId']}/defender", headers=admin).json()
    assert view["inSync"] is False and any("not available" in p for p in view["problems"])
    off = [a for a in client.get("/api/console/alerts", headers=admin, params={"device_id": device["deviceId"]}).json()
           if a["ruleId"] == defender.OFF_RULE]
    assert len(off) == 1 and "0x800106ba" in off[0]["details"]["description"]


def test_a_report_the_device_could_not_build_keeps_the_last_good_state(client, admin, tenant, device):
    _manage(client, admin, tenant, device)
    _complete(client, device, _check(client, admin, device), _report(tamper=True))
    _complete(client, device, _check(client, admin, device), {"reportError": "report: Value was either too large", "errors": []})
    view = client.get(f"/api/console/devices/{device['deviceId']}/defender", headers=admin).json()
    assert view["status"]["tamper"] is True and "too large" in view["error"] and view["problems"] == []
    assert not [a for a in client.get("/api/console/alerts", headers=admin, params={"device_id": device["deviceId"]}).json()
                if a["ruleId"] == defender.OFF_RULE]


def test_the_script_never_casts_defender_ages_to_int32():
    from fenrir_cloud import policy_schema
    body = defender.script({"defender": {**policy_schema.defaults()["defender"], "managed": True},
                            "attackSurface": policy_schema.defaults()["attackSurface"]})
    assert "[int]$status" not in body and "Days $status.QuickScanAge" in body and "reportError" in body
