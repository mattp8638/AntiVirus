"""Sigma engine, pipeline, incidents, automated response, tuning, hunting."""

import json
from datetime import datetime, timezone

import pytest

from fenrir_cloud.normalize import normalize
from fenrir_cloud.sigma import SigmaError, parse_rule


def win_event(event_type, payload, event_id):
    """Shape produced by the Windows service's telemetry spool."""
    return {"eventId": event_id, "eventType": event_type, "source": "etw", "summary": "", "occurredAt": datetime.now(timezone.utc).isoformat(),
            "payloadJson": json.dumps(payload)}


# --------------------------------------------------------------------------- engine


def test_modifiers_and_conditions():
    rule = parse_rule("""
title: t
id: t1
logsource: {category: process_creation}
detection:
  sel_img: {Image|endswith: ['\\powershell.exe', '\\pwsh.exe']}
  sel_enc: {CommandLine|windash|contains: ' -enc '}
  filter: {User|startswith: 'NT AUTHORITY'}
  condition: all of sel_* and not filter
level: high
""")
    assert rule.matches({"Image": "C:\\Windows\\powershell.exe", "CommandLine": "powershell /enc AAA", "User": "bob"}, "process")
    assert not rule.matches({"Image": "C:\\Windows\\powershell.exe", "CommandLine": "powershell -enc AAA",
                             "User": "NT AUTHORITY\\SYSTEM"}, "process")
    assert not rule.matches({"Image": "C:\\Windows\\cmd.exe", "CommandLine": "-enc"}, "process")
    assert not rule.matches({"Image": "C:\\Windows\\powershell.exe", "CommandLine": "powershell -enc AAA"}, "network")


def test_cidr_numeric_regex_and_keywords():
    rule = parse_rule("""
title: t
id: t2
logsource: {category: network_connection}
detection:
  net: {DestinationIp|cidr: 10.0.0.0/8, DestinationPort|gte: 4000}
  re: {Image|re: '(?i)nc(at)?$'}
  kw: [mimikatz]
  condition: (net and re) or kw
level: low
""")
    assert rule.matches({"DestinationIp": "10.1.2.3", "DestinationPort": 4444, "Image": "/usr/bin/ncat"}, "network")
    assert not rule.matches({"DestinationIp": "8.8.8.8", "DestinationPort": 4444, "Image": "/usr/bin/ncat"}, "network")
    assert rule.matches({"Note": "found MIMIKATZ.exe"}, "network")


def test_wildcards_case_insensitive_and_product():
    rule = parse_rule("""
title: t
id: t3
logsource: {category: process_creation, product: linux}
detection:
  sel: {CommandLine: 'curl * | sh'}
  condition: sel
level: high
""")
    assert rule.matches({"CommandLine": "CURL http://x | sh"}, "process", "linux")
    assert not rule.matches({"CommandLine": "curl http://x | sh"}, "process", "windows")


def test_invalid_rules_are_rejected():
    with pytest.raises(SigmaError):
        parse_rule("title: x\nid: y\ndetection: {sel: {a: b}, condition: sel and missing}\n")
    with pytest.raises(SigmaError):
        parse_rule("title: x\nid: y\nlevel: urgent\ndetection: {sel: {a: b}, condition: sel}\n")


def test_normalizer_handles_every_agent_shape():
    win = normalize(win_event("process.start", {"processImagePath": "C:\\x\\a.exe", "commandLine": "a -x", "pid": 4}, "1"))
    assert win["fields"]["Image"] == "C:\\x\\a.exe" and win["fields"]["ProcessName"] == "a.exe"
    assert win["category"] == "process"
    linux = normalize({"eventId": "2", "deviceId": "h", "timestamp": "2026-10-22T10:00:00Z", "eventType": "NetworkConnect",
                       "payload": {"processName": "curl", "pid": 9, "destinationIp": "1.2.3.4", "destinationPort": 443}})
    assert linux["fields"]["DestinationIp"] == "1.2.3.4" and linux["category"] == "network"


# --------------------------------------------------------------------------- pipeline


def send(client, device, events):
    response = client.post(f"/api/v1/devices/{device['deviceId']}/telemetry", json={"events": events}, headers=device["headers"])
    assert response.status_code == 200, response.text
    return response.json()


def test_shadow_copy_deletion_raises_incident_kills_and_tickets(client, admin, device):
    result = send(client, device, [win_event("process.start", {
        "processImagePath": "C:\\Windows\\System32\\vssadmin.exe", "commandLine": "vssadmin delete shadows /all /quiet",
        "parentProcessImagePath": "C:\\Users\\bob\\AppData\\Local\\Temp\\locker.exe", "pid": 4242}, "evt-1")])
    assert result["accepted"] == 1 and result["alerts"] >= 1
    alerts = client.get("/api/console/alerts", headers=admin).json()
    assert alerts[0]["title"] == "Shadow copy deletion" and alerts[0]["severity"] == "critical"
    assert "T1490" in alerts[0]["mitre"]
    incidents = client.get("/api/console/incidents", headers=admin).json()
    assert len(incidents) == 1 and incidents[0]["playbook"] == "ransomware-response"
    detail = client.get(f"/api/console/incidents/{incidents[0]['id']}", headers=admin).json()
    assert any(item["stage"] == "closure_gate" for item in detail["incident"]["checklist"])
    # Balanced policy: kill on high, ticket from high.
    types = {c["type"] for c in detail["commands"]}
    assert "process.tree.terminate" in types
    assert detail["ticket"]["priority"] == "P1" and detail["ticket"]["queue"] == "Security Operations"
    # Agent receives the kill with the right image path.
    pending = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]
    kill = next(i for i in pending if i["type"] == "process.tree.terminate")
    assert kill["targetPath"].endswith("vssadmin.exe")
    assert json.loads(kill["payloadJson"]) == {"pid": 4242}  # PID-targeted, never "every vssadmin.exe"


def test_no_path_wide_kill_without_pid_or_after_agent_block(client, admin, device):
    send(client, device, [win_event("process.start", {"processImagePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                                      "commandLine": "powershell -enc AAAA"}, "nopid")])
    send(client, device, [win_event("asr.rule.blocked", {"rule": "attackSurface.blockObfuscatedScripts", "pid": 77,
                                                         "processImagePath": "C:\\Windows\\System32\\cmd.exe"}, "blk")])
    commands = client.get(f"/api/console/commands?device_id={device['deviceId']}", headers=admin).json()
    assert not any(c["type"] in {"process.terminate", "process.tree.terminate"} for c in commands)
    incident = client.get("/api/console/incidents", headers=admin).json()[0]
    detail = client.get(f"/api/console/incidents/{incident['id']}", headers=admin).json()
    assert any("Automation skipped" in item["text"] for item in detail["incident"]["timeline"])


def test_duplicate_events_are_ignored(client, device):
    event = win_event("process.start", {"processImagePath": "C:\\a.exe", "commandLine": "a"}, "dup-1")
    assert send(client, device, [event])["accepted"] == 1
    again = send(client, device, [event])
    assert again["accepted"] == 0 and again["duplicates"] == 1


def test_mass_encryption_correlation(client, admin, device):
    events = [win_event("file.rename", {"processImagePath": "C:\\Temp\\x.exe", "pid": 77,
                                        "targetPath": f"C:\\Users\\bob\\Documents\\f{i}.docx.lockbit"}, f"r{i}") for i in range(30)]
    send(client, device, events)
    titles = {a["title"] for a in client.get("/api/console/alerts", headers=admin).json()}
    assert "Mass file encryption (ransomware behaviour)" in titles
    # Deduplicated: one extension alert for the burst, not thirty.
    extension_alerts = [a for a in client.get("/api/console/alerts", headers=admin).json()
                        if a["title"] == "File renamed to a ransomware extension"]
    assert len(extension_alerts) == 1 and len(extension_alerts[0]["eventIds"]) == 30


def test_audit_policy_blocks_nothing(client, admin, tenant, device):
    policies = client.get(f"/api/console/policies?tenant_id={tenant['id']}", headers=admin).json()
    default = next(p for p in policies if p["id"] == tenant["defaultPolicyId"])
    client.put(f"/api/console/policies/{default['id']}", json={"settings": {"response": {"autoKillOnHigh": False,
                                                                                          "autoOpenTicket": "off"}}}, headers=admin)
    send(client, device, [win_event("process.start", {"processImagePath": "C:\\Windows\\System32\\vssadmin.exe",
                                                      "commandLine": "vssadmin delete shadows /all"}, "e1")])
    commands = client.get(f"/api/console/commands?device_id={device['deviceId']}", headers=admin).json()
    assert not any(c["type"] == "process.tree.terminate" for c in commands)
    assert client.get("/api/console/tickets", headers=admin).json() == []


def test_false_positive_tuning_is_tenant_scoped(client, admin, device):
    event = {"processImagePath": "C:\\Tools\\backup.exe", "commandLine": "backup.exe wbadmin delete catalog", "pid": 1}
    send(client, device, [win_event("process.start", event, "fp-1")])
    alert = next(a for a in client.get("/api/console/alerts", headers=admin).json() if a["title"] == "Backup catalog or recovery disabled")
    client.patch(f"/api/console/alerts/{alert['id']}", json={"status": "false_positive", "suppress": True}, headers=admin)
    send(client, device, [win_event("process.start", event, "fp-2")])
    open_alerts = [a for a in client.get("/api/console/alerts?status=new", headers=admin).json()
                   if a["title"].startswith("Backup catalog")]
    assert open_alerts == []
    rules = {r["title"] for r in client.get("/api/console/rules", headers=admin).json()}
    assert "Backup catalog or recovery disabled (tuned)" in rules


def test_retro_hunt_and_event_search(client, admin, device):
    send(client, device, [win_event("process.start", {"processImagePath": "C:\\Windows\\System32\\certutil.exe",
                                                      "commandLine": "certutil -urlcache -f http://x/a.exe a.exe"}, "h1")])
    hunt = client.post("/api/console/hunt", json={"rule": """
title: certutil anywhere
id: hunt-1
logsource: {category: process_creation}
detection: {sel: {Image|endswith: certutil.exe}, condition: sel}
level: low
""", "days": 365}, headers=admin).json()
    assert hunt["hits"] == 1
    found = client.get("/api/console/events?q=ProcessName:certutil.exe AND urlcache&hours=24", headers=admin).json()
    assert found["count"] == 1


def test_custom_rule_with_response(client, admin, device):
    rule = """
title: Custom - block rclone exfil
id: custom-rclone
logsource: {category: process_creation}
detection: {sel: {ProcessName: rclone.exe}, condition: sel}
level: medium
tags: [attack.exfiltration, attack.t1567.002]
"""
    tested = client.post("/api/console/rules/test", json={"rule": rule, "events": [
        win_event("process.start", {"processImagePath": "C:\\x\\rclone.exe"}, "t")]}, headers=admin).json()
    assert tested["results"][0]["matched"] is True
    created = client.post("/api/console/rules", json={"rule": rule, "response": ["device.isolate"]}, headers=admin)
    assert created.status_code == 200, created.text
    send(client, device, [win_event("process.start", {"processImagePath": "C:\\x\\rclone.exe", "commandLine": "rclone copy"}, "c1")])
    commands = client.get(f"/api/console/commands?device_id={device['deviceId']}", headers=admin).json()
    assert any(c["type"] == "device.isolate" for c in commands)


def test_mitre_coverage(client, admin):
    coverage = client.get("/api/console/mitre", headers=admin).json()
    techniques = {t["technique"] for t in coverage["techniques"]}
    assert {"T1486", "T1490", "T1003.001", "T1059.001"} <= techniques


def test_incident_upgrades_to_ransomware_playbook(client, admin, device):
    send(client, device, [win_event("process.start", {"processImagePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                                      "commandLine": "powershell -enc AAAA"}, "p1")])
    send(client, device, [win_event("process.start", {"processImagePath": "C:\\Windows\\System32\\vssadmin.exe",
                                                      "commandLine": "vssadmin delete shadows /all"}, "p2")])
    incidents = client.get("/api/console/incidents", headers=admin).json()
    assert len(incidents) == 1 and incidents[0]["playbook"] == "ransomware-response"


def test_antimalware_findings_raise_alerts(client, admin, tenant):
    import json as _json

    from conftest import enroll

    def send(dev, events):
        response = client.post(f"/api/v1/devices/{dev['deviceId']}/telemetry", headers=dev["headers"], json={"events": events})
        assert response.status_code == 200, response.text

    win = enroll(client, admin, tenant, hostname="AV-WIN", serial="AV-1")
    send(win, [
        {"eventId": "av-1", "eventType": "scan.finding", "source": "scan.quick", "summary": "EICAR",
         "occurredAt": "2030-01-01T00:00:00Z",
         "payloadJson": _json.dumps({"path": "C:\\Users\\Public\\eicar.com", "remediationStatus": "quarantined",
                                     "disposition": "quarantine"})},
        {"eventId": "av-2", "eventType": "scan.finding", "source": "scan.quick", "summary": "Stuck file",
         "occurredAt": "2030-01-01T00:00:01Z",
         "payloadJson": _json.dumps({"path": "C:\\locked.exe", "remediationStatus": "failed", "disposition": "quarantine"})},
    ])
    send(win, [{"eventId": "av-amsi", "eventType": "scan.finding", "source": "amsi-provider", "summary": "AMSI block",
                "occurredAt": "2030-01-01T00:10:00Z",
                "payloadJson": _json.dumps({"appName": "PowerShell", "contentName": "x.ps1", "disposition": "block",
                                            "remediationStatus": "none"})}])
    lin = enroll(client, admin, tenant, hostname="AV-LIN", os_version="Ubuntu 24.04", serial="AV-2")
    send(lin, [
        {"eventId": "av-3", "eventType": "ransomware.canary.touched", "timestamp": "2030-01-01T00:00:02Z",
         "payload": {"path": "/home/jo/.fenrir-canary.docx", "change": "renamed"}},
        {"eventId": "av-4", "eventType": "scan.threat.detected", "timestamp": "2030-01-01T00:00:03Z",
         "payload": {"path": "/tmp/x", "threatName": "Linux.Miner", "verdict": "detected"}},
    ])
    alerts = client.get("/api/console/alerts", headers=admin).json()
    by_rule = {}
    for alert in alerts:
        by_rule.setdefault(alert["ruleId"], []).append(alert)
    remediated = by_rule["fenrir-av-threat-remediated"]
    assert len(remediated) == 1 and len(remediated[0]["eventIds"]) == 2  # EICAR + AMSI block, deduplicated
    assert len(by_rule["fenrir-av-threat-unremediated"]) == 2
    assert by_rule["fenrir-av-ransomware-canary"][0]["severity"] == "critical"


def test_quarantine_view_tracks_restore_and_delete(client, admin, tenant):
    import json as _json

    from conftest import enroll

    dev = enroll(client, admin, tenant, hostname="Q-WIN", serial="Q-1")
    events = [{"eventId": f"q-{i}", "eventType": "scan.finding", "source": "scan.quick", "summary": f"Threat {i}",
               "occurredAt": f"2030-01-01T00:00:0{i}Z",
               "payloadJson": _json.dumps({"path": f"C:\\bad{i}.exe", "remediationStatus": "quarantined",
                                           "quarantineRecordId": f"rec-{i}", "sha256": "ab" * 32})} for i in range(3)]
    events.append({"eventId": "q-none", "eventType": "scan.finding", "occurredAt": "2030-01-01T00:00:09Z",
                   "payloadJson": _json.dumps({"path": "C:\\left.exe", "remediationStatus": "failed", "quarantineRecordId": ""})})
    assert client.post(f"/api/v1/devices/{dev['deviceId']}/telemetry", headers=dev["headers"], json={"events": events}).status_code == 200
    items = client.get("/api/console/protection/quarantine", headers=admin).json()
    assert sorted(i["recordId"] for i in items) == ["rec-0", "rec-1", "rec-2"]
    assert items[0]["hostname"] == "Q-WIN" and items[0]["status"] == "quarantined"

    def issue(kind, record):
        response = client.post(f"/api/console/devices/{dev['deviceId']}/commands", headers=admin,
                               json={"type": kind, "recordId": record, "reason": "test"})
        assert response.status_code == 200, response.text
        return response.json()["id"]

    restored = issue("quarantine.restore", "rec-0")
    deleting = issue("quarantine.delete", "rec-1")
    assert client.post(f"/api/v1/devices/{dev['deviceId']}/commands/{restored}/complete", headers=dev["headers"],
                       json={"status": "completed", "resultJson": "{}"}).status_code == 200
    state = {i["recordId"]: i["status"] for i in client.get("/api/console/protection/quarantine", headers=admin).json()}
    assert state == {"rec-1": "deleting", "rec-2": "quarantined"}
    everything = client.get("/api/console/protection/quarantine?include_released=true", headers=admin).json()
    assert {i["recordId"]: i["status"] for i in everything}["rec-0"] == "restored"
    assert deleting
