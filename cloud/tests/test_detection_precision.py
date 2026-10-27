"""Antimalware precision: what clean machines send must not alert; real malware must, at the right level and with
ATT&CK that matches what happened. Payloads mirror the Windows agent (ScanEngine, RealtimeProtectionBroker,
ProcessGuard) and the Linux agent (schedule.go, agent.go)."""

import json
from datetime import timedelta

from conftest import enroll

from fenrir_cloud import db as database, services
from fenrir_cloud.detection import retune_open_alerts
from fenrir_cloud.models import Alert, Device, Event, Incident, utcnow

SHA_A, SHA_B = "a" * 64, "b" * 64
counter = {"n": 0}


def ev(event_type, payload, minutes_ago=1, raw_json=None):
    counter["n"] += 1
    return {"eventId": f"prec-{counter['n']}", "eventType": event_type, "source": "agent", "summary": event_type,
            "occurredAt": (utcnow() - timedelta(minutes=minutes_ago)).isoformat() + "Z",
            "payloadJson": raw_json if raw_json is not None else json.dumps(payload)}


def scan(**fields):
    return {"path": "C:\\Users\\jo\\Downloads\\tool.exe", "sha256": SHA_A, "contentType": "pe", "remediationStatus": "none",
            "disposition": "block", "heuristicScore": 50, "reputation": "unsigned", **fields}


def send(client, device, events):
    reply = client.post(f"/api/v1/devices/{device['deviceId']}/telemetry", headers=device["headers"], json={"events": events})
    assert reply.status_code == 200, reply.text
    return reply.json()


def alerts_for(client, admin, device):
    return client.get("/api/console/alerts", headers=admin, params={"device_id": device["deviceId"], "status": ""}).json()


CLEAN = [
    ("allowed by cleanware dampening", "scan.finding", scan(disposition="allow", reputation="trusted-signed;intel-known-good", heuristicScore=48)),
    ("excluded path allow override", "scan.finding", scan(disposition="allow", heuristicScore=0, alertTitle="File check completed")),
    ("moderate heuristic, report only", "scan.finding", scan(heuristicScore=55)),
    ("moderate heuristic quarantined by an older agent", "scan.finding", scan(heuristicScore=60, remediationStatus="quarantined")),
    ("trusted signer", "scan.finding", scan(heuristicScore=80, reputation="trusted-signed")),
    ("ML audit only", "threat.ml.audited", {"rule": "antimalware.mlStatic", "mode": "audit", "pid": 4410, "image": "C:\\Tools\\dev.exe"}),
    ("analyst quarantine bookkeeping", "quarantine.added", {"path": "C:\\x.exe", "recordId": "r1"}),
    ("website blocked", "web.request.blocked", {"url": "http://ads.example/x"}),
    ("PUA running", "threat.pua.detected", {"path": "/usr/bin/coinhive", "threatName": "PUA:Miner"}),
]


def test_clean_machine_events_raise_nothing(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="CLEAN-PC", serial="C-1")
    for _, event_type, payload in CLEAN:
        send(client, device, [ev(event_type, payload)])
    # Broken JSON from older Windows agents (stray quote after "confidence"), real-time ALLOWED the file.
    broken = ('{"path":"C:\\\\Users\\\\jo\\\\setup.exe","operation":"execute","action":"allow","disposition":"allow",'
              '"confidence":38","tacticId":"TA0002","techniqueId":"T1204.002","sha256":"' + SHA_B + '","remediationStatus":"none"}')
    send(client, device, [ev("realtime.protection.action", None, raw_json=broken)])
    assert alerts_for(client, admin, device) == []


def test_real_malware_alerts_at_the_right_level(client, admin, tenant):
    win = enroll(client, admin, tenant, hostname="INFECTED-PC", serial="I-1")
    cases = [
        ("quarantined", "scan.finding", scan(disposition="quarantine", heuristicScore=88, remediationStatus="quarantined"), "medium"),
        ("left behind", "scan.finding", scan(sha256="c" * 64, path="C:\\in-use.exe", disposition="quarantine", heuristicScore=90, remediationStatus="failed",
                                             remediationError="in use"), "high"),
        ("malicious cloud verdict, report-only", "scan.finding", scan(sha256="d" * 64, path="C:\\r.exe", heuristicScore=52, reputation="unsigned;intel-malicious"), "high"),
        ("ML enforcement failed", "threat.ml.block_failed", {"rule": "antimalware.mlStatic", "pid": 1, "image": "C:\\bad.exe"}, "high"),
    ]
    for _, event_type, payload, _ in cases:
        send(client, win, [ev(event_type, payload)])
    broken_block = ('{"path":"C:\\\\Users\\\\jo\\\\Downloads\\\\inv.exe","operation":"execute","action":"block","disposition":"quarantine",'
                    '"confidence":91","tacticId":"TA0002","techniqueId":"T1204.002","sha256":"' + "e" * 64 + '","remediationStatus":"quarantined",'
                    '"processId":7001,"processImage":"C:\\\\Users\\\\jo\\\\Downloads\\\\inv.exe","parentImage":"C:\\\\Windows\\\\explorer.exe"}')
    send(client, win, [ev("realtime.protection.action", None, raw_json=broken_block)])
    alerts = alerts_for(client, admin, win)
    # Same rule on the same device within 10 minutes is one alert with several occurrences.
    by_sha = {}
    for a in alerts:
        for occurrence in client.get(f"/api/console/alerts/{a['id']}", headers=admin).json()["alert"]["details"]["evidence"]:
            by_sha[(occurrence.get("file") or {}).get("sha256") or (occurrence.get("process") or {}).get("image")] = a
    assert by_sha[SHA_A]["severity"] == "medium" and by_sha["c" * 64]["severity"] == "high" and by_sha["d" * 64]["severity"] == "high"
    assert by_sha["C:\\bad.exe"]["severity"] == "high"  # ML enforcement failed
    assert len(alerts) == 2  # removed (scan + real-time), not removed (3 occurrences)
    realtime = by_sha["e" * 64]
    assert realtime["severity"] == "medium" and "T1204.002" in realtime["mitre"]  # a person launched it from Explorer
    # Files found at rest and a model score with no launcher are not "User Execution".
    assert not any(t.startswith("T1204") for t in by_sha["c" * 64]["mitre"])

    lin = enroll(client, admin, tenant, hostname="INFECTED-LIN", os_version="Ubuntu 24.04", serial="I-2")
    send(client, lin, [ev("scan.threat.detected", {"path": "/tmp/x", "sha256": "f" * 64, "threatName": "Linux.Miner", "verdict": "detected"}),
                       ev("scan.threat.quarantined", {"path": "/tmp/y", "sha256": "9" * 64, "threatName": "EICAR", "verdict": "quarantined"})])
    levels = sorted(a["severity"] for a in alerts_for(client, admin, lin))
    assert levels == ["high", "medium"]


def test_attack_from_evidence():
    from fenrir_cloud.detection import attack_for

    rule = "fenrir-av-threat-unremediated"
    assert attack_for(rule, ["execution", "T1204"], {"file": {"path": "x"}}, {}, "scan.finding") == []
    assert attack_for(rule, [], {"origin": {"emailAttachment": True}}, {}, "scan.finding") == ["initial_access", "T1566.001"]
    launched = {"process": {"pid": 5, "parentImage": "C:\\Windows\\explorer.exe"}}
    assert attack_for(rule, [], launched, {"operation": "execute"}, "realtime.protection.action") == ["execution", "T1204.002"]
    service = {"process": {"pid": 5, "parentImage": "C:\\Windows\\System32\\services.exe"}}
    assert attack_for(rule, [], service, {"operation": "execute"}, "realtime.protection.action") == ["execution"]
    assert attack_for(rule, [], {}, {"appName": "PowerShell", "techniqueId": "T1059.001"}, "scan.finding") == ["execution", "T1059.001"]
    assert attack_for("fenrir-exec-office-child", ["execution", "T1204.002"], {}, {}) == ["execution", "T1204.002"]  # other rules untouched


def test_repeats_fold_and_false_positive_learning(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="REPEAT-PC", serial="R-1")
    finding = scan(disposition="quarantine", heuristicScore=85, remediationStatus="failed", sha256="7" * 64, path="C:\\Tools\\legit-but-odd.exe")
    send(client, device, [ev("scan.finding", finding, minutes_ago=60 * 24 * 3)])  # three days ago
    send(client, device, [ev("scan.finding", finding, minutes_ago=5)])            # today's scan finds it again
    alerts = alerts_for(client, admin, device)
    assert len(alerts) == 1
    detail = client.get(f"/api/console/alerts/{alerts[0]['id']}", headers=admin).json()["alert"]
    assert detail["details"]["evidence"][0]["count"] == 2

    marked = client.patch(f"/api/console/alerts/{alerts[0]['id']}", headers=admin, json={"status": "false_positive", "trust": True}).json()
    assert marked["learned"] == {"trustedSha256": "7" * 64, "scope": "tenant"}
    send(client, device, [ev("scan.finding", finding, minutes_ago=1)])
    assert [a["status"] for a in alerts_for(client, admin, device)] == ["false_positive"]

    # The agents learn it too: the hash joins their policy's suppression list and the revision changes.
    session = database.session_factory()()
    try:
        _, doc = services.effective_policy(session, session.get(Device, device["deviceId"]))
        assert "7" * 64 in doc["suppressionSha256"]
    finally:
        session.close()
    other = enroll(client, admin, tenant, hostname="OTHER-PC", serial="R-2")
    send(client, other, [ev("scan.finding", finding)])
    assert alerts_for(client, admin, other) == []

    rules = client.get("/api/console/rules", headers=admin).json()
    quality = next(r["quality"] for r in rules if r["id"] == "fenrir-av-threat-unremediated")
    assert quality["falsePositive"] >= 1 and quality["fpRate"] is not None


def test_retune_closes_old_false_positives(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="OLD-ALERTS", serial="O-1")
    session = database.session_factory()()
    try:
        row = session.get(Device, device["deviceId"])
        # What the old rules raised: an allowed file as "not remediated", and a real quarantine-failed detection.
        allowed = Event(tenant_id=row.tenant_id, device_id=row.id, event_id="old-1", event_type="scan.finding", category="malware",
                        fields={"path": "C:\\Program Files\\App\\app.exe", "disposition": "allow", "remediationStatus": "none",
                                "reputation": "trusted-signed", "EventType": "scan.finding"}, occurred_at=utcnow())
        real = Event(tenant_id=row.tenant_id, device_id=row.id, event_id="old-2", event_type="scan.finding", category="malware",
                     fields={"path": "C:\\Users\\jo\\x.exe", "disposition": "quarantine", "remediationStatus": "failed", "heuristicScore": 93,
                             "EventType": "scan.finding"}, occurred_at=utcnow())
        session.add_all([allowed, real])
        session.flush()
        incident = Incident(tenant_id=row.tenant_id, device_id=row.id, title="Old", status="open", mitre=["T1204"], timeline=[])
        session.add(incident)
        session.flush()
        fp = Alert(tenant_id=row.tenant_id, device_id=row.id, rule_id="fenrir-av-threat-unremediated", title="Malware found but not remediated",
                   severity="high", mitre=["execution", "T1204"], event_ids=[allowed.id], details={}, incident_id=incident.id)
        tp = Alert(tenant_id=row.tenant_id, device_id=row.id, rule_id="fenrir-av-threat-unremediated", title="Malware found but not remediated",
                   severity="high", mitre=["execution", "T1204"], event_ids=[real.id], details={})
        session.add_all([fp, tp])
        session.commit()
        result = retune_open_alerts(session)
        session.commit()
        session.refresh(fp)
        session.refresh(tp)
        session.refresh(incident)
        assert result["closed"] == 1 and result["kept"] == 1
        assert fp.status == "false_positive" and "allowed it" in fp.details["autoResolved"]
        assert tp.status == "new" and tp.mitre == []  # at rest: no User Execution claim
        assert incident.status == "resolved"
    finally:
        session.close()


def test_everyday_admin_activity_is_quiet(client, admin, tenant):
    """Things IT tools and Office do on every clean Windows machine."""
    device = enroll(client, admin, tenant, hostname="ADMIN-PC", serial="Q-1")
    proc = lambda image, cmd, parent: ev("process.start", {"processImagePath": image, "commandLine": cmd, "parentProcessImagePath": parent})
    send(client, device, [
        proc("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -ec SQBuAHQAdQBuAGUA",
             "C:\\Program Files (x86)\\Microsoft Intune Management Extension\\AgentExecutor.exe"),
        proc("C:\\Windows\\System32\\rundll32.exe", "rundll32.exe shell32.dll,OpenAs_RunDLL C:\\x.pdf",
             "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
        proc("C:\\Windows\\System32\\schtasks.exe", "schtasks /create /tn Updater /tr \"C:\\ProgramData\\Vendor\\upd.exe\"",
             "C:\\Program Files\\Vendor\\setup.exe"),
        proc("C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe", "AnyDesk.exe --service", "C:\\Windows\\System32\\services.exe"),
    ])
    titles = [a["title"] for a in alerts_for(client, admin, device)]
    assert titles == [], titles
    # The attacker version of the same still alerts.
    send(client, device, [proc("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami",
                               "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE")])
    assert [a["title"] for a in alerts_for(client, admin, device)] == ["Office application spawned a shell"]
