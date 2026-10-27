import json
from datetime import timedelta

from fenrir_cloud import evidence
from fenrir_cloud.models import utcnow

# What the Windows scanner sends for a detection it could not quarantine (ScanEngine.cpp BuildScanFindingTelemetry).
SCAN_FINDING = {
    "path": "C:\\Users\\jo\\Downloads\\invoice.pdf.exe", "sizeBytes": 482304, "sha256": "a" * 64, "contentType": "pe",
    "reputation": "malicious", "signer": "", "heuristicScore": 92, "archiveEntryCount": 0, "remediationStatus": "failed",
    "disposition": "quarantine", "tacticId": "TA0002", "techniqueId": "T1204", "quarantineRecordId": "",
    "remediationError": "The file is in use by another process", "alertTitle": "Trojan:Win32/Fenrir.Gen!ml",
    "alertSummary": "Machine-learning model scored the file 0.97", "contextType": "browser",
    "originLabel": "Downloaded in Microsoft Edge from mail-attachments.example.net",
    "originContext": {"channel": "browser", "sourceUrl": "https://mail-attachments.example.net/x/invoice.pdf.exe",
                      "sourceDomain": "mail-attachments.example.net", "browserFamily": "edge", "downloadOriginated": True},
}

REALTIME_BLOCK = {
    "path": "C:\\ProgramData\\upd\\svc.exe", "sha256": "b" * 64, "remediationStatus": "quarantined", "processId": 4412,
    "processImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "parentImage": "C:\\Windows\\explorer.exe",
    "commandLine": "powershell -enc SQBFAFgA", "userSid": "S-1-5-21-1-2-3-1001", "alertTitle": "Blocked a dropped payload",
    "reasonCodes": ["unsigned-dropper", "encoded-command"],
}


def test_extract_scan_finding():
    found = evidence.extract({"originContext.sourceUrl": SCAN_FINDING["originContext"]["sourceUrl"],
                              **{k: v for k, v in SCAN_FINDING.items() if k != "originContext"},
                              "originContext.sourceDomain": "mail-attachments.example.net",
                              "originContext.downloadOriginated": True}, "scan.finding", "Trojan found")
    assert found["file"]["path"].endswith("invoice.pdf.exe") and found["file"]["sha256"] == "a" * 64
    assert found["file"]["reputation"] == "malicious" and "signer" not in found["file"]
    assert found["threat"]["name"] == "Trojan:Win32/Fenrir.Gen!ml" and found["threat"]["remediation"] == "failed"
    assert found["threat"]["remediationError"].startswith("The file is in use")
    assert found["origin"]["domain"] == "mail-attachments.example.net" and found["origin"]["downloaded"] is True
    assert "process" not in found and "network" not in found
    assert evidence.headline(found)["process"].endswith("invoice.pdf.exe")


def test_occurrences_fold_and_indicators():
    a = evidence.extract(REALTIME_BLOCK, "realtime.protection.action")
    details = evidence.add_occurrence({}, a)
    details = evidence.add_occurrence(details, evidence.extract(REALTIME_BLOCK, "realtime.protection.action"))
    assert len(details["evidence"]) == 1 and details["evidence"][0]["count"] == 2
    assert a["process"]["image"].endswith("powershell.exe") and a["process"]["parentImage"].endswith("explorer.exe")
    assert a["process"]["user"] == "S-1-5-21-1-2-3-1001" and a["threat"]["reasons"] == ["unsigned-dropper", "encoded-command"]
    iocs = evidence.indicators([details])
    assert iocs["sha256"][0]["value"] == "b" * 64 and any(p["value"].endswith("explorer.exe") for p in iocs["processes"])


def test_alert_and_incident_carry_evidence(client, admin, device):
    payload = json.dumps(SCAN_FINDING)
    events = [{"eventId": f"evt-scan-{i}", "eventType": "scan.finding", "source": "scanner", "summary": "Trojan:Win32/Fenrir.Gen!ml found",
               "occurredAt": (utcnow() - timedelta(minutes=5 - i)).isoformat() + "Z", "payloadJson": payload} for i in range(2)]
    reply = client.post(f"/api/v1/devices/{device['deviceId']}/telemetry", headers=device["headers"], json={"events": events}).json()
    assert reply["alerts"] >= 1
    alerts = client.get("/api/console/alerts", headers=admin, params={"device_id": device["deviceId"]}).json()
    alert = next(a for a in alerts if a["title"] == "Malware found but not remediated")
    assert alert["details"]["process"].endswith("invoice.pdf.exe") and alert["details"]["sha256"] == "a" * 64
    detail = client.get(f"/api/console/alerts/{alert['id']}", headers=admin).json()["alert"]["details"]
    occurrence = detail["evidence"][0]
    assert occurrence["count"] == 2 and occurrence["origin"]["domain"] == "mail-attachments.example.net"
    assert occurrence["event"]["type"] == "scan.finding"
    if alert.get("incidentId"):
        incident = client.get(f"/api/console/incidents/{alert['incidentId']}", headers=admin).json()
        assert incident["indicators"]["sha256"][0]["value"] == "a" * 64
        assert incident["alerts"][0]["details"]["evidence"]
