"""Active Directory: role detection from the system profile, the per-domain view and findings, and AD detections
(attacks alert; routine admin work does not)."""

import json
from datetime import timedelta

from conftest import enroll

from fenrir_cloud.models import utcnow

counter = {"n": 0}


def ad_event(event_type, fields, minutes_ago=1):
    counter["n"] += 1
    return {"eventId": f"ad-{counter['n']}", "eventType": event_type, "source": "ad-monitor", "summary": event_type,
            "occurredAt": (utcnow() - timedelta(minutes=minutes_ago)).isoformat() + "Z",
            "payloadJson": json.dumps({"domainController": "DC01.corp.example", **fields})}


def send(client, device, events):
    reply = client.post(f"/api/v1/devices/{device['deviceId']}/telemetry", headers=device["headers"], json={"events": events})
    assert reply.status_code == 200, reply.text


def titles(client, admin, device):
    rows = client.get("/api/console/alerts", headers=admin, params={"device_id": device["deviceId"], "status": ""}).json()
    return sorted((a["title"], a["severity"]) for a in rows)


SNAPSHOT = {
    "domain": {"dnsName": "corp.example", "netbios": "CORP", "mode": "Windows2016Domain", "forest": "corp.example",
               "pdcEmulator": "DC01.corp.example"},
    "domainControllers": [{"name": "DC01.corp.example", "site": "HQ", "roles": ["PDCEmulator"]},
                          {"name": "DC02.corp.example", "site": "HQ", "roles": []}],
    "counts": {"users": 120, "enabledUsers": 100, "computers": 80, "protectedUsers": 0},
    "privilegedGroups": [{"label": "Domain Admins", "name": "Domain Admins", "memberCount": 7,
                          "members": [{"sam": f"admin{i}", "type": "user"} for i in range(7)]},
                         {"label": "Enterprise Admins", "name": "Enterprise Admins", "memberCount": 1, "members": [{"sam": "admin0"}]}],
    "passwordPolicy": {"minLength": 7, "complexity": True, "lockoutThreshold": 0, "maxAgeDays": 0},
    "krbtgt": {"passwordAgeDays": 2400},
    "builtinAdministrator": {"enabled": True, "passwordAgeDays": 900},
    "guestEnabled": False,
    "risky": {"kerberoastable": [{"sam": "svc_sql", "privileged": True}, {"sam": "svc_web", "privileged": False}],
              "asrepRoastable": [{"sam": "legacy"}], "staleUsers": 3},
    "laps": {"legacySchema": False, "windowsSchema": False, "eligibleComputers": 78, "coveredComputers": 0},
    "recycleBin": False,
}
AUDIT_OK_EXCEPT_DS = [{"guid": g, "success": True, "failure": True} for g in (
    "{0CCE9237-69AE-11D9-BED3-505054503030}", "{0CCE9235-69AE-11D9-BED3-505054503030}", "{0CCE9242-69AE-11D9-BED3-505054503030}",
    "{0CCE9240-69AE-11D9-BED3-505054503030}", "{0CCE923F-69AE-11D9-BED3-505054503030}", "{0CCE923C-69AE-11D9-BED3-505054503030}")]


def test_roles_and_domain_view(client, admin, tenant):
    dc = enroll(client, admin, tenant, hostname="DC01", os_version="Windows Server 2022 Standard", serial="DC-1")
    ws = enroll(client, admin, tenant, hostname="PC-01", serial="WS-1")
    profile = {"os": {"name": "Microsoft Windows Server 2022 Standard", "domain": "corp.example"},
               "role": {"kind": "domain-controller", "domainRole": "Primary domain controller", "serverRoles": ["Active Directory Domain Services", "DNS Server"],
                        "workloads": ["Active Directory Domain Services"], "domain": "corp.example"},
               "auditPolicy": AUDIT_OK_EXCEPT_DS, "activeDirectory": SNAPSHOT}
    assert client.post(f"/api/v1/devices/{dc['deviceId']}/profile", headers=dc["headers"], json={"profile": profile}).status_code == 200
    assert client.post(f"/api/v1/devices/{ws['deviceId']}/profile", headers=ws["headers"],
                       json={"profile": {"os": {"name": "Windows 11 Pro"}, "role": {"kind": "workstation", "domainRole": "Member workstation"}}}).status_code == 200

    devices = {d["hostname"]: d for d in client.get("/api/console/devices", headers=admin).json()}
    assert devices["DC01"]["role"] == "domain-controller" and devices["DC01"]["roleLabel"] == "Domain controller"
    assert devices["PC-01"]["role"] == "workstation"
    detail_inventory = client.get(f"/api/console/devices/{dc['deviceId']}", headers=admin).json()["device"]["inventory"]
    assert detail_inventory["serverRoles"] == ["Active Directory Domain Services", "DNS Server"]
    servers = client.get("/api/console/devices", headers=admin, params={"role": "domain-controller"}).json()
    assert [d["hostname"] for d in servers] == ["DC01"]

    domains = client.get("/api/console/ad/domains", headers=admin).json()
    assert [d["domain"] for d in domains] == ["corp.example"]
    detail = client.get(f"/api/console/ad/domains/{tenant['id']}/corp.example", headers=admin).json()
    ids = {f["id"]: f for f in detail["findingsList"]}
    assert ids["krbtgt-old"]["severity"] == "high"
    assert ids["kerberoastable"]["severity"] == "high" and ids["kerberoastable"]["affected"][0] == "svc_sql"
    assert {"asrep", "too-many-das", "no-lockout", "pwd-length", "no-laps", "builtin-admin", "dc-coverage"} <= set(ids)
    assert "Directory Service Access" in ids["audit-policy"]["affected"][0]  # DCSync needs it
    assert ids["dc-coverage"]["title"] == "Fenrir is on 1 of 2 domain controllers"
    assert detail["controllers"][0]["agent"]["hostname"] == "DC01" and detail["controllers"][1]["agent"] is None
    assert 0 <= detail["score"] < 60


def test_ad_attacks_alert_and_routine_work_does_not(client, admin, tenant):
    dc = enroll(client, admin, tenant, hostname="DC02", os_version="Windows Server 2022 Standard", serial="DC-2")
    routine = [
        ad_event("ad.group.member_added", {"EventID": 4728, "TargetUserName": "Finance", "TargetSid": "S-1-5-21-1-2-3-1145", "MemberName": "CN=Jo"}),
        ad_event("ad.user.created", {"EventID": 4720, "TargetUserName": "new.starter", "SubjectUserName": "helpdesk"}),
        ad_event("ad.user.password_reset", {"EventID": 4724, "TargetUserName": "jo"}),
        ad_event("ad.replication.requested", {"EventID": 4662, "SubjectUserName": "MSOL_1a2b", "knownSyncAccount": True}),
        ad_event("ad.kerberos.rc4_service_ticket", {"EventID": 4769, "TargetUserName": "old.pc.user", "ServiceName": "svc_print"}),
        ad_event("ad.kerberos.rc4_service_ticket", {"EventID": 4769, "TargetUserName": "old.pc.user", "ServiceName": "svc_print"}),
        ad_event("ad.kerberos.preauth_failed", {"EventID": 4771, "TargetUserName": "jo", "IpAddress": "10.0.0.5"}),
        ad_event("ad.kerberos.preauth_failed", {"EventID": 4771, "TargetUserName": "jo", "IpAddress": "10.0.0.5"}),
        ad_event("ad.user.locked_out", {"EventID": 4740, "TargetUserName": "jo"}),
        ad_event("ad.object.sensitive_change", {"EventID": 5136, "AttributeLDAPDisplayName": "msDS-KeyCredentialLink",
                                                "ObjectClass": "computer", "SubjectUserName": "PC-01$"}),
    ]
    send(client, dc, routine)
    assert titles(client, admin, dc) == []

    attacks = [ad_event("ad.group.member_added", {"EventID": 4728, "TargetUserName": "Domain Admins", "TargetSid": "S-1-5-21-1-2-3-512",
                                                  "MemberName": "CN=mallory", "privilegedGroup": "Domain Admins"}),
               ad_event("ad.replication.requested", {"EventID": 4662, "SubjectUserName": "mallory", "knownSyncAccount": False})]
    attacks += [ad_event("ad.kerberos.rc4_service_ticket", {"EventID": 4769, "TargetUserName": "eve@CORP", "ServiceName": f"svc_{i}"})
                for i in range(6)]
    attacks += [ad_event("ad.kerberos.preauth_failed", {"EventID": 4771, "TargetUserName": f"user{i}", "IpAddress": "10.9.9.9"})
                for i in range(12)]
    send(client, dc, attacks)
    found = titles(client, admin, dc)
    assert ("Member added to a privileged AD group", "high") in found
    assert ("DCSync - directory replication requested by a non-DC account", "critical") in found
    assert ("Kerberoasting", "high") in found
    assert ("Password spraying against Active Directory (Kerberos)", "high") in found
    assert len(found) == 4

    detail = client.get(f"/api/console/ad/domains/{tenant['id']}/unknown", headers=admin)
    assert detail.status_code == 404  # DC02 sent no profile, so it is not a known DC yet
