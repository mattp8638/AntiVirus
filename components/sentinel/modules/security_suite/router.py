from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import ssl
import socket
import subprocess
from datetime import datetime, timezone
from email import policy
from email.parser import Parser
from pathlib import Path
from typing import Any, Callable, Dict, List
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, Body, HTTPException

from modules.build_manifest import CANONICAL_CAPABILITIES, CANONICAL_CAPABILITY_SLUGS

router = APIRouter()
WORKSPACE_ROOT = Path(__file__).resolve().parents[2]

SEVERITY_SCORE = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
COMMAND_PATTERNS = [
    ("Encoded PowerShell command", re.compile(r"(?i)(powershell|pwsh).*(-enc|-encodedcommand)\b"), "critical"),
    ("PowerShell execution policy bypass", re.compile(r"(?i)(powershell|pwsh).*executionpolicy\s+bypass"), "high"),
    ("PowerShell hidden window", re.compile(r"(?i)(powershell|pwsh).*(windowstyle\s+hidden|-w\s+hidden)"), "high"),
    ("Download cradle command", re.compile(r"(?i)(downloadstring|downloadfile|invoke-webrequest|iwr\b|curl\b|wget\b)"), "high"),
    ("Certutil download behaviour", re.compile(r"(?i)certutil.*(-urlcache|-split|-f).*https?://"), "high"),
    ("Bitsadmin transfer behaviour", re.compile(r"(?i)bitsadmin.*(/transfer|/create|/addfile).*https?://"), "high"),
    ("Regsvr32 remote execution", re.compile(r"(?i)regsvr32.*(scrobj\.dll|/i:https?://)"), "critical"),
    ("MSHTA remote execution", re.compile(r"(?i)mshta\s+https?://"), "critical"),
    ("Rundll32 JavaScript execution", re.compile(r"(?i)rundll32.*(javascript:|mshtml|url\.dll)"), "critical"),
    ("WMI process creation", re.compile(r"(?i)wmic.*process.*call.*create"), "high"),
    ("Scheduled task creation", re.compile(r"(?i)schtasks.*(/create|/change).*(/tn|/tr)"), "high"),
    ("Registry autorun modification", re.compile(r"(?i)reg\s+add.*\\(run|runonce)\\?"), "high"),
    ("New local user creation", re.compile(r"(?i)\bnet(\.exe)?\s+user\s+\S+\s+\S+\s+/add\b"), "high"),
    ("Local administrator membership change", re.compile(r"(?i)\bnet(\.exe)?\s+localgroup\s+administrators\s+\S+\s+/add\b"), "critical"),
    ("Defender preference weakening", re.compile(r"(?i)(set-mppreference|add-mppreference).*(-disable|-exclusion)"), "critical"),
    ("Firewall disable command", re.compile(r"(?i)(netsh\s+advfirewall.*state\s+off|set-netfirewallprofile.*enabled\s+false)"), "high"),
    ("Security log clear command", re.compile(r"(?i)(wevtutil\s+cl\s+security|clear-eventlog\s+.*security)"), "critical"),
    ("Shadow copy deletion", re.compile(r"(?i)(vssadmin|wmic).*shadow.*delete"), "critical"),
    ("Boot recovery weakening", re.compile(r"(?i)bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"), "critical"),
    ("Credential dumping command", re.compile(r"(?i)(mimikatz|sekurlsa|procdump.*lsass|rundll32.*comsvcs\.dll.*minidump)"), "critical"),
]
MITRE_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

MITRE_TECHNIQUES = [
    {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment", "tactics": ["Initial Access"], "keywords": ["phishing attachment", "risky attachment", "attachment", "invoice.pdf.exe", "docm", "xlsm", "double-extension attachment"]},
    {"id": "T1566.002", "name": "Phishing: Spearphishing Link", "tactics": ["Initial Access"], "keywords": ["phishing link", "suspicious url", "url present in email", "shortened url", "link mismatch", "credential link"]},
    {"id": "T1204.001", "name": "User Execution: Malicious Link", "tactics": ["Execution"], "keywords": ["click", "open link", "malicious link", "url redirect", "visible link text does not match"]},
    {"id": "T1204.002", "name": "User Execution: Malicious File", "tactics": ["Execution"], "keywords": ["open attachment", "risky attachment", "malicious file", "double extension", "executable attachment"]},
    {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell", "tactics": ["Execution"], "keywords": ["powershell", "pwsh", "encodedcommand", "-enc"]},
    {"id": "T1059.003", "name": "Command and Scripting Interpreter: Windows Command Shell", "tactics": ["Execution"], "keywords": ["cmd.exe", "command shell", "/c "]},
    {"id": "T1059.005", "name": "Command and Scripting Interpreter: Visual Basic", "tactics": ["Execution"], "keywords": ["wscript", "cscript", ".vbs", "vbscript"]},
    {"id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript", "tactics": ["Execution"], "keywords": ["javascript", ".js", ".jse", "node.exe"]},
    {"id": "T1047", "name": "Windows Management Instrumentation", "tactics": ["Execution"], "keywords": ["wmic", "wmi", "win32_process"]},
    {"id": "T1105", "name": "Ingress Tool Transfer", "tactics": ["Command and Control"], "keywords": ["downloadstring", "downloadfile", "invoke-webrequest", " iwr ", "curl", "wget", "certutil", "bitsadmin", "download cradle"]},
    {"id": "T1218.005", "name": "System Binary Proxy Execution: Mshta", "tactics": ["Defense Evasion"], "keywords": ["mshta", "html application"]},
    {"id": "T1218.010", "name": "System Binary Proxy Execution: Regsvr32", "tactics": ["Defense Evasion"], "keywords": ["regsvr32", "scrobj.dll"]},
    {"id": "T1218.011", "name": "System Binary Proxy Execution: Rundll32", "tactics": ["Defense Evasion"], "keywords": ["rundll32"]},
    {"id": "T1027", "name": "Obfuscated Files or Information", "tactics": ["Defense Evasion"], "keywords": ["encodedcommand", "base64", "obfuscated", "frombase64string", "hidden script"]},
    {"id": "T1036", "name": "Masquerading", "tactics": ["Defense Evasion"], "keywords": ["masquerading", "system-like process", "user-writable path", "lsass.exe", "svchost.exe"]},
    {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools", "tactics": ["Defense Evasion"], "keywords": ["disable defender", "stop-service windefend", "set-mppreference", "impair defenses", "tamper protection"]},
    {"id": "T1562.004", "name": "Impair Defenses: Disable or Modify System Firewall", "tactics": ["Defense Evasion"], "keywords": ["disable firewall", "firewall disabled", "netsh advfirewall set", "broad inbound allow firewall rule"]},
    {"id": "T1112", "name": "Modify Registry", "tactics": ["Defense Evasion"], "keywords": ["reg add", "registry", "run key", "autorun"]},
    {"id": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "tactics": ["Persistence", "Privilege Escalation"], "keywords": ["run key", "startup folder", "registry autorun", "currentversion\\run", "startup item"]},
    {"id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task", "tactics": ["Execution", "Persistence", "Privilege Escalation"], "keywords": ["schtasks", "scheduled task", "task scheduler"]},
    {"id": "T1543.003", "name": "Create or Modify System Process: Windows Service", "tactics": ["Persistence", "Privilege Escalation"], "keywords": ["service installed", "new service", "sc.exe create", "event id 7045", "7045"]},
    {"id": "T1136.001", "name": "Create Account: Local Account", "tactics": ["Persistence"], "keywords": ["new local user", "user created", "net user", "create account"]},
    {"id": "T1098", "name": "Account Manipulation", "tactics": ["Persistence", "Privilege Escalation"], "keywords": ["privilege change", "group membership change", "added to local group", "4732", "4728", "4756"]},
    {"id": "T1078", "name": "Valid Accounts", "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"], "keywords": ["valid account", "remote logon", "local administrator", "unexpected local administrator"]},
    {"id": "T1110", "name": "Brute Force", "tactics": ["Credential Access"], "keywords": ["repeated failed logons", "failed logon", "password spray", "brute force", "4625"]},
    {"id": "T1003", "name": "OS Credential Dumping", "tactics": ["Credential Access"], "keywords": ["lsass", "mimikatz", "credential dumping", "procdump", "sekurlsa"]},
    {"id": "T1555", "name": "Credentials from Password Stores", "tactics": ["Credential Access"], "keywords": ["credential", "password store", "browser password manager", "cookies", "token"]},
    {"id": "T1528", "name": "Steal Application Access Token", "tactics": ["Credential Access"], "keywords": ["oauth", "offline_access", "mail.readwrite", "application access token", "consent"]},
    {"id": "T1082", "name": "System Information Discovery", "tactics": ["Discovery"], "keywords": ["systeminfo", "hostname", "os version", "computername"]},
    {"id": "T1083", "name": "File and Directory Discovery", "tactics": ["Discovery"], "keywords": ["dir ", "ls ", "file discovery", "directory discovery"]},
    {"id": "T1016", "name": "System Network Configuration Discovery", "tactics": ["Discovery"], "keywords": ["ipconfig", "route print", "network configuration", "dns cache"]},
    {"id": "T1049", "name": "System Network Connections Discovery", "tactics": ["Discovery"], "keywords": ["netstat", "network connection", "listening port", "connections"]},
    {"id": "T1021", "name": "Remote Services", "tactics": ["Lateral Movement"], "keywords": ["rdp", "remote desktop", "psexec", "winrm", "remote service"]},
    {"id": "T1114", "name": "Email Collection", "tactics": ["Collection"], "keywords": ["mailbox", "email collection", "mail.read", "message export"]},
    {"id": "T1114.003", "name": "Email Collection: Email Forwarding Rule", "tactics": ["Collection"], "keywords": ["mailbox rule", "forward_to", "redirect_to", "forwarding rule", "suspicious mailbox rule"]},
    {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactics": ["Command and Control"], "keywords": ["https", "http", "web protocol", "remote_address", ":443", ":80"]},
    {"id": "T1090", "name": "Proxy", "tactics": ["Command and Control"], "keywords": ["proxy", "tor", "vpn", "tunnel"]},
    {"id": "T1567", "name": "Exfiltration Over Web Service", "tactics": ["Exfiltration"], "keywords": ["upload", "exfiltration", "cloud storage", "onedrive", "dropbox", "google drive"]},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactics": ["Impact"], "keywords": ["ransom", "encrypted", "locked", "ransomware", "mass file modification", ".locked"]},
    {"id": "T1490", "name": "Inhibit System Recovery", "tactics": ["Impact"], "keywords": ["vssadmin", "delete shadows", "shadow copy deletion", "wmic shadowcopy delete", "recovery tampering"]},
]

MITRE_BY_ID = {item["id"]: item for item in MITRE_TECHNIQUES}

CAPABILITY_ENDPOINTS: Dict[str, str] = {
    "av_scanner": "/api/av-native",
    "ioc_scanner": "/api/ioc-scanner",
    "phishing_email_analyser": "/api/phish",
    "endpoint_investigation_collector": "/api/endpoint/agent/{agent_id}/investigate",
    "persistence_scanner": "/api/persistence",
    "process_tree_viewer": "/api/security-suite/run/process_tree_viewer",
    "suspicious_command_line_analyser": "/api/security-suite/run/suspicious_command_line_analyser",
    "network_connection_monitor": "/api/network",
    "windows_event_log_collector": "/api/security-suite/run/windows_event_log_collector",
    "powershell_activity_analyser": "/api/security-suite/run/powershell_activity_analyser",
    "timeline_builder": "/api/security-suite/run/timeline_builder",
    "evidence_bundle_exporter": "/api/security-suite/run/evidence_bundle_exporter",
    "incident_report_generator": "/api/security-suite/run/incident_report_generator",
    "windows_security_baseline_checker": "/api/endpoint/score",
    "installed_software_inventory": "/api/security-suite/run/installed_software_inventory",
    "cve_kev_vulnerability_matcher": "/api/cve",
    "threat_feed_aggregator": "/api/threat-feeds",
    "yara_rule_manager": "/api/security-suite/run/yara_rule_manager",
    "case_management": "/api/cases",
    "security_health_score": "/api/endpoint/score",
}
for slug in CANONICAL_CAPABILITY_SLUGS:
    CAPABILITY_ENDPOINTS.setdefault(slug, f"/api/security-suite/run/{slug}")

WORKFLOW_PACKS: Dict[str, Dict[str, Any]] = {
    "endpoint_triage": {
        "name": "Endpoint Triage",
        "capabilities": [
            "process_tree_viewer",
            "suspicious_command_line_analyser",
            "network_connection_monitor",
            "persistence_scanner",
            "windows_event_log_collector",
            "powershell_activity_analyser",
            "timeline_builder",
        ],
    },
    "email_investigation": {
        "name": "Email Investigation",
        "capabilities": [
            "phishing_email_analyser",
            "email_header_analyser",
            "attachment_risk_analyser",
            "url_redirect_tracer",
            "mailbox_rule_checker",
        ],
    },
    "hardening_audit": {
        "name": "Hardening Audit",
        "capabilities": [
            "windows_security_baseline_checker",
            "backup_readiness_checker",
            "patch_status_checker",
            "browser_security_checker",
            "usb_guard",
            "firewall_rule_auditor",
            "local_account_admin_audit",
            "security_health_score",
            "remediation_guidance_wizard",
        ],
    },
    "cloud_saas_review": {
        "name": "Cloud/SaaS Review",
        "capabilities": [
            "cloud_saas_audit_importer",
            "oauth_app_permission_checker",
            "microsoft_365_security_checker",
            "logon_event_analyser",
            "privilege_change_monitor",
        ],
    },
    "rule_governance": {
        "name": "Rule Governance",
        "capabilities": [
            "threat_feed_aggregator",
            "yara_rule_manager",
            "sigma_rule_manager",
            "mitre_attack_mapper",
            "report_signing_integrity_checker",
            "signed_update_rule_distribution_system",
        ],
    },
}

PACK_SAMPLE_INPUTS: Dict[str, Dict[str, Any]] = {
    "process_tree_viewer": {"processes": [{"pid": 10, "name": "winword.exe"}, {"pid": 11, "ppid": 10, "name": "powershell.exe", "cmdline_text": "powershell.exe -EncodedCommand SQBFAFgA"}]},
    "suspicious_command_line_analyser": {"commands": ["powershell.exe -EncodedCommand SQBFAFgA"]},
    "network_connection_monitor": {"connections": [{"process_name": "powershell.exe", "remote_address": "203.0.113.10:443"}]},
    "persistence_scanner": {"scheduled_tasks": [{"TaskName": "Updater", "Actions": "powershell.exe -ExecutionPolicy Bypass"}]},
    "windows_event_log_collector": {"events": [{"Id": 7045, "Message": "A service was installed"}]},
    "powershell_activity_analyser": {"powershell_events": [{"Id": 4104, "Message": "Invoke-WebRequest http://example.test/p.ps1"}]},
    "timeline_builder": {"findings": [{"finding_id": "F-1", "module": "PowerShell Activity Analyser", "title": "Encoded PowerShell command", "severity": "critical", "created_at": "2026-04-28T10:00:00Z"}]},
    "phishing_email_analyser": {"raw_headers": "From: a@example.com\nReply-To: b@evil.test\nAuthentication-Results: mx; spf=fail\n\n", "body": "Review https://bit.ly/example", "attachments": [{"name": "invoice.pdf.exe"}]},
    "email_header_analyser": {"raw_headers": "From: a@example.com\nReply-To: b@evil.test\nAuthentication-Results: mx; spf=fail\n\n"},
    "attachment_risk_analyser": {"attachments": [{"name": "invoice.pdf.exe"}]},
    "url_redirect_tracer": {"urls": ["https://bit.ly/example"], "live_trace": False},
    "mailbox_rule_checker": {"org_domains": ["example.com"], "rules": [{"name": "Forward", "forward_to": "attacker@evil.test"}]},
    "windows_security_baseline_checker": {"controls": {"defender_enabled": False, "firewall_enabled": True, "rdp_enabled": True}},
    "backup_readiness_checker": {"last_backup_at": None, "restore_tested_at": None, "offline_backup": False, "protected_paths": []},
    "patch_status_checker": {"missing_kbs": ["KB5000000"], "require_last_update": False},
    "browser_security_checker": {"browsers": [{"name": "Edge", "safe_browsing_enabled": False, "extensions": [{"name": "Unknown", "permissions": ["cookies"]}]}]},
    "usb_guard": {"approved_serials": ["ABC"], "devices": [{"serial": "XYZ", "writable": True}], "read_only_required": True},
    "firewall_rule_auditor": {"rules": [{"direction": "inbound", "action": "allow", "remote_address": "any", "profile": "public"}]},
    "local_account_admin_audit": {"administrators": ["admin1", "admin2", "admin3"], "max_admins": 2},
    "security_health_score": {"findings": [{"severity": "critical"}, {"severity": "medium"}]},
    "remediation_guidance_wizard": {"findings": [{"finding_id": "F-1", "title": "Firewall disabled", "severity": "high", "recommended_action": "Enable firewall."}]},
    "cloud_saas_audit_importer": {"provider": "m365", "records": [{"CreationTime": "2026-04-28T10:00:00Z", "UserId": "user@example.com", "Operation": "ConsentToApplication"}]},
    "oauth_app_permission_checker": {"apps": [{"name": "Unknown Sync", "publisher_verified": False, "scopes": ["Mail.ReadWrite", "offline_access"]}]},
    "microsoft_365_security_checker": {"controls": {"mfa_enabled": False, "legacy_auth_blocked": False}},
    "logon_event_analyser": {"events": [{"Id": 4625, "user": "alice"}, {"Id": 4625, "user": "alice"}, {"Id": 4625, "user": "alice"}, {"Id": 4625, "user": "alice"}, {"Id": 4625, "user": "alice"}]},
    "privilege_change_monitor": {"events": [{"Id": 4732, "TargetUserName": "new-admin"}]},
    "threat_feed_aggregator": {"feeds": [{"name": "local", "indicators": [{"value": "203.0.113.10"}]}]},
    "yara_rule_manager": {"rules": ["rule Suspicious { strings: $a = \"powershell\" condition: $a }"]},
    "sigma_rule_manager": {"rules": ["title: Suspicious PowerShell\nlogsource:\n  product: windows\ndetection:\n  selection:\n    Image|endswith: powershell.exe\n  condition: selection"]},
    "mitre_attack_mapper": {"signals": ["PowerShell encodedcommand vssadmin"]},
    "report_signing_integrity_checker": {"document": {"case": "CASE-1"}},
    "signed_update_rule_distribution_system": {"package": {"version": "1.0.0", "rules": []}, "signature": ""},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, default=str, sort_keys=True)


CAPABILITY_EXPLANATIONS = {
    "AV Scanner": "Sentinel reviewed file evidence for executable, script-like, or otherwise risky artifacts that should be scanned before a user opens them.",
    "IOC Scanner": "Sentinel extracted indicators such as IPs, domains, URLs, hashes, and email addresses so they can be enriched and hunted across telemetry.",
    "Phishing Email Analyser": "Sentinel reviewed email headers, body content, links, and attachments for signs of sender spoofing, phishing, or malicious delivery.",
    "Persistence Scanner": "Sentinel inspected startup paths, scheduled tasks, services, and autorun-style entries for places malware commonly uses to survive reboot.",
    "Process Tree Viewer": "Sentinel reviewed parent-child process relationships to spot unusual launch chains, such as Office or browsers starting scripting tools.",
    "Suspicious Command Line Analyser": "Sentinel inspected command lines for signs of hidden execution, security bypass, remote download, or recovery tampering.",
    "Network Connection Monitor": "Sentinel reviewed connection evidence to spot suspicious tools or scripts communicating with remote systems.",
    "DNS Monitor": "Sentinel checked DNS answers against expected behaviour so unexpected resolution changes or lookup failures are visible.",
    "DNS Protection Tool": "Sentinel reviewed proposed DNS blocking policy for overly broad entries or risky protection changes.",
    "Windows Event Log Collector": "Sentinel reviewed Windows event log records for security-relevant activity such as service installs, log clearing, or command execution.",
    "PowerShell Activity Analyser": "Sentinel inspected PowerShell process and event evidence for script execution, obfuscation, downloads, and bypass behaviour.",
    "Ransomware Behaviour Guard": "Sentinel reviewed file and command activity for behaviours often seen during ransomware staging or recovery sabotage.",
    "Backup Readiness Checker": "Sentinel checked whether backup and restore controls are strong enough to support recovery after an incident.",
    "Windows Security Baseline Checker": "Sentinel compared endpoint controls against the expected Windows security baseline.",
    "Patch Status Checker": "Sentinel reviewed missing updates and patch age to identify systems drifting out of security update policy.",
    "Installed Software Inventory": "Sentinel reviewed installed software for outdated, risky, or unsupported applications.",
    "CVE / KEV Vulnerability Matcher": "Sentinel matched observed software or CVEs against known vulnerabilities and exploitation status.",
    "Browser Security Checker": "Sentinel reviewed browser controls and extensions for risky configuration or excessive permissions.",
    "USB Guard": "Sentinel reviewed removable media evidence against approved device and read-only policy.",
    "Firewall Rule Auditor": "Sentinel checked firewall rules for broad inbound access or public-profile exposure.",
    "Local Account/Admin Audit": "Sentinel reviewed local users and administrator membership for privilege and account hygiene issues.",
    "Logon Event Analyser": "Sentinel reviewed logon records for remote access, repeated failures, and authentication patterns that need investigation.",
    "Privilege Change Monitor": "Sentinel reviewed privilege and group membership events for unexpected elevation or account changes.",
    "Mailbox Rule Checker": "Sentinel inspected mailbox rules for forwarding, deletion, hiding, or routing behaviour commonly used after mailbox compromise.",
    "Email Header Analyser": "Sentinel parsed email headers and authentication results to judge whether the sender path can be trusted.",
    "Attachment Risk Analyser": "Sentinel reviewed attachment names and types for formats commonly used to deliver malware or disguise payloads.",
    "URL Redirect Tracer": "Sentinel reviewed URLs and redirect risk indicators before a user follows the link.",
    "OAuth App Permission Checker": "Sentinel reviewed OAuth application grants for excessive scopes, unverified publishers, and risky consent.",
    "Microsoft 365 Security Checker": "Sentinel compared tenant controls against expected Microsoft 365 security settings.",
    "YARA Rule Manager": "Sentinel checked YARA rules for basic rule structure before distribution.",
    "Sigma Rule Manager": "Sentinel checked Sigma rules for required fields before they are enabled or shared.",
    "Alert Correlation Engine": "Sentinel grouped alerts by shared entities so repeated activity against the same host, user, or source is easier to triage.",
    "Secrets Scanner": "Sentinel scanned text and repository content for exposed keys, tokens, passwords, or private key material.",
    "Git/Repo Security Scanner": "Sentinel reviewed repository metadata for sensitive files and unsafe source-control exposure.",
    "Container Image Scanner": "Sentinel reviewed container build content for risky base images, root execution, or embedded secrets.",
    "Report Signing / Integrity Checker": "Sentinel verified whether a report or package still matches its expected signature.",
    "Signed Update and Rule Distribution System": "Sentinel verified update or rule packages before trusting them for distribution.",
    "External Service Checker": "Sentinel checked an authorized external target for DNS reachability, HTTP response health, TLS certificate status, and exposed ports.",
}

FINDING_INTENTS = [
    ("encoded powershell command", "the command is trying to run PowerShell with its instructions encoded, which hides the real script text from casual review and many logs."),
    ("powershell execution policy bypass", "the command is trying to run PowerShell while ignoring the local script execution policy."),
    ("powershell hidden window", "the command is trying to run PowerShell without showing a visible window to the user."),
    ("download cradle command", "the command is trying to download content from a URL, often to stage or run code from a remote source."),
    ("certutil download behaviour", "the command is trying to use the built-in certutil tool as a file downloader."),
    ("bitsadmin transfer behaviour", "the command is trying to use the built-in BITS transfer tool to download or stage remote content."),
    ("regsvr32 remote execution", "the command is trying to execute remote script content through regsvr32 instead of a normal script host."),
    ("mshta remote execution", "the command is trying to launch remote HTML application or script content."),
    ("rundll32 javascript execution", "the command is trying to execute script content through rundll32, a Windows binary commonly abused for proxy execution."),
    ("wmi process creation", "the command is trying to start a process through Windows Management Instrumentation."),
    ("scheduled task creation", "the command is trying to create or modify a scheduled task that can run again later."),
    ("registry autorun modification", "the command is trying to add or change an autorun registry key for persistence."),
    ("new local user creation", "the command is trying to create a local user account."),
    ("local administrator membership change", "the command is trying to add an account to the local Administrators group."),
    ("defender preference weakening", "the command is trying to weaken Microsoft Defender settings or add scan exclusions."),
    ("firewall disable command", "the command is trying to turn off or weaken Windows firewall protection."),
    ("security log clear command", "the command is trying to clear Windows Security logs to remove investigation evidence."),
    ("shadow copy deletion", "the command is trying to remove Windows recovery snapshots, which makes rollback and recovery harder."),
    ("boot recovery weakening", "the command is trying to weaken Windows boot recovery options."),
    ("credential dumping command", "the command is trying to access or dump credentials from memory or credential stores."),
    ("recovery tampering command observed", "the activity is trying to interfere with recovery options, a common step before or during ransomware activity."),
    ("mass file modification pattern", "many files changed in a short pattern, which can indicate encryption, destructive modification, or automated tampering."),
    ("ransomware-style file extensions observed", "files were renamed to extensions commonly associated with encryption or ransom activity."),
    ("suspicious parent-child process chain", "a parent process launched a child process that is often abused for scripting, download, or execution."),
    ("risky process has missing parent", "a process that is commonly abused for execution does not have its expected parent in the supplied telemetry."),
    ("system-like process running from user-writable path", "a process name that normally belongs in Windows system folders appears to be running from a user-writable location, which can indicate masquerading."),
    ("script/system tool has network connection", "a scripting or system utility is communicating externally, which can indicate payload download, command-and-control, or data movement."),
    ("domain did not resolve", "the domain lookup failed, which may be expected for dead infrastructure or may indicate a DNS or policy problem."),
    ("dns answer changed from baseline", "the domain is resolving differently from the expected baseline, which could be infrastructure change, hijack, or sinkhole behaviour."),
    ("invalid domain supplied", "the DNS monitor was given a value that does not look like a valid domain name."),
    ("expected mail domain has no mx records", "the domain is expected to receive email but does not currently show mail exchanger records."),
    ("domain has fewer than two name servers", "the domain may have weak DNS resilience because it has fewer authoritative name servers than expected."),
    ("dns answer points to private or reserved ip", "the domain resolves to an address that is private, reserved, or not normally reachable from the public internet."),
    ("invalid sinkhole ip supplied", "the DNS protection policy was given an invalid sinkhole address and Sentinel replaced it with a safe default."),
    ("invalid domain in dns policy", "the DNS protection policy contains an entry that is not a valid domain name."),
    ("dns block conflicts with allowlist", "the same domain or root domain is both allowed and blocked, so the policy would be ambiguous."),
    ("high-value domain block requested", "the policy would block a widely used business domain and should require explicit approval."),
    ("wildcard dns block requested", "the DNS protection rule could block a broad set of domains, so it needs scope validation."),
    ("email authentication failure", "the message failed sender authentication, so the sender identity cannot be trusted without more context."),
    ("reply-to domain differs from from domain", "replies would go to a different domain than the visible sender, a common phishing and fraud pattern."),
    ("high-risk attachment type", "the attachment type can execute code or scripts if opened."),
    ("double-extension attachment", "the attachment is trying to look like one file type while ending as a more dangerous executable or script type."),
    ("archive attachment requires inspection", "the archive may hide files that need to be extracted and scanned safely."),
    ("url present in email body", "the email is trying to send the user to an external location that should be reputation-checked."),
    ("shortened or punycode url", "the URL may be hiding its real destination or using lookalike domain encoding."),
    ("non-http url supplied", "the link uses a non-web scheme that can trigger local applications or unusual handlers."),
    ("high-risk oauth permission grant", "the app is asking for sensitive access that could expose mailbox or tenant data."),
    ("oauth app publisher not verified", "the app publisher has not been verified, which increases consent and impersonation risk."),
    ("m365 control drift", "a Microsoft 365 control is not set to the expected secure value."),
    ("baseline drift", "an endpoint control is not set to the expected secure value."),
    ("missing security updates", "the system is missing updates that may close known security weaknesses."),
    ("endpoint patch age exceeds policy", "the endpoint has gone longer than policy allows without recent patching."),
    ("legacy or risky software installed", "the installed software may be unsupported or commonly targeted."),
    ("known exploited vulnerability match", "the vulnerability is known to be exploited in the wild and should be prioritised."),
    ("vulnerability match", "the observed software or CVE matches a known vulnerability that needs triage."),
    ("safe browsing disabled", "browser protection against malicious sites or downloads is disabled."),
    ("high-permission browser extension", "a browser extension has permissions that could expose user data or browser activity."),
    ("unapproved usb device", "a removable device that is not on the approved list was observed."),
    ("writable usb device violates policy", "the removable device can be written to when policy expects read-only media."),
    ("broad inbound allow firewall rule", "the firewall rule allows inbound access from a wide source range."),
    ("inbound public profile allow rule", "the firewall permits inbound access while the public network profile is in scope."),
    ("excessive local administrators", "too many accounts have local admin rights, increasing the impact of credential theft."),
    ("unexpected local administrator", "an account has local admin rights that were not expected."),
    ("password never expires on local account", "a local account has a weak lifecycle setting that can increase stale credential risk."),
    ("repeated failed logons", "the same account has repeated authentication failures, which can indicate brute force, password spray, or stale credentials."),
    ("remote/network logon observed", "a remote or network logon occurred and should be checked against expected access."),
    ("privilege or group membership change", "an account or group privilege changed, which can indicate legitimate admin work or unauthorized elevation."),
    ("suspicious mailbox rule behaviour", "the mailbox rule may be forwarding, hiding, deleting, or redirecting mail in a way often seen after compromise."),
    ("invalid yara rule shape", "the YARA rule does not have enough valid structure to distribute safely."),
    ("sigma rule missing required fields", "the Sigma rule is missing metadata or detection fields needed for reliable use."),
    ("multiple alerts correlated to one entity", "several alerts point at the same user, host, or source, making the combined activity more important than one alert alone."),
    ("sensitive-looking file tracked by git", "a file name suggests credentials or secrets may be stored in source control."),
    ("repository path outside workspace was not scanned", "the requested repository path was outside the trusted workspace boundary."),
    ("base image uses latest tag", "the container build is not pinned to a stable base image version."),
    ("container does not set non-root user", "the container may run as root, increasing impact if the workload is compromised."),
    ("secret-like value in dockerfile", "a secret appears to be embedded in the image build definition."),
    ("report signature verification failed", "the report content does not match the expected signature."),
    ("update package signature missing or invalid", "the update package cannot be trusted because its signature did not verify."),
    ("mapped activity to", "Sentinel is translating the observed behaviour into the MITRE ATT&CK framework so the investigation can show likely adversary tactics and techniques."),
    ("audit log cleared", "the Windows Security audit log was cleared, which can remove investigation evidence."),
    ("failed logon observed", "Windows recorded an unsuccessful sign-in attempt."),
    ("repeated failed logons", "multiple failed sign-ins for the same account may indicate password spray, brute force, or stale credentials."),
    ("special privileges assigned", "an account logged on with powerful local privileges."),
    ("user account created", "a new account was created and should be validated against change records."),
    ("user added to privileged group", "an account was added to a privileged group, increasing its access."),
    ("user added to local privileged group", "an account was added to a local privileged group, increasing endpoint control."),
    ("service installed", "a new service was installed, which can be legitimate software deployment or persistence."),
    ("scheduled task event", "a scheduled task was created or changed and may run code later."),
    ("defender malware detection", "Microsoft Defender reported malware or unwanted software."),
    ("defender configuration changed", "Microsoft Defender settings changed and should be checked for tampering."),
    ("powershell script block contains suspicious behaviour", "PowerShell script content includes behaviour often used for download, obfuscation, defense evasion, or execution."),
    ("powershell encoded command decoded", "Sentinel decoded a PowerShell encoded command so the real command text can be reviewed."),
    ("timeline item missing timestamp", "an item could not be placed confidently in time, which weakens the incident chronology."),
    ("high-risk activity cluster in timeline", "multiple high-impact events are close together in the same investigation timeline and should be reviewed as one activity chain."),
    ("private or local target blocked", "the requested external check pointed at a private or local address and Sentinel stopped it by default."),
    ("target has no dns answers", "the target name did not return DNS addresses."),
    ("dns lookup failed", "Sentinel could not resolve the target hostname."),
    ("http probe failed", "Sentinel could not reach the target over the requested HTTP or HTTPS path."),
    ("external service returned server error", "the external service responded with a server-side error."),
    ("missing http security header", "the HTTPS response is missing a browser security header that usually helps reduce client-side attack risk."),
    ("tls probe failed", "Sentinel could not complete a TLS certificate check against the target."),
    ("tls certificate expires soon", "the target certificate is close to expiry and could cause outage or trust failures."),
    ("unexpected open external port", "the target exposes a port that is not part of the expected standard web surface."),
]


def _short_text(value: Any, limit: int = 240) -> str:
    text = _text(value).replace("\r", " ").replace("\n", " ").strip()
    return text if len(text) <= limit else f"{text[:limit - 3]}..."


def _label(key: str) -> str:
    return str(key).replace("_", " ").replace("-", " ").title()


def _module_explanation(module: str) -> str:
    return CAPABILITY_EXPLANATIONS.get(module, f"Sentinel ran the {module} capability and reviewed the supplied evidence for risky or unexpected behaviour.")


def _finding_intent(title: str) -> str:
    raw = str(title or "").lower()
    for needle, intent in FINDING_INTENTS:
        if needle in raw:
            return intent
    return "the behaviour is unusual, weak, or risky for this check. It is not proof by itself, but it deserves validation against normal business activity."


def _evidence_summary(evidence: Any) -> str:
    if isinstance(evidence, dict):
        if evidence.get("command"):
            return f"Command line observed: {_short_text(evidence.get('command'))}"
        process = evidence.get("process")
        if isinstance(process, dict):
            command = process.get("cmdline_text") or process.get("cmdline") or process.get("command")
            if command:
                return f"Process command line observed: {_short_text(command)}"
            name = process.get("name") or process.get("process_name") or process.get("Image")
            if name:
                return f"Process observed: {_short_text(name)}"
        for key in ["Message", "message", "Actions", "action", "url", "domain", "path", "name", "control", "host", "target", "remote_address", "source_ip", "sha256", "rule"]:
            if evidence.get(key):
                return f"{_label(key)}: {_short_text(evidence.get(key))}"
        if "expected" in evidence or "actual" in evidence:
            return f"Expected {_short_text(evidence.get('expected'))}; observed {_short_text(evidence.get('actual'))}."
        if "missing" in evidence:
            return f"Missing items: {_short_text(evidence.get('missing'))}"
        if evidence:
            preview = ", ".join(f"{_label(k)}: {_short_text(v, 80)}" for k, v in list(evidence.items())[:4])
            return preview
    if evidence:
        return _short_text(evidence)
    return "No compact evidence summary was available for this finding."


def _stable_id(title: str, evidence: Any) -> str:
    digest = hashlib.sha1(json.dumps({"title": title, "evidence": evidence}, sort_keys=True, default=str).encode()).hexdigest()
    return f"F-{digest[:12].upper()}"


def _finding(module: str, title: str, severity: str, evidence: Any, recommendation: str) -> Dict[str, Any]:
    what_was_checked = _module_explanation(module)
    possible_intent = _finding_intent(title)
    evidence_summary = _evidence_summary(evidence)
    plain_english = f"{what_was_checked} It found: {title}. In plain English, {possible_intent}"
    return {
        "finding_id": _stable_id(title, evidence),
        "module": module,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "plain_english": plain_english,
        "what_was_checked": what_was_checked,
        "possible_intent": possible_intent,
        "evidence_summary": evidence_summary,
        "analyst_next_step": recommendation,
        "recommended_action": recommendation,
        "created_at": _now(),
    }


def _finish(slug: str, payload: Dict[str, Any], data: Dict[str, Any] | None = None, findings: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    findings = findings or []
    data = data or {}
    highest = max((f.get("severity", "informational") for f in findings), key=lambda s: SEVERITY_SCORE.get(s, 0), default="informational")
    return {
        "capability": slug,
        "status": "complete",
        "generated_at": _now(),
        "input_summary": {"keys": sorted(payload.keys()), "item_count": sum(len(_as_list(v)) for v in payload.values())},
        "highest_severity": highest,
        "finding_count": len(findings),
        "findings": sorted(findings, key=lambda f: SEVERITY_SCORE.get(f.get("severity", "informational"), 0), reverse=True),
        "data": data,
    }


def _pack_summary(pack_slug: str, pack: Dict[str, Any], results: List[Dict[str, Any]]) -> Dict[str, Any]:
    findings = [finding for result in results for finding in result.get("findings", [])]
    highest = max((finding.get("severity", "informational") for finding in findings), key=lambda s: SEVERITY_SCORE.get(s, 0), default="informational")
    score = max(0, 100 - sum({"critical": 25, "high": 15, "medium": 8, "low": 3}.get(str(finding.get("severity", "")).lower(), 0) for finding in findings))
    timeline = [
        {
            "time": finding.get("created_at") or _now(),
            "source": finding.get("module"),
            "event": finding.get("title"),
            "severity": finding.get("severity", "informational"),
            "evidence_ref": finding.get("finding_id"),
            "plain_english": finding.get("plain_english"),
        }
        for finding in findings
    ]
    timeline.sort(key=lambda item: str(item.get("time") or ""))
    remediation = [
        {
            "finding_id": finding.get("finding_id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "steps": [
                "Preserve related evidence",
                "Validate business context",
                finding.get("recommended_action") or "Apply Sentinel remediation guidance",
                "Re-run the workflow pack to verify closure",
            ],
        }
        for finding in findings[:25]
    ]
    return {
        "pack": pack_slug,
        "name": pack["name"],
        "status": "complete",
        "generated_at": _now(),
        "capability_count": len(pack["capabilities"]),
        "finding_count": len(findings),
        "highest_severity": highest,
        "health_score": score,
        "health_band": "critical" if score < 50 else "high" if score < 70 else "medium" if score < 85 else "low",
        "capabilities": pack["capabilities"],
        "results": results,
        "findings": sorted(findings, key=lambda f: SEVERITY_SCORE.get(f.get("severity", "informational"), 0), reverse=True),
        "timeline": timeline,
        "remediation": remediation,
        "case_draft": {
            "title": f"{pack['name']} findings",
            "severity": highest,
            "summary": f"{pack['name']} produced {len(findings)} finding(s) across {len(pack['capabilities'])} capabilities.",
            "finding_ids": [finding.get("finding_id") for finding in findings],
        },
    }


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _extract_iocs(text: str) -> Dict[str, List[str]]:
    return {
        "ipv4": sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))),
        "urls": sorted(set(re.findall(r"https?://[^\s'\"<>]+", text, flags=re.I))),
        "emails": sorted(set(re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text))),
        "sha256": sorted(set(re.findall(r"\b[a-fA-F0-9]{64}\b", text))),
        "domains": sorted(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text))),
    }


def _command_line_findings(processes: List[Dict[str, Any]], module: str = "Suspicious Command Line Analyser") -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for process in processes:
        command = _text(process.get("cmdline_text") or process.get("cmdline") or process.get("command") or "")
        for title, pattern, severity in COMMAND_PATTERNS:
            if pattern.search(command):
                findings.append(_finding(module, title, severity, {"process": process, "command": command}, "Validate parent process, user context and execution source. Preserve evidence before remediation."))
    return findings


def _command_features(process: Dict[str, Any]) -> Dict[str, Any]:
    command = _text(process.get("cmdline_text") or process.get("cmdline") or process.get("command") or "")
    first_token = command.strip().split(maxsplit=1)[0].strip('"') if command.strip() else str(process.get("name") or "")
    executable = Path(first_token).name.lower()
    urls = re.findall(r"https?://[^\s'\"<>]+", command, flags=re.I)
    switches = sorted(set(re.findall(r"(?<!\w)(?:--?/[A-Za-z0-9_-]+|--[A-Za-z0-9_-]+|-[A-Za-z][A-Za-z0-9_-]*)", command)))
    suspicious_matches = [
        {"title": title, "severity": severity}
        for title, pattern, severity in COMMAND_PATTERNS
        if pattern.search(command)
    ]
    risk_points = sum({"critical": 45, "high": 30, "medium": 12, "low": 5}.get(item["severity"], 0) for item in suspicious_matches)
    if urls:
        risk_points += 10
    return {
        "process": process.get("name") or executable or "unknown",
        "executable": executable or "unknown",
        "command_line": command,
        "switches": switches,
        "urls": urls,
        "match_count": len(suspicious_matches),
        "matches": suspicious_matches,
        "risk_score": min(100, risk_points),
        "risk_band": "critical" if risk_points >= 70 else "high" if risk_points >= 40 else "medium" if risk_points >= 18 else "low" if risk_points else "informational",
    }


def _av_scanner(payload: Dict[str, Any]) -> Dict[str, Any]:
    files = _as_list(payload.get("files") or payload.get("file") or [])
    findings: List[Dict[str, Any]] = []
    scanned = []
    risky_ext = {".exe", ".dll", ".scr", ".ps1", ".vbs", ".js", ".hta", ".iso", ".lnk"}
    for item in files:
        path = str(item.get("path") if isinstance(item, dict) else item)
        suffix = Path(path).suffix.lower()
        entry = {"path": path, "extension": suffix, "sha256": item.get("sha256") if isinstance(item, dict) else None}
        scanned.append(entry)
        if suffix in risky_ext:
            findings.append(_finding("AV Scanner", "Executable or script-like artifact supplied", "medium", entry, "Scan with native AV engine and verify publisher/signature before execution."))
    return _finish("av_scanner", payload, {"scanned_files": scanned, "native_route": "/api/av-native"}, findings)


def _ioc_scanner(payload: Dict[str, Any]) -> Dict[str, Any]:
    text = _text(payload.get("text") or payload)
    iocs = _extract_iocs(text)
    findings = [_finding("IOC Scanner", f"{key.upper()} indicator extracted", "low", {"type": key, "value": value}, "Enrich this indicator with threat feeds and local telemetry.") for key, values in iocs.items() for value in values]
    return _finish("ioc_scanner", payload, {"iocs": iocs}, findings)


def _email_header_analyser(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw = str(payload.get("raw_headers") or payload.get("headers") or "")
    message = Parser(policy=policy.default).parsestr(raw)
    headers = {key.lower(): message.get_all(key, []) for key in message.keys()}
    auth = " ".join(headers.get("authentication-results", []))
    findings: List[Dict[str, Any]] = []
    if re.search(r"\b(spf|dkim|dmarc)=fail", auth, re.I):
        findings.append(_finding("Email Header Analyser", "Email authentication failure", "high", {"authentication_results": auth}, "Treat as suspicious unless a trusted forwarding path explains the failure."))
    if message.get("Reply-To") and message.get("From") and str(message.get("Reply-To")).split("@")[-1].lower() != str(message.get("From")).split("@")[-1].lower():
        findings.append(_finding("Email Header Analyser", "Reply-To domain differs from From domain", "medium", {"from": message.get("From"), "reply_to": message.get("Reply-To")}, "Verify sender legitimacy and user interaction before release."))
    return _finish("email_header_analyser", payload, {"headers": headers, "from": message.get("From"), "subject": message.get("Subject")}, findings)


def _attachment_risk_analyser(payload: Dict[str, Any]) -> Dict[str, Any]:
    attachments = _as_list(payload.get("attachments") or [])
    findings: List[Dict[str, Any]] = []
    risky = {".exe", ".scr", ".js", ".vbs", ".ps1", ".hta", ".lnk", ".iso", ".img", ".docm", ".xlsm"}
    archive = {".zip", ".rar", ".7z"}
    for attachment in attachments:
        name = str(attachment.get("name") if isinstance(attachment, dict) else attachment)
        suffixes = [s.lower() for s in Path(name).suffixes]
        evidence = {"name": name, "suffixes": suffixes}
        if suffixes and suffixes[-1] in risky:
            findings.append(_finding("Attachment Risk Analyser", "High-risk attachment type", "high", evidence, "Quarantine and detonate before allowing user access."))
        if len(suffixes) > 1 and suffixes[-1] in risky:
            findings.append(_finding("Attachment Risk Analyser", "Double-extension attachment", "critical", evidence, "Block or quarantine; double extensions are commonly used to disguise payloads."))
        if suffixes and suffixes[-1] in archive:
            findings.append(_finding("Attachment Risk Analyser", "Archive attachment requires inspection", "medium", evidence, "Extract safely and scan contained files recursively."))
    return _finish("attachment_risk_analyser", payload, {"attachment_count": len(attachments)}, findings)


def _phishing_email_analyser(payload: Dict[str, Any]) -> Dict[str, Any]:
    header_result = _email_header_analyser(payload)
    attachment_result = _attachment_risk_analyser(payload)
    text = _text(payload.get("body") or payload)
    iocs = _extract_iocs(text)
    findings = header_result["findings"] + attachment_result["findings"]
    if iocs["urls"]:
        findings.append(_finding("Phishing Email Analyser", "URL present in email body", "medium", {"urls": iocs["urls"]}, "Trace redirects and compare domains against trusted sender context."))
    return _finish("phishing_email_analyser", payload, {"iocs": iocs, "header_summary": header_result["data"]}, findings)


def _process_tree_viewer(payload: Dict[str, Any]) -> Dict[str, Any]:
    processes = _as_list(payload.get("processes") or [])
    normalized: List[Dict[str, Any]] = []
    for raw in processes:
        if not isinstance(raw, dict):
            continue
        pid = raw.get("pid") or raw.get("ProcessId") or raw.get("process_id")
        parent_pid = raw.get("ppid") or raw.get("parent_pid") or raw.get("ParentProcessId")
        try:
            pid = int(pid)
        except Exception:
            pass
        try:
            parent_pid = int(parent_pid) if parent_pid is not None else None
        except Exception:
            pass
        name = str(raw.get("name") or raw.get("process_name") or raw.get("Image") or raw.get("ProcessName") or "unknown")
        normalized.append({
            **raw,
            "pid": pid,
            "parent_pid": parent_pid,
            "name": Path(name).name.lower(),
            "display_name": Path(name).name,
            "cmdline_text": raw.get("cmdline_text") or raw.get("cmdline") or raw.get("command") or raw.get("CommandLine") or "",
            "executable_path": raw.get("path") or raw.get("executable_path") or raw.get("ExecutablePath") or raw.get("Image") or "",
            "user": raw.get("user") or raw.get("username") or raw.get("User") or "",
            "created_at": raw.get("created_at") or raw.get("start_time") or raw.get("CreationDate") or raw.get("time"),
        })
    by_pid = {p.get("pid"): p for p in normalized if p.get("pid") is not None}
    children: Dict[Any, List[Dict[str, Any]]] = {}
    for process in normalized:
        children.setdefault(process.get("parent_pid"), []).append(process)

    def lineage(process: Dict[str, Any]) -> List[Dict[str, Any]]:
        chain = []
        seen = set()
        current = process
        while current and current.get("parent_pid") in by_pid and current.get("parent_pid") not in seen:
            parent = by_pid[current["parent_pid"]]
            seen.add(parent.get("pid"))
            chain.append({"pid": parent.get("pid"), "name": parent.get("display_name") or parent.get("name"), "parent_pid": parent.get("parent_pid")})
            current = parent
        chain.reverse()
        chain.append({"pid": process.get("pid"), "name": process.get("display_name") or process.get("name"), "parent_pid": process.get("parent_pid")})
        return chain

    tree = []
    suspicious_chains = []
    orphan_processes = []
    findings: List[Dict[str, Any]] = []
    suspicious = {
        "winword.exe": {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"},
        "excel.exe": {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"},
        "powerpnt.exe": {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"},
        "outlook.exe": {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"},
        "chrome.exe": {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
        "msedge.exe": {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
        "explorer.exe": {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe"},
    }
    risky_processes = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "schtasks.exe"}
    system_names = {"lsass.exe", "services.exe", "svchost.exe", "winlogon.exe", "csrss.exe"}
    user_writable_markers = ["\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\"]
    for process in normalized:
        parent = by_pid.get(process.get("parent_pid"), {})
        chain = lineage(process)
        item = {
            "pid": process.get("pid"),
            "name": process.get("display_name") or process.get("name"),
            "parent_pid": process.get("parent_pid"),
            "parent_name": parent.get("display_name") or parent.get("name"),
            "child_count": len(children.get(process.get("pid"), [])),
            "user": process.get("user"),
            "command_line": process.get("cmdline_text"),
            "lineage": chain,
        }
        tree.append(item)
        parent_name = str(parent.get("name") or "").lower()
        child_name = str(process.get("name") or "").lower()
        if child_name in suspicious.get(parent_name, set()):
            suspicious_chains.append(item)
            findings.append(_finding("Process Tree Viewer", "Suspicious parent-child process chain", "high", item, "Inspect document, browser, script and network evidence around this process chain."))
        if process.get("parent_pid") and process.get("parent_pid") not in by_pid:
            orphan_processes.append(item)
            if child_name in risky_processes:
                findings.append(_finding("Process Tree Viewer", "Risky process has missing parent", "medium", item, "Confirm whether parent telemetry rolled over or whether the process was injected/reparented."))
        path_text = str(process.get("executable_path") or "").lower()
        if child_name in system_names and any(marker in path_text for marker in user_writable_markers):
            findings.append(_finding("Process Tree Viewer", "System-like process running from user-writable path", "critical", item, "Treat as likely masquerading until file signature and path are verified."))
    findings.extend(_command_line_findings(normalized, module="Process Tree Viewer"))
    roots = [item for item in tree if not item.get("parent_pid") or item.get("parent_pid") not in by_pid]
    return _finish("process_tree_viewer", payload, {
        "tree": tree,
        "roots": roots,
        "process_count": len(normalized),
        "root_count": len(roots),
        "suspicious_chain_count": len(suspicious_chains),
        "orphan_processes": orphan_processes,
        "suspicious_chains": suspicious_chains,
    }, findings)


def _suspicious_command_line_analyser(payload: Dict[str, Any]) -> Dict[str, Any]:
    processes = _as_list(payload.get("processes") or payload.get("commands") or [])
    normalized = [{"cmdline_text": item} if isinstance(item, str) else item for item in processes]
    analysed = [_command_features(item) for item in normalized if isinstance(item, dict)]
    return _finish("suspicious_command_line_analyser", payload, {
        "analysed": analysed,
        "command_count": len(analysed),
        "suspicious_count": len([item for item in analysed if item["match_count"]]),
        "highest_risk_score": max((item["risk_score"] for item in analysed), default=0),
    }, _command_line_findings(normalized))


def _network_connection_monitor(payload: Dict[str, Any]) -> Dict[str, Any]:
    connections = _as_list(payload.get("connections") or [])
    findings: List[Dict[str, Any]] = []
    risky_procs = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
    for conn in connections:
        if not isinstance(conn, dict):
            continue
        proc = str(conn.get("process_name") or "").lower()
        remote = str(conn.get("remote_ip") or conn.get("remote_address") or conn.get("raddr") or "")
        if remote and proc in risky_procs:
            findings.append(_finding("Network Connection Monitor", "Script/system tool has network connection", "high", conn, "Review command line and destination reputation."))
    return _finish("network_connection_monitor", payload, {"connection_count": len(connections)}, findings)


def _persistence_scanner(payload: Dict[str, Any]) -> Dict[str, Any]:
    services = _as_list(payload.get("services") or [])
    tasks = _as_list(payload.get("scheduled_tasks") or payload.get("tasks") or [])
    startup = _as_list(payload.get("startup_items") or payload.get("startup") or [])
    autoruns = _as_list(payload.get("registry_autoruns") or payload.get("autoruns") or [])
    findings: List[Dict[str, Any]] = []
    user_writable = re.compile(r"(?i)(\\users\\[^\\]+\\appdata\\|\\temp\\|/tmp/|/users/[^/]+/)", re.I)

    def inspect_item(module_item: Any, command_keys: List[str], title: str) -> None:
        if not isinstance(module_item, dict):
            return
        command = " ".join(str(module_item.get(key) or "") for key in command_keys)
        if user_writable.search(command):
            findings.append(_finding("Persistence Scanner", f"{title} points to user-writable location", "high", module_item, "Validate owner, signature and creation time; disable only after evidence preservation."))
        for pattern_title, pattern, severity in COMMAND_PATTERNS:
            if pattern.search(command):
                findings.append(_finding("Persistence Scanner", f"Persistence command: {pattern_title}", severity, module_item, "Review this persistence entry for malicious execution."))

    for service in services:
        inspect_item(service, ["binpath", "PathName", "path", "command", "ImagePath"], "Service")
    for task in tasks:
        inspect_item(task, ["Actions", "Task To Run", "command", "arguments"], "Scheduled task")
    for item in startup:
        inspect_item(item, ["path", "command", "target"], "Startup item")
    for autorun in autoruns:
        inspect_item(autorun, ["value", "command", "path"], "Registry autorun")

    return _finish(
        "persistence_scanner",
        payload,
        {"service_count": len(services), "scheduled_task_count": len(tasks), "startup_item_count": len(startup), "registry_autorun_count": len(autoruns)},
        findings,
    )


DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
DNS_DOMAIN_RE = re.compile(r"(?i)^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
HIGH_VALUE_DOMAINS = {
    "microsoft.com",
    "office.com",
    "windows.com",
    "google.com",
    "gmail.com",
    "apple.com",
    "amazon.com",
    "cloudflare.com",
    "github.com",
}


def _normalize_domain(value: Any) -> str:
    domain = str(value or "").strip().lower()
    domain = re.sub(r"(?i)^https?://", "", domain).split("/", 1)[0].split(":", 1)[0].strip(".")
    return domain


def _valid_domain(domain: str, allow_wildcard: bool = False) -> bool:
    if not domain:
        return False
    if domain.startswith("*.") and not allow_wildcard:
        return False
    return bool(DNS_DOMAIN_RE.match(domain))


def _record_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        for key in ["values", "records", "answers", "ips"]:
            if key in value:
                return _record_list(value[key])
        return sorted(str(item).strip() for item in value.values() if str(item).strip())
    return sorted({str(item).strip().strip('"') for item in _as_list(value) if str(item).strip()})


def _baseline_records(baseline: Any, domain: str, record_type: str) -> List[str]:
    if not isinstance(baseline, dict):
        return []
    raw = baseline.get(domain) or baseline.get(domain.rstrip("."))
    if isinstance(raw, dict):
        return _record_list(raw.get(record_type) or raw.get(record_type.lower()))
    if record_type == "A":
        return _record_list(raw)
    return []


def _observed_records(observed: Any, domain: str, record_type: str) -> List[str] | None:
    if not isinstance(observed, dict):
        return None
    raw = observed.get(domain) or observed.get(domain.rstrip("."))
    if raw is None:
        return None
    if isinstance(raw, dict):
        return _record_list(raw.get(record_type) or raw.get(record_type.lower()))
    if record_type == "A":
        return _record_list(raw)
    return []


def _nslookup_records(domain: str, record_type: str) -> Dict[str, Any]:
    try:
        completed = subprocess.run(["nslookup", f"-type={record_type}", domain], capture_output=True, text=True, timeout=8, shell=False)
    except Exception as exc:
        return {"records": [], "error": type(exc).__name__, "detail": str(exc)}
    text = f"{completed.stdout}\n{completed.stderr}"
    if completed.returncode != 0 and not completed.stdout:
        return {"records": [], "error": "nslookup_failed", "detail": text.strip()[:500]}
    records: set[str] = set()
    for line in text.splitlines():
        clean = line.strip().strip('"')
        if not clean or clean.lower().startswith(("server:", "address:", "non-authoritative", "canonical name")):
            continue
        if record_type in {"A", "AAAA"}:
            for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[a-f0-9]{1,4}:){2,}[a-f0-9:]+\b", clean, flags=re.I):
                records.add(match)
        elif record_type == "MX":
            match = re.search(r"mail exchanger\s*=\s*(.+)$", clean, flags=re.I)
            if match:
                records.add(match.group(1).strip().rstrip("."))
        elif record_type == "NS":
            match = re.search(r"nameserver\s*=\s*(.+)$", clean, flags=re.I)
            if match:
                records.add(match.group(1).strip().rstrip("."))
        elif record_type == "TXT":
            if "text =" in clean.lower():
                records.add(clean.split("=", 1)[-1].strip().strip('"'))
        elif record_type == "CNAME":
            if "canonical name =" in clean.lower():
                records.add(clean.split("=", 1)[-1].strip().rstrip("."))
    return {"records": sorted(records)}


def _resolve_dns_records(domain: str, record_types: List[str], live: bool) -> Dict[str, Any]:
    records: Dict[str, Any] = {}
    for record_type in record_types:
        if not live:
            records[record_type] = []
            continue
        if record_type in {"A", "AAAA"}:
            family = socket.AF_INET if record_type == "A" else socket.AF_INET6
            try:
                records[record_type] = sorted({info[4][0] for info in socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)})
            except Exception as exc:
                records[record_type] = []
                records[f"{record_type}_error"] = type(exc).__name__
            continue
        lookup = _nslookup_records(domain, record_type)
        records[record_type] = lookup.get("records", [])
        if lookup.get("error"):
            records[f"{record_type}_error"] = lookup["error"]
    return records


def _is_private_dns_answer(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    except ValueError:
        return False


def _dns_monitor(payload: Dict[str, Any]) -> Dict[str, Any]:
    domains = [_normalize_domain(d) for d in _as_list(payload.get("domains") or payload.get("domain") or []) if str(d).strip()]
    baseline = payload.get("baseline") or {}
    observed = payload.get("observed_records") or payload.get("observations") or {}
    record_types = [str(item).upper() for item in _as_list(payload.get("record_types") or ["A", "AAAA", "MX", "NS", "CNAME"]) if str(item).upper() in DNS_RECORD_TYPES]
    live = bool(payload.get("resolve_live", not bool(observed)))
    expect_mx = bool(payload.get("expect_mx", False))
    records: Dict[str, Any] = {}
    findings: List[Dict[str, Any]] = []
    for domain in domains:
        if not _valid_domain(domain):
            records[domain] = {"valid": False, "records": {}}
            findings.append(_finding("DNS Monitor", "Invalid domain supplied", "medium", {"domain": domain}, "Correct the domain before monitoring it."))
            continue
        resolved = _resolve_dns_records(domain, record_types, live)
        for record_type in record_types:
            supplied = _observed_records(observed, domain, record_type)
            if supplied is not None:
                resolved[record_type] = supplied
        answers = {record_type: _record_list(resolved.get(record_type)) for record_type in record_types}
        records[domain] = {"valid": True, "live_resolution": live, "records": answers, "errors": {key: value for key, value in resolved.items() if key.endswith("_error")}}
        if not answers.get("A") and not answers.get("AAAA"):
            findings.append(_finding("DNS Monitor", "Domain did not resolve", "medium", {"domain": domain, "records": answers}, "Confirm whether the domain should resolve and inspect DNS policy."))
        if expect_mx and not answers.get("MX"):
            findings.append(_finding("DNS Monitor", "Expected mail domain has no MX records", "medium", {"domain": domain, "records": answers}, "Confirm mail routing and DNS configuration for this domain."))
        if "NS" in record_types and answers.get("NS") and len(answers["NS"]) < 2:
            findings.append(_finding("DNS Monitor", "Domain has fewer than two name servers", "low", {"domain": domain, "ns_records": answers["NS"]}, "Use at least two authoritative name servers for resilience."))
        for answer in answers.get("A", []) + answers.get("AAAA", []):
            if _is_private_dns_answer(answer):
                findings.append(_finding("DNS Monitor", "DNS answer points to private or reserved IP", "high", {"domain": domain, "answer": answer}, "Confirm whether this is intentional split-horizon DNS or a sinkhole."))
        for record_type in record_types:
            expected = _baseline_records(baseline, domain, record_type)
            if not expected:
                continue
            actual = answers.get(record_type, [])
            added = sorted(set(actual) - set(expected))
            removed = sorted(set(expected) - set(actual))
            if added or removed:
                findings.append(_finding("DNS Monitor", "DNS answer changed from baseline", "medium", {"domain": domain, "record_type": record_type, "expected": expected, "actual": actual, "added": added, "removed": removed}, "Review for DNS hijack, sinkhole, or infrastructure migration."))
    return _finish("dns_monitor", payload, {"records": records, "record_types": record_types, "live_resolution": live, "domain_count": len(domains)}, findings)


def _dns_protection_tool(payload: Dict[str, Any]) -> Dict[str, Any]:
    blocked = sorted({_normalize_domain(d) for d in _as_list(payload.get("blocked_domains") or payload.get("domains") or []) if str(d).strip()})
    allowed = sorted({_normalize_domain(d) for d in _as_list(payload.get("allowed_domains") or []) if str(d).strip()})
    sinkhole = str(payload.get("sinkhole_ip", "0.0.0.0")).strip()
    findings = []
    try:
        ipaddress.ip_address(sinkhole)
    except ValueError:
        sinkhole = "0.0.0.0"
        findings.append(_finding("DNS Protection Tool", "Invalid sinkhole IP supplied", "medium", {"sinkhole_ip": payload.get("sinkhole_ip")}, "Use a valid IPv4 or IPv6 sinkhole address."))
    invalid = [domain for domain in blocked + allowed if not _valid_domain(domain, allow_wildcard=True)]
    for domain in invalid:
        findings.append(_finding("DNS Protection Tool", "Invalid domain in DNS policy", "medium", {"domain": domain}, "Remove or correct invalid DNS policy entries before deployment."))
    blocked = [domain for domain in blocked if domain not in invalid]
    allowed = [domain for domain in allowed if domain not in invalid]
    allowed_roots = {domain.removeprefix("*.") for domain in allowed}
    effective = []
    conflicts = []
    for domain in blocked:
        root = domain.removeprefix("*.")
        if domain in allowed or root in allowed_roots:
            conflicts.append(domain)
            continue
        effective.append(domain)
    high_value = [domain for domain in effective if domain.removeprefix("*.") in HIGH_VALUE_DOMAINS]
    for domain in conflicts:
        findings.append(_finding("DNS Protection Tool", "DNS block conflicts with allowlist", "high", {"domain": domain, "allowed_domains": allowed}, "Resolve allow/block conflicts before publishing policy."))
    for domain in high_value:
        findings.append(_finding("DNS Protection Tool", "High-value domain block requested", "high", {"domain": domain}, "Require explicit approval before blocking widely used business domains."))
    if any(domain.startswith("*.") for domain in effective):
        findings.append(_finding("DNS Protection Tool", "Wildcard DNS block requested", "low", {"blocked_domains": effective}, "Validate wildcard scope to avoid business disruption."))
    hosts_domains = [domain for domain in effective if not domain.startswith("*.")]
    rpz_zone = []
    dnsmasq_rules = []
    for domain in effective:
        rpz_name = domain[2:] if domain.startswith("*.") else domain
        wildcard_prefix = "*." if domain.startswith("*.") else ""
        rpz_zone.append(f"{wildcard_prefix}{rpz_name} CNAME .")
        dnsmasq_rules.append(f"address=/{rpz_name}/{sinkhole}")
    policy = {
        "blocked_domains": effective,
        "allowed_domains": allowed,
        "conflicts": conflicts,
        "invalid_domains": invalid,
        "hosts_file_entries": [f"{sinkhole} {domain}" for domain in hosts_domains],
        "rpz_zone_records": rpz_zone,
        "dnsmasq_rules": dnsmasq_rules,
        "pihole_gravity_list": hosts_domains,
        "plain_blocklist": "\n".join(effective),
        "plain_allowlist": "\n".join(allowed),
        "dns_sinkhole": sinkhole,
        "deployment_plan": [
            "Review conflicts, wildcard entries, and high-value domains.",
            "Publish the generated policy to DNS filtering infrastructure.",
            "Flush resolver caches or wait for TTL expiry.",
            "Run DNS Monitor against blocked and allowed domains to verify behaviour.",
        ],
        "rollback_plan": [
            "Remove generated block entries from DNS filtering infrastructure.",
            "Restore the previous policy version from change control.",
            "Flush resolver caches or wait for TTL expiry.",
            "Verify affected domains resolve to expected baseline records.",
        ],
    }
    policy["policy_sha256"] = hashlib.sha256(_canonical_bytes(policy)).hexdigest()
    return _finish("dns_protection_tool", payload, policy, findings)


def _collect_wevtutil(channel: str, limit: int) -> List[Dict[str, Any]]:
    try:
        completed = subprocess.run(["wevtutil", "qe", channel, f"/c:{limit}", "/rd:true", "/f:text"], capture_output=True, text=True, timeout=10, shell=False)
        if completed.returncode != 0:
            return []
        return [{"channel": channel, "raw": block.strip()} for block in completed.stdout.split("\n\n") if block.strip()]
    except Exception:
        return []


def _parse_raw_event(raw: str) -> Dict[str, Any]:
    event: Dict[str, Any] = {"raw": raw}
    patterns = {
        "ProviderName": r"(?im)^\s*Provider Name:\s*(.+)$",
        "Id": r"(?im)^\s*Event ID:\s*(\d+)",
        "Level": r"(?im)^\s*Level:\s*(.+)$",
        "TimeCreated": r"(?im)^\s*Date:\s*(.+)$",
        "Computer": r"(?im)^\s*Computer:\s*(.+)$",
        "User": r"(?im)^\s*User:\s*(.+)$",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, raw or "")
        if match:
            event[key] = match.group(1).strip()
    event["Message"] = raw
    return event


def _normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    if event.get("raw") and not any(key in event for key in ["Id", "EventID", "event_id", "Message"]):
        event = {**event, **_parse_raw_event(str(event.get("raw") or ""))}
    event_id = str(event.get("Id") or event.get("EventID") or event.get("event_id") or "").strip()
    channel = str(event.get("channel") or event.get("Channel") or event.get("LogName") or event.get("log_name") or "")
    provider = str(event.get("ProviderName") or event.get("provider") or event.get("Source") or "")
    message = _text(event.get("Message") or event.get("message") or event.get("ScriptBlockText") or event.get("raw") or event)
    user = str(event.get("TargetUserName") or event.get("SubjectUserName") or event.get("User") or event.get("user") or "")
    return {
        **event,
        "event_id": event_id,
        "channel": channel,
        "provider": provider,
        "time": event.get("TimeCreated") or event.get("time") or event.get("timestamp") or event.get("created_at"),
        "computer": event.get("Computer") or event.get("computer") or event.get("hostname"),
        "user": user,
        "message": message,
        "summary": _short_text(message, 260),
    }


def _event_counts(events: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for event in events:
        value = str(event.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: item[0]))


def _windows_event_log_collector(payload: Dict[str, Any]) -> Dict[str, Any]:
    channels = _as_list(payload.get("channels") or ["System", "Security", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Windows Defender/Operational"])
    limit = int(payload.get("limit", 25))
    supplied = payload.get("events")
    events: List[Dict[str, Any]] = []
    if supplied is not None:
        events = [e for e in _as_list(supplied) if isinstance(e, dict)]
    elif payload.get("collect_local", False):
        for channel in channels:
            events.extend(_collect_wevtutil(str(channel), limit))
    normalized = [_normalize_event(event) for event in events]
    findings = _event_log_findings(normalized, failure_threshold=int(payload.get("failure_threshold", 5)))
    timeline = [
        {
            "time": event.get("time"),
            "channel": event.get("channel"),
            "event_id": event.get("event_id"),
            "provider": event.get("provider"),
            "summary": event.get("summary"),
            "user": event.get("user"),
            "computer": event.get("computer"),
        }
        for event in normalized
    ]
    timeline.sort(key=lambda item: (bool(item.get("time_inferred")), str(item.get("time") or "9999-12-31T23:59:59Z")))
    return _finish("windows_event_log_collector", payload, {
        "channels": channels,
        "events": normalized,
        "event_count": len(normalized),
        "event_counts_by_id": _event_counts(normalized, "event_id"),
        "event_counts_by_channel": _event_counts(normalized, "channel"),
        "timeline": timeline,
        "collection_mode": "supplied" if supplied is not None else "local" if payload.get("collect_local", False) else "none",
    }, findings)


def _event_log_findings(events: List[Dict[str, Any]], failure_threshold: int = 5) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    high_value = {
        "1102": ("Audit log cleared", "critical"),
        "4625": ("Failed logon observed", "medium"),
        "4672": ("Special privileges assigned", "medium"),
        "4720": ("User account created", "high"),
        "4722": ("User account enabled", "medium"),
        "4724": ("Password reset attempted", "medium"),
        "4726": ("User account deleted", "high"),
        "4728": ("User added to privileged group", "critical"),
        "4732": ("User added to local privileged group", "critical"),
        "4738": ("User account changed", "medium"),
        "4698": ("Scheduled task event", "high"),
        "4702": ("Scheduled task event", "medium"),
        "7045": ("Service installed", "high"),
        "1116": ("Defender malware detection", "high"),
        "5007": ("Defender configuration changed", "high"),
    }
    failures: Dict[str, int] = {}
    for event in events:
        eid = str(event.get("event_id") or event.get("Id") or event.get("EventID") or "")
        message = _text(event.get("message") or event.get("Message") or event.get("raw") or event)
        user = str(event.get("user") or event.get("TargetUserName") or "unknown")
        if eid in high_value:
            title, severity = high_value[eid]
            findings.append(_finding("Windows Event Log Collector", title, severity, event, "Correlate with user, host and process telemetry."))
        if eid == "4625" or "failed logon" in message.lower():
            failures[user] = failures.get(user, 0) + 1
        for title, pattern, severity in COMMAND_PATTERNS:
            if pattern.search(message):
                findings.append(_finding("Windows Event Log Collector", title, severity, event, "Review command execution telemetry and isolate if malicious."))
    for user, count in failures.items():
        if count >= failure_threshold:
            findings.append(_finding("Windows Event Log Collector", "Repeated failed logons", "high", {"user": user, "count": count}, "Investigate password spray, brute force or stale credential use."))
    return findings


POWERSHELL_SCRIPT_PATTERNS = [
    ("PowerShell script block contains suspicious behaviour", re.compile(r"(?i)(invoke-expression|\biex\b|downloadstring|downloadfile|frombase64string|reflection\.assembly|amsiutils|amsiinitfailed|set-mppreference|add-mppreference|webclient|start-bitstransfer|new-object\s+net\.webclient)"), "high"),
]


def _decode_powershell_encoded(command: str) -> str | None:
    match = re.search(r"(?i)(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]+)", command or "")
    if not match:
        return None
    token = match.group(1)
    try:
        decoded = base64.b64decode(token + "=" * (-len(token) % 4))
    except Exception:
        return None
    for encoding in ["utf-16le", "utf-8"]:
        try:
            text = decoded.decode(encoding, errors="strict").strip("\x00\r\n ")
            if text:
                return text
        except Exception:
            continue
    return None


def _powershell_activity_analyser(payload: Dict[str, Any]) -> Dict[str, Any]:
    events = [e for e in _as_list(payload.get("events") or payload.get("powershell_events") or []) if isinstance(e, dict)]
    processes = [p for p in _as_list(payload.get("processes") or []) if isinstance(p, dict)]
    findings = _command_line_findings(processes, module="PowerShell Activity Analyser")
    normalized_events = [_normalize_event(event) for event in events]
    script_blocks = []
    decoded_commands = []
    process_features = [_command_features(process) for process in processes]
    for process in processes:
        command = _text(process.get("cmdline_text") or process.get("cmdline") or process.get("command") or "")
        decoded = _decode_powershell_encoded(command)
        if decoded:
            decoded_commands.append({"source": "process", "process": process.get("name"), "decoded": decoded, "original": command})
            findings.append(_finding("PowerShell Activity Analyser", "PowerShell encoded command decoded", "medium", {"command": command, "decoded": decoded}, "Review the decoded command and correlate with parent process, user and network evidence."))
    for event in normalized_events:
        message = _text(event.get("Message") or event.get("ScriptBlockText") or event.get("message") or event)
        script_text = str(event.get("ScriptBlockText") or event.get("script_block") or message)
        if str(event.get("event_id") or event.get("Id") or "") in {"4103", "4104"} or "scriptblock" in message.lower():
            script_blocks.append({"event_id": event.get("event_id"), "time": event.get("time"), "user": event.get("user"), "script": _short_text(script_text, 800)})
        decoded = _decode_powershell_encoded(message)
        if decoded:
            decoded_commands.append({"source": "event", "event_id": event.get("event_id"), "decoded": decoded, "original": _short_text(message, 400)})
            findings.append(_finding("PowerShell Activity Analyser", "PowerShell encoded command decoded", "medium", {"event": event, "decoded": decoded}, "Review the decoded command and correlate with parent process, user and network evidence."))
        for title, pattern, severity in COMMAND_PATTERNS:
            if pattern.search(message):
                findings.append(_finding("PowerShell Activity Analyser", title, severity, event, "Review script block content and originating user/process."))
        for title, pattern, severity in POWERSHELL_SCRIPT_PATTERNS:
            if pattern.search(script_text):
                findings.append(_finding("PowerShell Activity Analyser", title, severity, event, "Inspect the full script block, decoded content, parent process and network indicators."))
    timeline = [
        {"time": event.get("time") or _now(), "event_id": event.get("event_id"), "summary": event.get("summary"), "user": event.get("user")}
        for event in normalized_events
    ]
    timeline.sort(key=lambda item: str(item.get("time") or ""))
    return _finish("powershell_activity_analyser", payload, {
        "event_count": len(normalized_events),
        "process_count": len(processes),
        "events": normalized_events,
        "processes": process_features,
        "script_blocks": script_blocks,
        "decoded_commands": decoded_commands,
        "event_counts_by_id": _event_counts(normalized_events, "event_id"),
        "timeline": timeline,
    }, findings)


def _timeline_phase(item: Dict[str, Any]) -> str:
    text = _text(item).lower()
    if any(token in text for token in ["phishing", "attachment", "url", "email"]):
        return "Initial Access"
    if any(token in text for token in ["powershell", "cmd.exe", "script", "encodedcommand", "process"]):
        return "Execution"
    if any(token in text for token in ["scheduled task", "autorun", "service installed", "service was installed", "run key", "persistence"]):
        return "Persistence"
    if any(token in text for token in ["defender", "firewall", "audit log cleared", "obfuscated", "masquerading"]):
        return "Defense Evasion"
    if any(token in text for token in ["credential", "failed logon", "password", "lsass"]):
        return "Credential Access"
    if any(token in text for token in ["network", "connection", "dns", "http", "tls"]):
        return "Command and Control"
    if any(token in text for token in ["ransom", "shadow", "recovery", "encrypted", "impact"]):
        return "Impact"
    return "Investigation"


def _timeline_entity(item: Dict[str, Any]) -> str:
    for key in ["hostname", "host", "computer", "Computer", "user", "TargetUserName", "process_name", "name", "domain", "source_ip", "remote_address"]:
        value = item.get(key)
        if value:
            return str(value)
    evidence = item.get("evidence")
    if isinstance(evidence, dict):
        return _timeline_entity(evidence)
    return "global"


def _timeline_time(item: Dict[str, Any]) -> tuple[str, bool]:
    value = item.get("created_at") or item.get("time") or item.get("TimeCreated") or item.get("timestamp") or item.get("generated_at") or item.get("date")
    if value:
        return str(value), False
    return _now(), True


def _timeline_item(raw: Dict[str, Any], source_type: str, index: int) -> Dict[str, Any]:
    timestamp, inferred = _timeline_time(raw)
    event_text = raw.get("title") or raw.get("event") or raw.get("Message") or raw.get("summary") or raw.get("name") or f"{source_type} item {index + 1}"
    severity = str(raw.get("severity") or raw.get("highest_severity") or raw.get("risk_band") or "informational").lower()
    return {
        "time": timestamp,
        "time_inferred": inferred,
        "source": raw.get("module") or raw.get("source") or raw.get("ProviderName") or source_type,
        "source_type": source_type,
        "event": _short_text(event_text, 260),
        "severity": severity,
        "phase": _timeline_phase(raw),
        "entity": _timeline_entity(raw),
        "evidence_ref": raw.get("finding_id") or raw.get("event_id") or raw.get("id") or f"{source_type}-{index + 1}",
        "plain_english": raw.get("plain_english"),
        "raw": raw,
    }


def _timeline_builder(payload: Dict[str, Any]) -> Dict[str, Any]:
    source_keys = ["findings", "events", "alerts", "processes", "connections", "dns_records", "powershell_events"]
    timeline: List[Dict[str, Any]] = []
    for source_key in source_keys:
        for index, item in enumerate(_as_list(payload.get(source_key) or [])):
            if isinstance(item, dict):
                timeline.append(_timeline_item(item, source_key, index))
    if not timeline and isinstance(payload.get("items"), list):
        for index, item in enumerate(_as_list(payload.get("items"))):
            if isinstance(item, dict):
                timeline.append(_timeline_item(item, "items", index))
    timeline.sort(key=lambda item: str(item.get("time") or "9999-12-31T23:59:59Z"))
    severity_counts: Dict[str, int] = {}
    phase_counts: Dict[str, int] = {}
    entity_index: Dict[str, List[str]] = {}
    findings: List[Dict[str, Any]] = []
    for item in timeline:
        severity_counts[item["severity"]] = severity_counts.get(item["severity"], 0) + 1
        phase_counts[item["phase"]] = phase_counts.get(item["phase"], 0) + 1
        entity_index.setdefault(item["entity"], []).append(item["evidence_ref"])
        if item["time_inferred"]:
            findings.append(_finding("Timeline Builder", "Timeline item missing timestamp", "low", item, "Add original event timestamps so the chronology can be trusted."))
    high_risk = [item for item in timeline if item["severity"] in {"critical", "high"}]
    if len(high_risk) >= int(payload.get("cluster_threshold", 3)):
        findings.append(_finding("Timeline Builder", "High-risk activity cluster in timeline", "high", {"count": len(high_risk), "items": high_risk[:10]}, "Review these high-risk timeline items together as a possible incident chain."))
    observed_times = [item["time"] for item in timeline if not item.get("time_inferred")]
    return _finish("timeline_builder", payload, {
        "timeline": timeline,
        "item_count": len(timeline),
        "first_seen": observed_times[0] if observed_times else timeline[0]["time"] if timeline else None,
        "last_seen": observed_times[-1] if observed_times else timeline[-1]["time"] if timeline else None,
        "severity_counts": severity_counts,
        "phase_counts": phase_counts,
        "entity_index": entity_index,
        "high_risk_count": len(high_risk),
    }, findings)


def _evidence_bundle_exporter(payload: Dict[str, Any]) -> Dict[str, Any]:
    artifacts = _as_list(payload.get("artifacts") or payload.get("files") or [])
    manifest = {"created_at": _now(), "artifact_count": len(artifacts), "artifacts": []}
    for artifact in artifacts:
        content = _text(artifact)
        manifest["artifacts"].append({"name": artifact.get("name") if isinstance(artifact, dict) else None, "sha256": hashlib.sha256(content.encode()).hexdigest(), "size_bytes": len(content.encode())})
    manifest["manifest_sha256"] = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    return _finish("evidence_bundle_exporter", payload, {"manifest": manifest}, [])


def _incident_report_generator(payload: Dict[str, Any]) -> Dict[str, Any]:
    title = str(payload.get("title") or "Sentinel Incident Report")
    findings = _as_list(payload.get("findings") or [])
    summary = str(payload.get("summary") or f"{len(findings)} finding(s) included.")
    lines = [f"# {title}", "", f"Generated: {_now()}", "", "## Summary", summary, "", "## Findings"]
    for finding in findings:
        if isinstance(finding, dict):
            lines.append(f"- [{finding.get('severity', 'informational')}] {finding.get('title', 'Untitled')} - {finding.get('recommended_action', '')}")
    markdown = "\n".join(lines)
    html = "<html><body>" + markdown.replace("&", "&amp;").replace("<", "&lt;").replace("\n", "<br>") + "</body></html>"
    return _finish("incident_report_generator", payload, {"markdown": markdown, "html": html}, [])


def _ransomware_behaviour_guard(payload: Dict[str, Any]) -> Dict[str, Any]:
    events = _as_list(payload.get("events") or [])
    findings: List[Dict[str, Any]] = []
    modified_paths = [str(e.get("path") or "") for e in events if isinstance(e, dict) and str(e.get("action", "")).lower() in {"write", "modify", "rename", "delete"}]
    ransom_ext = [path for path in modified_paths if Path(path).suffix.lower() in {".locked", ".encrypted", ".crypt", ".ryk", ".lockbit"}]
    commands = " ".join(_text(e) for e in events)
    if len(set(modified_paths)) >= int(payload.get("mass_change_threshold", 100)):
        findings.append(_finding("Ransomware Behaviour Guard", "Mass file modification pattern", "critical", {"count": len(set(modified_paths))}, "Contain the endpoint and preserve volatile process/network evidence."))
    if ransom_ext:
        findings.append(_finding("Ransomware Behaviour Guard", "Ransomware-style file extensions observed", "critical", {"paths": ransom_ext[:50]}, "Isolate affected host and verify backup integrity before recovery."))
    if re.search(r"(?i)(vssadmin|wmic).*shadow.*delete|bcdedit.*recoveryenabled\s+no", commands):
        findings.append(_finding("Ransomware Behaviour Guard", "Recovery tampering command observed", "critical", {"commands": commands[:2000]}, "Treat as active ransomware or destructive staging."))
    return _finish("ransomware_behaviour_guard", payload, {"event_count": len(events), "modified_path_count": len(set(modified_paths))}, findings)


def _backup_readiness_checker(payload: Dict[str, Any]) -> Dict[str, Any]:
    checks = {
        "recent_backup": bool(payload.get("last_backup_at")),
        "restore_tested": bool(payload.get("restore_tested_at")),
        "offline_or_immutable": bool(payload.get("offline_backup") or payload.get("immutable_backup")),
        "critical_paths_covered": bool(payload.get("protected_paths")),
        "documented_rpo": payload.get("rpo_hours") is not None,
    }
    findings = [_finding("Backup Readiness Checker", f"Backup control missing: {key}", "high" if key in {"recent_backup", "offline_or_immutable"} else "medium", {"control": key}, "Close this backup readiness gap before relying on recovery.") for key, passed in checks.items() if not passed]
    score = max(0, 100 - len(findings) * 20)
    return _finish("backup_readiness_checker", payload, {"checks": checks, "score": score}, findings)


def _windows_security_baseline_checker(payload: Dict[str, Any]) -> Dict[str, Any]:
    expected = {
        "defender_enabled": True,
        "defender_realtime_enabled": True,
        "firewall_enabled": True,
        "bitlocker_enabled": True,
        "secure_boot_enabled": True,
        "windows_update_enabled": True,
        "powershell_logging_enabled": True,
        "audit_policy_enabled": True,
        "rdp_enabled": False,
        "smb_v1_enabled": False,
    }
    controls = payload.get("controls") or payload
    findings = []
    for key, value in expected.items():
        if key in controls and controls.get(key) != value:
            findings.append(_finding("Windows Security Baseline Checker", f"Baseline drift: {key}", "high" if key in {"defender_enabled", "firewall_enabled"} else "medium", {"control": key, "expected": value, "actual": controls.get(key)}, "Align this endpoint to the Sentinel Windows baseline."))
    return _finish("windows_security_baseline_checker", payload, {"expected": expected}, findings)


def _patch_status_checker(payload: Dict[str, Any]) -> Dict[str, Any]:
    missing = _as_list(payload.get("missing_updates") or payload.get("missing_kbs") or [])
    last_update = _parse_time(payload.get("last_update_at"))
    findings = []
    if missing:
        findings.append(_finding("Patch Status Checker", "Missing security updates", "high", {"missing": missing}, "Apply missing security updates or document accepted exceptions."))
    if last_update:
        age_days = (datetime.now(timezone.utc) - last_update.astimezone(timezone.utc)).days
        if age_days > int(payload.get("max_patch_age_days", 35)):
            findings.append(_finding("Patch Status Checker", "Endpoint patch age exceeds policy", "medium", {"age_days": age_days}, "Bring endpoint back into patch compliance."))
    elif payload.get("require_last_update", True):
        findings.append(_finding("Patch Status Checker", "Last update timestamp missing", "medium", {}, "Collect patch inventory from the endpoint."))
    return _finish("patch_status_checker", payload, {"missing_count": len(missing)}, findings)


def _installed_software_inventory(payload: Dict[str, Any]) -> Dict[str, Any]:
    software = _as_list(payload.get("software") or payload.get("inventory") or [])
    normalized = []
    findings = []
    for item in software:
        if not isinstance(item, dict):
            item = {"name": str(item)}
        name = str(item.get("name") or item.get("DisplayName") or "")
        version = str(item.get("version") or item.get("DisplayVersion") or "")
        normalized.append({"name": name, "version": version, "publisher": item.get("publisher") or item.get("Publisher")})
        if re.search(r"(?i)\b(java 6|java 7|flash|silverlight|internet explorer)\b", name):
            findings.append(_finding("Installed Software Inventory", "Legacy or risky software installed", "medium", {"name": name, "version": version}, "Remove unsupported software or isolate until upgraded."))
    return _finish("installed_software_inventory", payload, {"software": normalized, "count": len(normalized)}, findings)


def _cve_kev_vulnerability_matcher(payload: Dict[str, Any]) -> Dict[str, Any]:
    software = _as_list(payload.get("software") or [])
    vulns = _as_list(payload.get("vulnerabilities") or payload.get("cves") or [])
    matches = []
    findings = []
    for sw in software:
        sw_text = _text(sw).lower()
        for vuln in vulns:
            vuln_text = _text(vuln).lower()
            product = str(vuln.get("product", "") if isinstance(vuln, dict) else "").lower()
            if product and product in sw_text or any(token and token in sw_text and token in vuln_text for token in str(sw.get("name", "") if isinstance(sw, dict) else sw).lower().split()):
                match = {"software": sw, "vulnerability": vuln, "kev": bool(isinstance(vuln, dict) and vuln.get("kev"))}
                matches.append(match)
                findings.append(_finding("CVE / KEV Vulnerability Matcher", "Known exploited vulnerability match" if match["kev"] else "Vulnerability match", "critical" if match["kev"] else "high", match, "Prioritise remediation based on exploit status and exposure."))
    return _finish("cve_kev_vulnerability_matcher", payload, {"matches": matches}, findings)


def _browser_security_checker(payload: Dict[str, Any]) -> Dict[str, Any]:
    browsers = _as_list(payload.get("browsers") or [])
    findings = []
    for browser in browsers:
        if not isinstance(browser, dict):
            continue
        if browser.get("password_manager_enabled", False):
            findings.append(_finding("Browser Security Checker", "Browser password manager enabled", "medium", browser, "Use managed password vault policy and disable unmanaged browser storage if required."))
        if not browser.get("safe_browsing_enabled", True):
            findings.append(_finding("Browser Security Checker", "Safe browsing disabled", "high", browser, "Enable browser safe browsing or equivalent phishing/malware protection."))
        for ext in _as_list(browser.get("extensions") or []):
            if isinstance(ext, dict) and ext.get("permissions") and any(p in ext.get("permissions", []) for p in ["webRequest", "cookies", "tabs", "nativeMessaging"]):
                findings.append(_finding("Browser Security Checker", "High-permission browser extension", "medium", ext, "Review extension publisher, permissions and business need."))
    return _finish("browser_security_checker", payload, {"browser_count": len(browsers)}, findings)


def _usb_guard(payload: Dict[str, Any]) -> Dict[str, Any]:
    devices = _as_list(payload.get("devices") or [])
    approved = set(str(x).lower() for x in _as_list(payload.get("approved_serials") or []))
    findings = []
    for device in devices:
        if not isinstance(device, dict):
            continue
        serial = str(device.get("serial") or device.get("serial_number") or "").lower()
        if serial and approved and serial not in approved:
            findings.append(_finding("USB Guard", "Unapproved USB device", "high", device, "Block or investigate removable media not on the approved list."))
        if device.get("writable", False) and payload.get("read_only_required", False):
            findings.append(_finding("USB Guard", "Writable USB device violates policy", "medium", device, "Apply read-only removable storage policy."))
    return _finish("usb_guard", payload, {"device_count": len(devices)}, findings)


def _firewall_rule_auditor(payload: Dict[str, Any]) -> Dict[str, Any]:
    rules = _as_list(payload.get("rules") or [])
    findings = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        direction = str(rule.get("direction") or rule.get("Direction") or "").lower()
        action = str(rule.get("action") or rule.get("Action") or "").lower()
        remote = str(rule.get("remote_address") or rule.get("RemoteAddress") or "").lower()
        profile = str(rule.get("profile") or rule.get("Profile") or "").lower()
        if direction == "inbound" and action == "allow" and remote in {"any", "*", "0.0.0.0/0", ""}:
            findings.append(_finding("Firewall Rule Auditor", "Broad inbound allow firewall rule", "high", rule, "Restrict source, profile and ports for inbound rules."))
        if "public" in profile and action == "allow" and direction == "inbound":
            findings.append(_finding("Firewall Rule Auditor", "Inbound public profile allow rule", "medium", rule, "Confirm public profile exposure is required."))
    return _finish("firewall_rule_auditor", payload, {"rule_count": len(rules)}, findings)


def _local_account_admin_audit(payload: Dict[str, Any]) -> Dict[str, Any]:
    users = _as_list(payload.get("users") or [])
    admins = _as_list(payload.get("administrators") or payload.get("admins") or [])
    allowed = set(str(x).lower() for x in _as_list(payload.get("allowed_admins") or []))
    findings = []
    if len(admins) > int(payload.get("max_admins", 2)):
        findings.append(_finding("Local Account/Admin Audit", "Excessive local administrators", "medium", {"administrators": admins}, "Remove unnecessary local administrator membership."))
    for admin in admins:
        name = str(admin.get("name") if isinstance(admin, dict) else admin).lower()
        if allowed and name not in allowed:
            findings.append(_finding("Local Account/Admin Audit", "Unexpected local administrator", "high", {"admin": admin}, "Validate and remove unexpected privileged account."))
    for user in users:
        if isinstance(user, dict) and user.get("enabled", True) and user.get("password_never_expires", False):
            findings.append(_finding("Local Account/Admin Audit", "Password never expires on local account", "medium", user, "Review password policy and disable stale local accounts."))
    return _finish("local_account_admin_audit", payload, {"user_count": len(users), "admin_count": len(admins)}, findings)


def _logon_event_analyser(payload: Dict[str, Any]) -> Dict[str, Any]:
    events = _as_list(payload.get("events") or [])
    failures: Dict[str, int] = {}
    findings = []
    for event in events:
        if not isinstance(event, dict):
            continue
        eid = str(event.get("Id") or event.get("event_id") or "")
        user = str(event.get("TargetUserName") or event.get("user") or "unknown")
        if eid == "4625" or "failed logon" in _text(event).lower():
            failures[user] = failures.get(user, 0) + 1
        if eid == "4624" and str(event.get("LogonType") or event.get("logon_type")) in {"10", "3"}:
            findings.append(_finding("Logon Event Analyser", "Remote/network logon observed", "low", event, "Correlate remote logon with expected access."))
    for user, count in failures.items():
        if count >= int(payload.get("failure_threshold", 5)):
            findings.append(_finding("Logon Event Analyser", "Repeated failed logons", "high", {"user": user, "count": count}, "Investigate password spray, brute force or stale credential use."))
    return _finish("logon_event_analyser", payload, {"failure_counts": failures}, findings)


def _privilege_change_monitor(payload: Dict[str, Any]) -> Dict[str, Any]:
    events = _as_list(payload.get("events") or [])
    privileged_ids = {"4670", "4672", "4728", "4732", "4756", "4738"}
    findings = []
    for event in events:
        if isinstance(event, dict) and str(event.get("Id") or event.get("event_id") or "") in privileged_ids:
            findings.append(_finding("Privilege Change Monitor", "Privilege or group membership change", "high", event, "Validate requester, ticket and affected account."))
    return _finish("privilege_change_monitor", payload, {"event_count": len(events)}, findings)


def _mailbox_rule_checker(payload: Dict[str, Any]) -> Dict[str, Any]:
    rules = _as_list(payload.get("rules") or [])
    org_domains = {str(x).lower() for x in _as_list(payload.get("org_domains") or [])}
    findings = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        target = str(rule.get("forward_to") or rule.get("redirect_to") or rule.get("ForwardTo") or "").lower()
        action_text = _text(rule).lower()
        external = target and org_domains and not any(target.endswith("@" + d) or target.endswith(d) for d in org_domains)
        if external or any(token in action_text for token in ["forward", "redirect", "delete", "markasread", "hide"]):
            findings.append(_finding("Mailbox Rule Checker", "Suspicious mailbox rule behaviour", "high" if external else "medium", rule, "Confirm the mailbox owner created this rule and remove if unauthorised."))
    return _finish("mailbox_rule_checker", payload, {"rule_count": len(rules)}, findings)


def _is_private_url(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return True
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return True
    except Exception:
        return False
    return False


def _target_host(target: str) -> str | None:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return parsed.hostname or target.split(":")[0]


def _is_private_host(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return True
    except Exception:
        return False
    return False


def _http_probe(url: str) -> Dict[str, Any]:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    probe_url = url if "://" in url else f"https://{url}"
    try:
        response = requests.get(probe_url, timeout=8, allow_redirects=False)
        return {
            "url": probe_url,
            "scheme": parsed.scheme or "https",
            "status_code": response.status_code,
            "server": response.headers.get("server"),
            "content_type": response.headers.get("content-type"),
            "location": response.headers.get("location"),
            "security_headers": {
                "strict_transport_security": response.headers.get("strict-transport-security"),
                "content_security_policy": response.headers.get("content-security-policy"),
                "x_frame_options": response.headers.get("x-frame-options"),
                "x_content_type_options": response.headers.get("x-content-type-options"),
                "referrer_policy": response.headers.get("referrer-policy"),
            },
        }
    except Exception as exc:
        return {"url": probe_url, "error": type(exc).__name__, "detail": str(exc)}


def _tls_probe(host: str, port: int = 443) -> Dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as wrapped:
                cert = wrapped.getpeercert()
        not_after = cert.get("notAfter")
        expires_at = None
        days_remaining = None
        if not_after:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            expires_at = expires.isoformat()
            days_remaining = (expires - datetime.now(timezone.utc)).days
        return {
            "host": host,
            "port": port,
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "expires_at": expires_at,
            "days_remaining": days_remaining,
            "subject_alt_names": cert.get("subjectAltName", []),
        }
    except Exception as exc:
        return {"host": host, "port": port, "error": type(exc).__name__, "detail": str(exc)}


def _port_probe(host: str, ports: List[int]) -> List[Dict[str, Any]]:
    results = []
    for port in ports[:20]:
        try:
            with socket.create_connection((host, int(port)), timeout=2):
                results.append({"port": int(port), "state": "open"})
        except Exception:
            results.append({"port": int(port), "state": "closed_or_filtered"})
    return results


def _url_redirect_tracer(payload: Dict[str, Any]) -> Dict[str, Any]:
    urls = _as_list(payload.get("urls") or payload.get("url") or [])
    live = bool(payload.get("live_trace", False))
    allow_private = bool(payload.get("allow_private", False))
    traces = []
    findings = []
    for url in urls:
        url = str(url)
        parsed = urlparse(url)
        trace = {"url": url, "scheme": parsed.scheme, "host": parsed.hostname, "hops": []}
        if parsed.scheme not in {"http", "https"}:
            findings.append(_finding("URL Redirect Tracer", "Non-HTTP URL supplied", "medium", {"url": url}, "Inspect non-web URI schemes before user interaction."))
        if live and (allow_private or not _is_private_url(url)):
            try:
                response = requests.get(url, timeout=5, allow_redirects=True)
                trace["final_url"] = response.url
                trace["status_code"] = response.status_code
                trace["hops"] = [r.url for r in response.history] + [response.url]
            except Exception as exc:
                trace["error"] = type(exc).__name__
        if parsed.hostname and re.search(r"(?i)(xn--|bit\.ly|tinyurl|t\.co|goo\.gl)", parsed.hostname):
            findings.append(_finding("URL Redirect Tracer", "Shortened or punycode URL", "medium", {"url": url}, "Expand and reputation-check before release."))
        traces.append(trace)
    return _finish("url_redirect_tracer", payload, {"traces": traces}, findings)


def _oauth_app_permission_checker(payload: Dict[str, Any]) -> Dict[str, Any]:
    apps = _as_list(payload.get("apps") or [])
    risky_scopes = {"mail.readwrite", "mail.send", "files.readwrite.all", "directory.readwrite.all", "offline_access", "user.readwrite.all"}
    findings = []
    for app in apps:
        if not isinstance(app, dict):
            continue
        scopes = {str(s).lower() for s in _as_list(app.get("scopes") or app.get("permissions") or [])}
        risky = sorted(scopes & risky_scopes)
        if risky:
            findings.append(_finding("OAuth App Permission Checker", "High-risk OAuth permission grant", "high", {"app": app.get("name"), "risky_scopes": risky}, "Review consent, publisher, owner and revoke unnecessary grants."))
        if app.get("publisher_verified") is False:
            findings.append(_finding("OAuth App Permission Checker", "OAuth app publisher not verified", "medium", app, "Require verified publishers for sensitive consent."))
    return _finish("oauth_app_permission_checker", payload, {"app_count": len(apps)}, findings)


def _microsoft_365_security_checker(payload: Dict[str, Any]) -> Dict[str, Any]:
    controls = payload.get("controls") or payload
    expected = {
        "mfa_enabled": True,
        "legacy_auth_blocked": True,
        "audit_log_enabled": True,
        "safe_links_enabled": True,
        "safe_attachments_enabled": True,
        "external_forwarding_blocked": True,
        "admin_count_reviewed": True,
    }
    findings = []
    for key, value in expected.items():
        if key in controls and controls.get(key) != value:
            findings.append(_finding("Microsoft 365 Security Checker", f"M365 control drift: {key}", "high" if key in {"mfa_enabled", "legacy_auth_blocked"} else "medium", {"control": key, "expected": value, "actual": controls.get(key)}, "Align tenant configuration to the Sentinel M365 baseline."))
    return _finish("microsoft_365_security_checker", payload, {"expected": expected}, findings)


def _threat_feed_aggregator(payload: Dict[str, Any]) -> Dict[str, Any]:
    feeds = _as_list(payload.get("feeds") or [])
    indicators = {}
    for feed in feeds:
        for indicator in _as_list(feed.get("indicators") if isinstance(feed, dict) else []):
            value = str(indicator.get("value") if isinstance(indicator, dict) else indicator).lower()
            indicators.setdefault(value, {"value": value, "sources": []})
            indicators[value]["sources"].append(feed.get("name", "unnamed") if isinstance(feed, dict) else "unnamed")
    return _finish("threat_feed_aggregator", payload, {"indicator_count": len(indicators), "indicators": list(indicators.values())}, [])


def _yara_rule_manager(payload: Dict[str, Any]) -> Dict[str, Any]:
    rules = _as_list(payload.get("rules") or payload.get("rule") or [])
    findings = []
    results = []
    for rule in rules:
        text = str(rule.get("text") if isinstance(rule, dict) else rule)
        valid = bool(re.search(r"\brule\s+[A-Za-z0-9_]+\s*\{", text) and re.search(r"\bcondition\s*:", text))
        result = {"valid": valid, "name": re.search(r"\brule\s+([A-Za-z0-9_]+)", text).group(1) if re.search(r"\brule\s+([A-Za-z0-9_]+)", text) else None}
        results.append(result)
        if not valid:
            findings.append(_finding("YARA Rule Manager", "Invalid YARA rule shape", "medium", {"rule": text[:500]}, "Add a rule declaration and condition block before distribution."))
    return _finish("yara_rule_manager", payload, {"rules": results}, findings)


def _sigma_rule_manager(payload: Dict[str, Any]) -> Dict[str, Any]:
    rules = _as_list(payload.get("rules") or payload.get("rule") or [])
    findings = []
    results = []
    for rule in rules:
        text = str(rule.get("text") if isinstance(rule, dict) else rule)
        keys = {line.split(":", 1)[0].strip().lower() for line in text.splitlines() if ":" in line}
        missing = sorted({"title", "logsource", "detection"} - keys)
        results.append({"valid": not missing, "missing": missing})
        if missing:
            findings.append(_finding("Sigma Rule Manager", "Sigma rule missing required fields", "medium", {"missing": missing}, "Add required Sigma metadata before enabling rule."))
    return _finish("sigma_rule_manager", payload, {"rules": results}, findings)


def _mitre_source_entries(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    preferred_keys = ["findings", "alerts", "events", "signals", "commands", "processes", "connections", "rules", "logs"]
    entries: List[Dict[str, Any]] = []
    for key in preferred_keys:
        if key not in payload:
            continue
        for index, item in enumerate(_as_list(payload.get(key))):
            raw = item if isinstance(item, dict) else {"value": item}
            text = _text(raw)
            entries.append({
                "source_type": key,
                "source_id": raw.get("finding_id") or raw.get("id") or raw.get("event_id") or f"{key}-{index + 1}",
                "module": raw.get("module") or raw.get("source") or raw.get("tool") or key,
                "severity": raw.get("severity") or raw.get("highest_severity") or "informational",
                "title": raw.get("title") or raw.get("name") or raw.get("event") or "",
                "text": text,
                "raw": raw,
            })
    if payload.get("text"):
        entries.append({"source_type": "text", "source_id": "text-1", "module": "text", "severity": "informational", "title": "Text signal", "text": str(payload.get("text")), "raw": {"text": payload.get("text")}})
    if not entries:
        entries.append({"source_type": "payload", "source_id": "payload-1", "module": "payload", "severity": "informational", "title": "Payload", "text": _text(payload), "raw": payload})
    return entries


def _mitre_confidence_label(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.65:
        return "medium"
    return "low"


def _mitre_url(technique_id: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"


def _mitre_mapping_reason(technique: Dict[str, Any], matched_terms: List[str], source_modules: List[str]) -> str:
    terms = ", ".join(matched_terms[:5])
    modules = ", ".join(source_modules[:4])
    return f"Matched {technique['id']} {technique['name']} because the evidence contained {terms or 'a direct technique reference'} in {modules or 'the supplied signals'}."


def _mitre_attack_mapper(payload: Dict[str, Any]) -> Dict[str, Any]:
    entries = _mitre_source_entries(payload)
    mappings: Dict[str, Dict[str, Any]] = {}
    entry_matches: Dict[str, List[str]] = {}

    for entry in entries:
        text = entry["text"]
        lower = text.lower()
        matched_ids: List[str] = []

        for technique_id in sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, flags=re.I))):
            normalized_id = technique_id.upper()
            technique = MITRE_BY_ID.get(normalized_id)
            if not technique:
                technique = {"id": normalized_id, "name": "ATT&CK technique referenced directly", "tactics": ["Unmapped"], "keywords": []}
            mapping = mappings.setdefault(normalized_id, {
                "technique_id": normalized_id,
                "technique": technique["name"],
                "tactics": technique["tactics"],
                "confidence": 0.0,
                "matched_terms": set(),
                "evidence_refs": [],
                "source_modules": set(),
                "severities": [],
            })
            mapping["confidence"] = max(mapping["confidence"], 0.95)
            mapping["matched_terms"].add(normalized_id)
            mapping["evidence_refs"].append({"source_id": entry["source_id"], "source_type": entry["source_type"], "title": entry["title"], "excerpt": _short_text(entry["text"], 280)})
            mapping["source_modules"].add(str(entry["module"]))
            mapping["severities"].append(entry["severity"])
            matched_ids.append(normalized_id)

        for technique in MITRE_TECHNIQUES:
            matched_terms = [term for term in technique["keywords"] if term.lower() in lower]
            if not matched_terms:
                continue
            score = min(0.9, 0.52 + (len(matched_terms) * 0.08))
            if entry["source_type"] in {"findings", "alerts"}:
                score += 0.08
            if entry["severity"] in {"critical", "high"}:
                score += 0.05
            score = min(score, 0.96)
            technique_id = technique["id"]
            mapping = mappings.setdefault(technique_id, {
                "technique_id": technique_id,
                "technique": technique["name"],
                "tactics": technique["tactics"],
                "confidence": 0.0,
                "matched_terms": set(),
                "evidence_refs": [],
                "source_modules": set(),
                "severities": [],
            })
            mapping["confidence"] = max(mapping["confidence"], score)
            mapping["matched_terms"].update(matched_terms)
            mapping["evidence_refs"].append({"source_id": entry["source_id"], "source_type": entry["source_type"], "title": entry["title"], "excerpt": _short_text(entry["text"], 280)})
            mapping["source_modules"].add(str(entry["module"]))
            mapping["severities"].append(entry["severity"])
            matched_ids.append(technique_id)

        entry_matches[entry["source_id"]] = sorted(set(matched_ids))

    technique_rows = []
    for technique_id, mapping in mappings.items():
        matched_terms = sorted(mapping["matched_terms"])
        source_modules = sorted(mapping["source_modules"])
        confidence = round(float(mapping["confidence"]), 2)
        severities = [str(severity).lower() for severity in mapping["severities"]]
        highest = max(severities, key=lambda s: SEVERITY_SCORE.get(s, 0), default="informational")
        row = {
            "technique_id": technique_id,
            "technique": mapping["technique"],
            "tactics": mapping["tactics"],
            "confidence": confidence,
            "confidence_label": _mitre_confidence_label(confidence),
            "matched_terms": matched_terms,
            "source_count": len({item["source_id"] for item in mapping["evidence_refs"]}),
            "source_modules": source_modules,
            "evidence_refs": mapping["evidence_refs"][:8],
            "highest_source_severity": highest,
            "why": _mitre_mapping_reason({"id": technique_id, "name": mapping["technique"]}, matched_terms, source_modules),
            "mitre_url": _mitre_url(technique_id),
        }
        technique_rows.append(row)

    technique_rows.sort(key=lambda row: (row["confidence"], SEVERITY_SCORE.get(row["highest_source_severity"], 0), row["source_count"]), reverse=True)
    covered_tactics = sorted({tactic for row in technique_rows for tactic in row["tactics"] if tactic in MITRE_TACTICS}, key=lambda tactic: MITRE_TACTICS.index(tactic))
    tactic_matrix = [
        {
            "tactic": tactic,
            "technique_count": len([row for row in technique_rows if tactic in row["tactics"]]),
            "techniques": [row["technique_id"] for row in technique_rows if tactic in row["tactics"]],
        }
        for tactic in MITRE_TACTICS
    ]
    unmapped = [
        {
            "source_id": entry["source_id"],
            "source_type": entry["source_type"],
            "title": entry["title"],
            "excerpt": _short_text(entry["text"], 220),
        }
        for entry in entries
        if not entry_matches.get(entry["source_id"])
    ]
    navigator_layer = {
        "name": "Sentinel ATT&CK Mapping",
        "versions": {"attack": "enterprise", "navigator": "4.8"},
        "domain": "enterprise-attack",
        "description": "Generated by Sentinel MITRE ATT&CK Mapper from supplied findings, events, commands and signals.",
        "techniques": [
            {
                "techniqueID": row["technique_id"],
                "score": int(row["confidence"] * 100),
                "comment": row["why"],
                "enabled": True,
            }
            for row in technique_rows
        ],
    }
    findings = [
        _finding(
            "MITRE ATT&CK Mapper",
            f"Mapped activity to {row['technique_id']}: {row['technique']}",
            "low" if row["confidence"] < 0.85 else "medium",
            {"technique_id": row["technique_id"], "technique": row["technique"], "tactics": row["tactics"], "matched_terms": row["matched_terms"], "evidence_refs": row["evidence_refs"][:3]},
            "Use this ATT&CK mapping to plan detection coverage, investigation scope and reporting. Validate context before treating it as confirmed adversary behaviour.",
        )
        for row in technique_rows[:20]
    ]
    return _finish("mitre_attack_mapper", payload, {
        "techniques": technique_rows,
        "technique_count": len(technique_rows),
        "covered_tactics": covered_tactics,
        "tactic_coverage_percent": round((len(covered_tactics) / len(MITRE_TACTICS)) * 100, 1),
        "tactic_matrix": tactic_matrix,
        "unmapped_signals": unmapped,
        "navigator_layer": navigator_layer,
    }, findings)


def _case_management(payload: Dict[str, Any]) -> Dict[str, Any]:
    case = {"case_id": payload.get("case_id") or f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}", "title": payload.get("title", "Untitled case"), "status": payload.get("status", "open"), "findings": _as_list(payload.get("findings") or [])}
    return _finish("case_management", payload, {"case": case}, [])


def _mini_siem_log_search(payload: Dict[str, Any]) -> Dict[str, Any]:
    events = [e for e in _as_list(payload.get("events") or []) if isinstance(e, dict)]
    query = str(payload.get("query") or "").lower()
    field_filters = payload.get("filters") or {}
    matches = []
    for event in events:
        if query and query not in _text(event).lower():
            continue
        if any(str(event.get(k, "")).lower() != str(v).lower() for k, v in field_filters.items()):
            continue
        matches.append(event)
    return _finish("mini_siem_log_search", payload, {"matches": matches, "match_count": len(matches)}, [])


def _alert_correlation_engine(payload: Dict[str, Any]) -> Dict[str, Any]:
    alerts = [a for a in _as_list(payload.get("alerts") or payload.get("findings") or []) if isinstance(a, dict)]
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for alert in alerts:
        key = str(alert.get("host") or alert.get("hostname") or alert.get("user") or alert.get("source_ip") or "global")
        groups.setdefault(key, []).append(alert)
    correlations = [{"entity": key, "alert_count": len(value), "highest_severity": max((a.get("severity", "informational") for a in value), key=lambda s: SEVERITY_SCORE.get(s, 0), default="informational")} for key, value in groups.items()]
    findings = [_finding("Alert Correlation Engine", "Multiple alerts correlated to one entity", "high", corr, "Open a case and review timeline for this entity.") for corr in correlations if corr["alert_count"] >= int(payload.get("threshold", 3))]
    return _finish("alert_correlation_engine", payload, {"correlations": correlations}, findings)


def _security_health_score(payload: Dict[str, Any]) -> Dict[str, Any]:
    findings = _as_list(payload.get("findings") or [])
    score = 100
    for finding in findings:
        if isinstance(finding, dict):
            score -= {"critical": 25, "high": 15, "medium": 8, "low": 3}.get(str(finding.get("severity", "")).lower(), 0)
    score = max(0, score)
    return _finish("security_health_score", payload, {"score": score, "band": "critical" if score < 50 else "high" if score < 70 else "medium" if score < 85 else "low"}, [])


def _remediation_guidance_wizard(payload: Dict[str, Any]) -> Dict[str, Any]:
    findings = _as_list(payload.get("findings") or [])
    guidance = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity", "informational"))
        guidance.append({"finding_id": finding.get("finding_id"), "title": finding.get("title"), "priority": severity, "steps": ["Preserve evidence", "Validate business context", finding.get("recommended_action") or "Apply vendor remediation guidance", "Verify the control after remediation"]})
    return _finish("remediation_guidance_wizard", payload, {"guidance": guidance}, [])


def _risk_register_export(payload: Dict[str, Any]) -> Dict[str, Any]:
    risks = [r for r in _as_list(payload.get("risks") or payload.get("findings") or []) if isinstance(r, dict)]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "title", "severity", "owner", "status", "remediation"])
    writer.writeheader()
    for risk in risks:
        writer.writerow({"id": risk.get("finding_id") or risk.get("id"), "title": risk.get("title"), "severity": risk.get("severity"), "owner": risk.get("owner", ""), "status": risk.get("status", "open"), "remediation": risk.get("recommended_action", "")})
    return _finish("risk_register_export", payload, {"csv": output.getvalue(), "risk_count": len(risks)}, [])


def _mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _secrets_scanner(payload: Dict[str, Any]) -> Dict[str, Any]:
    contents = _as_list(payload.get("contents") or payload.get("text") or [])
    patterns = {
        "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "OpenAI API key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        "Generic private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "Generic token assignment": re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{12,})"),
    }
    findings = []
    for content in contents:
        text = _text(content)
        for label, pattern in patterns.items():
            for match in pattern.finditer(text):
                secret = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
                findings.append(_finding("Secrets Scanner", label, "critical", {"secret_preview": _mask_secret(secret)}, "Rotate the secret and remove it from source history."))
    return _finish("secrets_scanner", payload, {"content_count": len(contents)}, findings)


def _git_repo_security_scanner(payload: Dict[str, Any]) -> Dict[str, Any]:
    repo = Path(str(payload.get("path") or WORKSPACE_ROOT)).resolve()
    findings = []
    data: Dict[str, Any] = {"path": str(repo), "tracked_sensitive_files": []}
    if not str(repo).lower().startswith(str(WORKSPACE_ROOT).lower()):
        findings.append(_finding("Git/Repo Security Scanner", "Repository path outside workspace was not scanned", "medium", {"path": str(repo)}, "Run the scanner from a trusted workspace path."))
        return _finish("git_repo_security_scanner", payload, data, findings)
    try:
        tracked = subprocess.run(["git", "ls-files"], cwd=repo, capture_output=True, text=True, timeout=15, shell=False).stdout.splitlines()
        sensitive = [f for f in tracked if re.search(r"(?i)(^|/)\.env|secret|credential|private.*key|id_rsa", f)]
        data["tracked_sensitive_files"] = sensitive
        for item in sensitive:
            findings.append(_finding("Git/Repo Security Scanner", "Sensitive-looking file tracked by git", "high", {"path": item}, "Remove sensitive files from git and rotate exposed credentials."))
    except Exception as exc:
        data["error"] = type(exc).__name__
    return _finish("git_repo_security_scanner", payload, data, findings)


def _container_image_scanner(payload: Dict[str, Any]) -> Dict[str, Any]:
    dockerfile = str(payload.get("dockerfile") or "")
    findings = []
    if re.search(r"(?im)^FROM\s+.+:latest\b", dockerfile):
        findings.append(_finding("Container Image Scanner", "Base image uses latest tag", "medium", {}, "Pin base images by version or digest."))
    if not re.search(r"(?im)^USER\s+\S+", dockerfile):
        findings.append(_finding("Container Image Scanner", "Container does not set non-root USER", "medium", {}, "Run containers as non-root where possible."))
    if re.search(r"(?i)(password|secret|token|api_key)\s*=", dockerfile):
        findings.append(_finding("Container Image Scanner", "Secret-like value in Dockerfile", "critical", {}, "Move secrets to runtime secret management."))
    return _finish("container_image_scanner", payload, {"dockerfile_present": bool(dockerfile)}, findings)


def _cloud_saas_audit_importer(payload: Dict[str, Any]) -> Dict[str, Any]:
    records = _as_list(payload.get("records") or payload.get("events") or [])
    normalized = []
    for record in records:
        if isinstance(record, dict):
            normalized.append({"provider": record.get("provider") or payload.get("provider", "unknown"), "time": record.get("time") or record.get("timestamp") or record.get("CreationTime"), "actor": record.get("actor") or record.get("user") or record.get("UserId"), "action": record.get("action") or record.get("Operation"), "source_ip": record.get("source_ip") or record.get("ClientIP"), "raw": record})
    return _finish("cloud_saas_audit_importer", payload, {"records": normalized, "record_count": len(normalized)}, [])


def _signing_secret() -> bytes:
    return os.getenv("SENTINEL_SIGNING_SECRET", "sentinel-dev-signing-secret-change-me").encode()


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def _report_signing_integrity_checker(payload: Dict[str, Any]) -> Dict[str, Any]:
    document = payload.get("document") or payload.get("payload") or {}
    digest = hashlib.sha256(_canonical_bytes(document)).hexdigest()
    signature = hmac.new(_signing_secret(), digest.encode(), hashlib.sha256).hexdigest()
    provided = payload.get("signature")
    verified = hmac.compare_digest(str(provided), signature) if provided else None
    findings = []
    if provided and not verified:
        findings.append(_finding("Report Signing / Integrity Checker", "Report signature verification failed", "critical", {"sha256": digest}, "Reject the report and verify the signing secret/source."))
    return _finish("report_signing_integrity_checker", payload, {"sha256": digest, "signature": signature, "verified": verified}, findings)


def _role_based_analyst_home_user_modes(payload: Dict[str, Any]) -> Dict[str, Any]:
    mode = str(payload.get("mode") or "analyst").lower()
    analyst = ["case_management", "mini_siem_log_search", "alert_correlation_engine", "mitre_attack_mapper", "risk_register_export"]
    home = ["av_scanner", "phishing_email_analyser", "windows_security_baseline_checker", "backup_readiness_checker", "browser_security_checker"]
    enabled = home if mode in {"home", "home_user"} else analyst + home
    return _finish("role_based_analyst_home_user_modes", payload, {"mode": mode, "enabled_capabilities": enabled}, [])


def _signed_update_rule_distribution_system(payload: Dict[str, Any]) -> Dict[str, Any]:
    package = payload.get("package") or {}
    digest = hashlib.sha256(_canonical_bytes(package)).hexdigest()
    expected = hmac.new(_signing_secret(), digest.encode(), hashlib.sha256).hexdigest()
    supplied = payload.get("signature")
    verified = hmac.compare_digest(str(supplied), expected) if supplied else False
    findings = []
    if not verified:
        findings.append(_finding("Signed Update and Rule Distribution System", "Update package signature missing or invalid", "critical", {"sha256": digest}, "Do not install unsigned rule/update packages."))
    return _finish("signed_update_rule_distribution_system", payload, {"sha256": digest, "expected_signature": expected, "verified": verified}, findings)


RUNNERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "av_scanner": _av_scanner,
    "ioc_scanner": _ioc_scanner,
    "phishing_email_analyser": _phishing_email_analyser,
    "endpoint_investigation_collector": lambda payload: _finish("endpoint_investigation_collector", payload, {"expected_artifacts": ["endpoint_snapshot.json", "processes.json", "network_connections.json", "persistence.json", "event_logs.json", "powershell_activity.json"]}, []),
    "persistence_scanner": _persistence_scanner,
    "process_tree_viewer": _process_tree_viewer,
    "suspicious_command_line_analyser": _suspicious_command_line_analyser,
    "network_connection_monitor": _network_connection_monitor,
    "dns_monitor": _dns_monitor,
    "dns_protection_tool": _dns_protection_tool,
    "windows_event_log_collector": _windows_event_log_collector,
    "powershell_activity_analyser": _powershell_activity_analyser,
    "timeline_builder": _timeline_builder,
    "evidence_bundle_exporter": _evidence_bundle_exporter,
    "incident_report_generator": _incident_report_generator,
    "ransomware_behaviour_guard": _ransomware_behaviour_guard,
    "backup_readiness_checker": _backup_readiness_checker,
    "windows_security_baseline_checker": _windows_security_baseline_checker,
    "patch_status_checker": _patch_status_checker,
    "installed_software_inventory": _installed_software_inventory,
    "cve_kev_vulnerability_matcher": _cve_kev_vulnerability_matcher,
    "browser_security_checker": _browser_security_checker,
    "usb_guard": _usb_guard,
    "firewall_rule_auditor": _firewall_rule_auditor,
    "local_account_admin_audit": _local_account_admin_audit,
    "logon_event_analyser": _logon_event_analyser,
    "privilege_change_monitor": _privilege_change_monitor,
    "mailbox_rule_checker": _mailbox_rule_checker,
    "email_header_analyser": _email_header_analyser,
    "attachment_risk_analyser": _attachment_risk_analyser,
    "url_redirect_tracer": _url_redirect_tracer,
    "oauth_app_permission_checker": _oauth_app_permission_checker,
    "microsoft_365_security_checker": _microsoft_365_security_checker,
    "threat_feed_aggregator": _threat_feed_aggregator,
    "yara_rule_manager": _yara_rule_manager,
    "sigma_rule_manager": _sigma_rule_manager,
    "mitre_attack_mapper": _mitre_attack_mapper,
    "case_management": _case_management,
    "mini_siem_log_search": _mini_siem_log_search,
    "alert_correlation_engine": _alert_correlation_engine,
    "security_health_score": _security_health_score,
    "remediation_guidance_wizard": _remediation_guidance_wizard,
    "risk_register_export": _risk_register_export,
    "secrets_scanner": _secrets_scanner,
    "git_repo_security_scanner": _git_repo_security_scanner,
    "container_image_scanner": _container_image_scanner,
    "cloud_saas_audit_importer": _cloud_saas_audit_importer,
    "report_signing_integrity_checker": _report_signing_integrity_checker,
    "role_based_analyst_home_user_modes": _role_based_analyst_home_user_modes,
    "signed_update_rule_distribution_system": _signed_update_rule_distribution_system,
}


@router.get("/manifest")
def manifest() -> Dict[str, Any]:
    return {"locked": True, "count": len(CANONICAL_CAPABILITIES), "capabilities": CANONICAL_CAPABILITIES}


@router.get("/audit")
def audit() -> Dict[str, Any]:
    capabilities = []
    for item in CANONICAL_CAPABILITIES:
        slug = str(item["slug"])
        capabilities.append({**item, "endpoint": CAPABILITY_ENDPOINTS[slug], "suite_runner": slug in RUNNERS, "covered": slug in CAPABILITY_ENDPOINTS and slug in RUNNERS})
    return {"locked": True, "coverage_count": len([item for item in capabilities if item["covered"]]), "capabilities": capabilities}


@router.get("/packs")
def packs() -> Dict[str, Any]:
    return {
        "count": len(WORKFLOW_PACKS),
        "packs": [
            {"slug": slug, "name": pack["name"], "capabilities": pack["capabilities"], "capability_count": len(pack["capabilities"])}
            for slug, pack in WORKFLOW_PACKS.items()
        ],
    }


@router.post("/run/{capability_slug}")
def run_capability(capability_slug: str, payload: Dict[str, Any] = Body(default_factory=dict)) -> Dict[str, Any]:
    runner = RUNNERS.get(capability_slug)
    if runner is None:
        raise HTTPException(status_code=404, detail=f"Unknown or unimplemented capability: {capability_slug}")
    return runner(payload or {})


@router.post("/run-pack/{pack_slug}")
def run_pack(pack_slug: str, payload: Dict[str, Any] = Body(default_factory=dict)) -> Dict[str, Any]:
    pack = WORKFLOW_PACKS.get(pack_slug)
    if pack is None:
        raise HTTPException(status_code=404, detail=f"Unknown workflow pack: {pack_slug}")
    inputs = payload.get("inputs") if isinstance(payload.get("inputs"), dict) else {}
    use_samples = bool(payload.get("use_samples", not inputs))
    results = []
    for capability_slug in pack["capabilities"]:
        runner = RUNNERS[capability_slug]
        capability_payload = inputs.get(capability_slug)
        if capability_payload is None and use_samples:
            capability_payload = PACK_SAMPLE_INPUTS.get(capability_slug, {})
        if capability_payload is None:
            capability_payload = {}
        results.append(runner(capability_payload))
    return _pack_summary(pack_slug, pack, results)


@router.post("/external-check")
def external_check(payload: Dict[str, Any] = Body(default_factory=dict)) -> Dict[str, Any]:
    target = str(payload.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")

    checks = set(str(item).lower() for item in _as_list(payload.get("checks") or ["dns", "http", "tls"]))
    allow_private = bool(payload.get("allow_private", False))
    host = _target_host(target)
    if not host:
        raise HTTPException(status_code=400, detail="target host could not be parsed")

    findings: List[Dict[str, Any]] = []
    data: Dict[str, Any] = {"target": target, "host": host, "checks": sorted(checks), "private_blocked": False}

    if _is_private_host(host) and not allow_private:
        data["private_blocked"] = True
        findings.append(_finding("External Service Checker", "Private or local target blocked", "medium", {"target": target, "host": host}, "Enable allow_private only when you are intentionally checking an internal system."))
        return _finish("external_service_checker", payload, data, findings)

    if "dns" in checks:
        try:
            addresses = sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
            data["dns"] = {"addresses": addresses}
            if not addresses:
                findings.append(_finding("External Service Checker", "Target has no DNS answers", "medium", {"host": host}, "Confirm the hostname and authoritative DNS configuration."))
        except Exception as exc:
            data["dns"] = {"error": type(exc).__name__, "detail": str(exc)}
            findings.append(_finding("External Service Checker", "DNS lookup failed", "medium", {"host": host, "error": type(exc).__name__}, "Confirm the hostname and resolver path."))

    if "http" in checks:
        http = _http_probe(target)
        data["http"] = http
        if http.get("error"):
            findings.append(_finding("External Service Checker", "HTTP probe failed", "medium", http, "Confirm the service is reachable and listening on the expected scheme."))
        headers = http.get("security_headers") or {}
        if http.get("status_code") and int(http["status_code"]) >= 500:
            findings.append(_finding("External Service Checker", "External service returned server error", "high", http, "Investigate service health and upstream dependencies."))
        for key in ["strict_transport_security", "content_security_policy", "x_frame_options", "x_content_type_options"]:
            if http.get("scheme") == "https" and not headers.get(key):
                findings.append(_finding("External Service Checker", f"Missing HTTP security header: {key}", "low", {"header": key, "target": target}, "Add this response header where appropriate for the application."))

    if "tls" in checks:
        tls_port = int(payload.get("tls_port", 443))
        tls = _tls_probe(host, tls_port)
        data["tls"] = tls
        if tls.get("error"):
            findings.append(_finding("External Service Checker", "TLS probe failed", "medium", tls, "Confirm certificate configuration and TLS listener availability."))
        elif tls.get("days_remaining") is not None and tls["days_remaining"] < int(payload.get("min_tls_days", 30)):
            findings.append(_finding("External Service Checker", "TLS certificate expires soon", "high", tls, "Renew or rotate the certificate before expiry."))

    if "ports" in checks:
        ports = [int(port) for port in _as_list(payload.get("ports") or [80, 443]) if str(port).isdigit()]
        data["ports"] = _port_probe(host, ports)
        open_ports = [item for item in data["ports"] if item["state"] == "open"]
        for item in open_ports:
            if item["port"] not in {80, 443}:
                findings.append(_finding("External Service Checker", "Unexpected open external port", "medium", {"host": host, **item}, "Confirm the exposed service is intentional and protected."))

    return _finish("external_service_checker", payload, data, findings)
