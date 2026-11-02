"""Canonical Sentinel build manifest.

This file is the source of truth for the product capability list. Tests assert
that every item remains represented so implementation work does not drift away
from the requested build order.
"""

from __future__ import annotations

from typing import Dict, List


CANONICAL_CAPABILITIES: List[Dict[str, str | int]] = [
    {"order": 1, "name": "AV Scanner", "slug": "av_scanner", "state": "built", "owner": "modules.av_engine"},
    {"order": 2, "name": "IOC Scanner", "slug": "ioc_scanner", "state": "built", "owner": "modules.ioc_scanner"},
    {"order": 3, "name": "Phishing Email Analyser", "slug": "phishing_email_analyser", "state": "in_progress", "owner": "modules.phish"},
    {"order": 4, "name": "Endpoint Investigation Collector", "slug": "endpoint_investigation_collector", "state": "built", "owner": "agent.investigation"},
    {"order": 5, "name": "Persistence Scanner", "slug": "persistence_scanner", "state": "built", "owner": "modules.persistence"},
    {"order": 6, "name": "Process Tree Viewer", "slug": "process_tree_viewer", "state": "built", "owner": "modules.investigator"},
    {"order": 7, "name": "Suspicious Command Line Analyser", "slug": "suspicious_command_line_analyser", "state": "built", "owner": "modules.investigator"},
    {"order": 8, "name": "Network Connection Monitor", "slug": "network_connection_monitor", "state": "built", "owner": "modules.network"},
    {"order": 9, "name": "DNS Monitor", "slug": "dns_monitor", "state": "planned", "owner": "modules.security_suite"},
    {"order": 10, "name": "DNS Protection Tool", "slug": "dns_protection_tool", "state": "planned", "owner": "modules.security_suite"},
    {"order": 11, "name": "Windows Event Log Collector", "slug": "windows_event_log_collector", "state": "built", "owner": "agent.collectors.logs"},
    {"order": 12, "name": "PowerShell Activity Analyser", "slug": "powershell_activity_analyser", "state": "built", "owner": "agent.investigation"},
    {"order": 13, "name": "Timeline Builder", "slug": "timeline_builder", "state": "built", "owner": "modules.investigator.timeline"},
    {"order": 14, "name": "Evidence Bundle Exporter", "slug": "evidence_bundle_exporter", "state": "built", "owner": "agent.exporter"},
    {"order": 15, "name": "Incident Report Generator", "slug": "incident_report_generator", "state": "built", "owner": "modules.investigator.reporting"},
    {"order": 16, "name": "Ransomware Behaviour Guard", "slug": "ransomware_behaviour_guard", "state": "planned", "owner": "modules.security_suite"},
    {"order": 17, "name": "Backup Readiness Checker", "slug": "backup_readiness_checker", "state": "planned", "owner": "modules.security_suite"},
    {"order": 18, "name": "Windows Security Baseline Checker", "slug": "windows_security_baseline_checker", "state": "partial", "owner": "modules.endpoint"},
    {"order": 19, "name": "Patch Status Checker", "slug": "patch_status_checker", "state": "planned", "owner": "modules.security_suite"},
    {"order": 20, "name": "Installed Software Inventory", "slug": "installed_software_inventory", "state": "built", "owner": "agent.collectors.software"},
    {"order": 21, "name": "CVE / KEV Vulnerability Matcher", "slug": "cve_kev_vulnerability_matcher", "state": "built", "owner": "modules.cve"},
    {"order": 22, "name": "Browser Security Checker", "slug": "browser_security_checker", "state": "planned", "owner": "modules.security_suite"},
    {"order": 23, "name": "USB Guard", "slug": "usb_guard", "state": "planned", "owner": "modules.security_suite"},
    {"order": 24, "name": "Firewall Rule Auditor", "slug": "firewall_rule_auditor", "state": "planned", "owner": "modules.security_suite"},
    {"order": 25, "name": "Local Account/Admin Audit", "slug": "local_account_admin_audit", "state": "built", "owner": "agent.collectors.users"},
    {"order": 26, "name": "Logon Event Analyser", "slug": "logon_event_analyser", "state": "planned", "owner": "modules.security_suite"},
    {"order": 27, "name": "Privilege Change Monitor", "slug": "privilege_change_monitor", "state": "planned", "owner": "modules.security_suite"},
    {"order": 28, "name": "Mailbox Rule Checker", "slug": "mailbox_rule_checker", "state": "planned", "owner": "modules.security_suite"},
    {"order": 29, "name": "Email Header Analyser", "slug": "email_header_analyser", "state": "partial", "owner": "modules.email_intel"},
    {"order": 30, "name": "Attachment Risk Analyser", "slug": "attachment_risk_analyser", "state": "partial", "owner": "modules.phish"},
    {"order": 31, "name": "URL Redirect Tracer", "slug": "url_redirect_tracer", "state": "planned", "owner": "modules.security_suite"},
    {"order": 32, "name": "OAuth App Permission Checker", "slug": "oauth_app_permission_checker", "state": "planned", "owner": "modules.security_suite"},
    {"order": 33, "name": "Microsoft 365 Security Checker", "slug": "microsoft_365_security_checker", "state": "planned", "owner": "modules.security_suite"},
    {"order": 34, "name": "Threat Feed Aggregator", "slug": "threat_feed_aggregator", "state": "built", "owner": "modules.threat_feeds"},
    {"order": 35, "name": "YARA Rule Manager", "slug": "yara_rule_manager", "state": "partial", "owner": "modules.av_engine"},
    {"order": 36, "name": "Sigma Rule Manager", "slug": "sigma_rule_manager", "state": "planned", "owner": "modules.security_suite"},
    {"order": 37, "name": "MITRE ATT&CK Mapper", "slug": "mitre_attack_mapper", "state": "planned", "owner": "modules.security_suite"},
    {"order": 38, "name": "Case Management", "slug": "case_management", "state": "built", "owner": "modules.cases"},
    {"order": 39, "name": "Mini-SIEM / Log Search", "slug": "mini_siem_log_search", "state": "planned", "owner": "modules.security_suite"},
    {"order": 40, "name": "Alert Correlation Engine", "slug": "alert_correlation_engine", "state": "planned", "owner": "modules.security_suite"},
    {"order": 41, "name": "Security Health Score", "slug": "security_health_score", "state": "built", "owner": "modules.endpoint"},
    {"order": 42, "name": "Remediation Guidance Wizard", "slug": "remediation_guidance_wizard", "state": "planned", "owner": "modules.security_suite"},
    {"order": 43, "name": "Risk Register Export", "slug": "risk_register_export", "state": "planned", "owner": "modules.security_suite"},
    {"order": 44, "name": "Secrets Scanner", "slug": "secrets_scanner", "state": "planned", "owner": "modules.security_suite"},
    {"order": 45, "name": "Git/Repo Security Scanner", "slug": "git_repo_security_scanner", "state": "planned", "owner": "modules.security_suite"},
    {"order": 46, "name": "Container Image Scanner", "slug": "container_image_scanner", "state": "planned", "owner": "modules.security_suite"},
    {"order": 47, "name": "Cloud/SaaS Audit Importer", "slug": "cloud_saas_audit_importer", "state": "planned", "owner": "modules.security_suite"},
    {"order": 48, "name": "Report Signing / Integrity Checker", "slug": "report_signing_integrity_checker", "state": "planned", "owner": "modules.security_suite"},
    {"order": 49, "name": "Role-Based Analyst/Home User Modes", "slug": "role_based_analyst_home_user_modes", "state": "planned", "owner": "modules.security_suite"},
    {"order": 50, "name": "Signed Update and Rule Distribution System", "slug": "signed_update_rule_distribution_system", "state": "planned", "owner": "modules.security_suite"},
]

CANONICAL_CAPABILITY_NAMES = [str(item["name"]) for item in CANONICAL_CAPABILITIES]
CANONICAL_CAPABILITY_SLUGS = [str(item["slug"]) for item in CANONICAL_CAPABILITIES]
