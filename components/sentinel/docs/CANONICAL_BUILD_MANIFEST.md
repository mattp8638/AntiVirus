# Sentinel Canonical Build Manifest

This document locks the requested Sentinel enhancement list. Product, backend,
frontend, and test work should track this list and avoid adding unrelated
capability drift ahead of these items.

The executable source of truth is `modules/build_manifest.py`; tests assert that
the application exposes coverage for every capability below.

1. AV Scanner
2. IOC Scanner
3. Phishing Email Analyser
4. Endpoint Investigation Collector
5. Persistence Scanner
6. Process Tree Viewer
7. Suspicious Command Line Analyser
8. Network Connection Monitor
9. DNS Monitor
10. DNS Protection Tool
11. Windows Event Log Collector
12. PowerShell Activity Analyser
13. Timeline Builder
14. Evidence Bundle Exporter
15. Incident Report Generator
16. Ransomware Behaviour Guard
17. Backup Readiness Checker
18. Windows Security Baseline Checker
19. Patch Status Checker
20. Installed Software Inventory
21. CVE / KEV Vulnerability Matcher
22. Browser Security Checker
23. USB Guard
24. Firewall Rule Auditor
25. Local Account/Admin Audit
26. Logon Event Analyser
27. Privilege Change Monitor
28. Mailbox Rule Checker
29. Email Header Analyser
30. Attachment Risk Analyser
31. URL Redirect Tracer
32. OAuth App Permission Checker
33. Microsoft 365 Security Checker
34. Threat Feed Aggregator
35. YARA Rule Manager
36. Sigma Rule Manager
37. MITRE ATT&CK Mapper
38. Case Management
39. Mini-SIEM / Log Search
40. Alert Correlation Engine
41. Security Health Score
42. Remediation Guidance Wizard
43. Risk Register Export
44. Secrets Scanner
45. Git/Repo Security Scanner
46. Container Image Scanner
47. Cloud/SaaS Audit Importer
48. Report Signing / Integrity Checker
49. Role-Based Analyst/Home User Modes
50. Signed Update and Rule Distribution System
