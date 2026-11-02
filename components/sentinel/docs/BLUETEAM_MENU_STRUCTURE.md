# Sentinel / Fenrir Menu and Submenu Structure

This document groups the 60-tool Blue Team roadmap into practical menus and submenus. The goal is to keep the UI clean, avoid a long sidebar, and make the platform feel like a coherent defensive security workspace rather than a list of disconnected tools.

## Navigation principles

1. Use a small number of top-level menus.
2. Group tools by user workflow, not by build order.
3. Keep the dashboard focused on risk, alerts and next actions.
4. Avoid making every tool a top-level tab.
5. Use contextual shortcuts where one tool belongs in more than one place.
6. Support future Home User, Analyst, Admin and Developer modes.

---

# Recommended Main Sidebar

The main sidebar should contain only these menus:

```text
Dashboard
Devices
Investigate
Protect
Vulnerabilities
Network & DNS
Email & Cloud
Intelligence & Rules
SOC Workspace
Developer & Supply Chain
Settings
```

Everything else should live as a submenu or contextual tab.

---

# 1. Dashboard

Purpose: one page showing what needs attention first.

Submenus:

| Submenu | Content |
|---|---|
| Overview | Overall risk, alert summary, active cases, high-risk devices |
| Priority Queue | Critical devices, KEVs, failed baselines, active investigations |
| Recent Activity | Scans, agent check-ins, evidence uploads, case updates |
| Top Fixes | Remediation guidance, patch priorities, baseline failures |
| Risk Summary | Risk register summary, unresolved risks, critical assets |

Tools represented:

- 41 Security Health Score
- 42 Remediation Guidance Wizard
- 43 Risk Register Export
- 51 Asset Criticality / Ownership Register
- 60 Guided Response Playbooks

---

# 2. Devices

Purpose: endpoint agents, posture, inventory and device health.

Submenus:

| Submenu | Tools / content |
|---|---|
| Device List | Agents, hostnames, OS, last seen, risk score, investigation state |
| Device Detail | Summary, posture, findings, evidence, cases, timelines |
| Installed Software | 20 Installed Software Inventory |
| Security Baseline | 18 Windows Security Baseline Checker |
| Patch Status | 19 Patch Status Checker |
| Browser Security | 22 Browser Security Checker |
| Backup Readiness | 17 Backup Readiness Checker |
| Asset Ownership | 51 Asset Criticality / Ownership Register |

Recommended behaviour:

- Selecting a device should open a device workspace.
- Device detail should have tabs: Summary, Health, Inventory, Findings, Investigations, Evidence, Cases.
- Device risk should combine technical risk and asset criticality.

---

# 3. Investigate

Purpose: run endpoint investigations and analyse evidence.

Submenus:

| Submenu | Tools / content |
|---|---|
| Run Investigation | 4 Endpoint Investigation Collector |
| Investigation Results | Findings, evidence, scope, status and report links |
| Persistence | 5 Persistence Scanner |
| Processes | 6 Process Tree Viewer, 7 Suspicious Command Line Analyser |
| Network Evidence | 8 Network Connection Monitor |
| Event Logs | 11 Windows Event Log Collector |
| PowerShell Activity | 12 PowerShell Activity Analyser |
| Timeline | 13 Timeline Builder |
| Evidence Bundles | 14 Evidence Bundle Exporter, 52 Chain-of-Custody Log |
| Reports | 15 Incident Report Generator |
| Remote Access | 57 Remote Access Tool Detector |
| Service Weaknesses | 58 Service Path and Permission Auditor |

Recommended behaviour:

- Start with selecting a device, then investigation scope.
- Results should show summary first and technical evidence second.
- Timeline should be reusable from cases and investigations.

---

# 4. Protect

Purpose: defensive controls, scanning, containment and exceptions.

Submenus:

| Submenu | Tools / content |
|---|---|
| AV Scanner | 1 AV Scanner |
| IOC Scanner | 2 IOC Scanner |
| Quarantine | 53 Quarantine Review / Restore Manager |
| Ransomware Guard | 16 Ransomware Behaviour Guard |
| DNS Protection | 10 DNS Protection Tool |
| USB Guard | 23 USB Guard |
| Firewall Controls | 24 Firewall Rule Auditor where action is required |
| Exceptions | 59 Alert Exception / Suppression Manager |
| Offline Scan | Safe offline scan workflow as part of AV operations |

Recommended behaviour:

- Default to safe actions: scan, alert, review and snapshot evidence.
- Quarantine and blocking must be explicit and audited.
- Exceptions must have scope, reason, owner and expiry date.

---

# 5. Vulnerabilities

Purpose: patching, CVEs, KEVs and exposure management.

Submenus:

| Submenu | Tools / content |
|---|---|
| Vulnerability Dashboard | Summary of CVEs, KEVs and exposed assets |
| CVE / KEV Matcher | 21 CVE / KEV Vulnerability Matcher |
| Patch Status | 19 Patch Status Checker |
| Software Inventory | 20 Installed Software Inventory |
| Exposure Review | 24 Firewall Rule Auditor, exposed services, remote access exposure |
| SMB Shares | 56 SMB Share Permission Auditor |
| Risk Register | 43 Risk Register Export |

Tools also used here:

- 51 Asset Criticality / Ownership Register
- 57 Remote Access Tool Detector

Recommended behaviour:

- Prioritise KEV/known exploited items above ordinary CVEs.
- Show affected product, installed version, recommended version/removal and business impact.
- Let unresolved issues export to the risk register.

---

# 6. Network & DNS

Purpose: network evidence, DNS, topology and local traffic-routing tampering.

Submenus:

| Submenu | Tools / content |
|---|---|
| Network Connections | 8 Network Connection Monitor |
| DNS Monitor | 9 DNS Monitor |
| DNS Protection | 10 DNS Protection Tool |
| Topology | Imported topology discovery module |
| Firewall Audit | 24 Firewall Rule Auditor |
| Hosts / Proxy / VPN | 55 Hosts / Proxy / VPN Tamper Checker |
| SMB Shares | 56 SMB Share Permission Auditor |

Recommended behaviour:

- Topology should live under Network & DNS, not be hidden under exposure scanning.
- DNS Protection may appear under Protect too, but management belongs here.
- Hosts/proxy/VPN tampering should be treated as network-defence evidence.

---

# 7. Email & Cloud

Purpose: phishing, suspicious email, mailbox compromise and Microsoft 365 posture.

Submenus:

| Submenu | Tools / content |
|---|---|
| Phishing Email Analyser | 3 Phishing Email Analyser |
| Header Analysis | 29 Email Header Analyser |
| URL Tracing | 31 URL Redirect Tracer |
| Attachment Analysis | 30 Attachment Risk Analyser |
| Mailbox Rules | 28 Mailbox Rule Checker |
| OAuth Apps | 32 OAuth App Permission Checker |
| Microsoft 365 Security | 33 Microsoft 365 Security Checker |
| Trust Signals | 54 Certificate and Trust Store Auditor |
| Response Playbooks | 60 Guided Response Playbooks for phishing/mailbox compromise |

Recommended behaviour:

- Keep phishing simulation separate from defensive email analysis.
- Support pasted headers, pasted raw email and uploaded `.eml` files.
- Microsoft 365 checks should be read-only first.

---

# 8. Intelligence & Rules

Purpose: feeds, rules, ATT&CK mapping and signed updates.

Submenus:

| Submenu | Tools / content |
|---|---|
| Threat Feeds | 34 Threat Feed Aggregator |
| YARA Rules | 35 YARA Rule Manager |
| Sigma Rules | 36 Sigma Rule Manager |
| Native AV Rules | Native AV rule pack management |
| ATT&CK Mapping | 37 MITRE ATT&CK Mapper |
| Exceptions | 59 Alert Exception / Suppression Manager |
| Signed Updates | 50 Signed Update and Rule Distribution System |

Recommended behaviour:

- Analyst/admin focused.
- Every feed/rule change should show source, version, enabled state and last update.
- Rule testing should be available before enforcement.

---

# 9. SOC Workspace

Purpose: cases, reports, log search, correlation and guided response.

Submenus:

| Submenu | Tools / content |
|---|---|
| Cases | 38 Case Management |
| Case Detail | Notes, evidence, affected devices/users, findings and timeline |
| Log Search | 39 Mini-SIEM / Log Search |
| Correlation | 40 Alert Correlation Engine |
| Reports | 15 Incident Report Generator, 48 Report Signing / Integrity Checker |
| Chain of Custody | 52 Evidence Chain-of-Custody Log |
| Remediation | 42 Remediation Guidance Wizard |
| Playbooks | 60 Guided Response Playbooks |
| Risk Register | 43 Risk Register Export |
| Role Views | 49 Role-Based Analyst/Home User Modes |

Recommended behaviour:

- Cases should become the centre of analyst workflow.
- Findings from all modules should attach to a case.
- Reports should generate from case data rather than being typed manually.

---

# 10. Developer & Supply Chain

Purpose: developer, repository, container and cloud/SaaS risk.

Submenus:

| Submenu | Tools / content |
|---|---|
| Secrets Scanner | 44 Secrets Scanner |
| Repository Security | 45 Git/Repo Security Scanner |
| Container Images | 46 Container Image Scanner |
| Cloud/SaaS Imports | 47 Cloud/SaaS Audit Importer |
| Asset Ownership | 51 Asset Criticality / Ownership Register for developer/cloud assets |

Recommended behaviour:

- Hide or collapse in Home User mode.
- Start with local secrets scanning before container/cloud complexity.
- No destructive cloud actions in MVP.

---

# 11. Settings

Purpose: configuration, agents, connectors, roles, updates and audit settings.

Submenus:

| Submenu | Tools / content |
|---|---|
| General Settings | App mode, storage, retention, environment configuration |
| Agents | Agent enrolment, heartbeat, tasking and trust model |
| Connectors | Email, Microsoft 365, feeds, cloud/SaaS and local integrations |
| Roles and Modes | 49 Role-Based Analyst/Home User Modes |
| Update Settings | 50 Signed Update and Rule Distribution System |
| Audit Settings | 52 Chain-of-custody, settings changes, exceptions and exports |
| Secrets | Safe storage of API keys and credentials |

Recommended behaviour:

- Dangerous settings should require confirmation and explain impact.
- Secrets must be masked and never returned in plaintext.
- Production mode should require a proper secret key and persistent storage.

---

# Role-Based Menu Views

## Home User Mode

Show:

```text
Dashboard
Devices
Protect
Vulnerabilities
Email & Cloud
SOC Workspace
Settings
```

Hide or collapse:

```text
Intelligence & Rules
Developer & Supply Chain
Advanced Network tools
Advanced SIEM/correlation
```

## Analyst Mode

Show:

```text
Dashboard
Devices
Investigate
Protect
Vulnerabilities
Network & DNS
Email & Cloud
Intelligence & Rules
SOC Workspace
Settings
```

Hide by default:

```text
Developer & Supply Chain
```

## Admin Mode

Show all operational and configuration menus except Developer & Supply Chain unless enabled.

## Developer / Supply Chain Mode

Show developer/cloud posture tools alongside endpoint and SOC views.

---

# Duplicate Placement Rule

Some tools appear in more than one logical area. This is deliberate.

Examples:

- Patch Status appears under Devices and Vulnerabilities.
- Firewall Rule Auditor appears under Protect, Vulnerabilities and Network & DNS.
- Certificate Auditor appears under Device Health and Email & Cloud.
- Chain-of-Custody appears under Investigation and SOC Workspace.

Rule:

```text
One module implementation, multiple contextual entry points.
```

Do not duplicate backend modules just because a feature appears in multiple menus.

---

# Recommended First UI Refactor

Current working/partial pages should move like this:

| Current page | New menu |
|---|---|
| Command Overview | Dashboard → Overview |
| Threat Pipeline | Intelligence & Rules → Threat Pipeline or Protect → IOC Scanner |
| AV Scanner | Protect → AV Scanner |
| IOC Scanner | Protect → IOC Scanner |
| Endpoint Risk | Devices → Security Baseline |
| Investigator | Investigate → Run Investigation |
| Investigation Details | Investigate → Investigation Results |
| Persistence Scanner | Investigate → Persistence |
| Network Monitor | Network & DNS → Network Connections |
| Cases & Reports | SOC Workspace → Cases |
| ExposureScout | Vulnerabilities → Exposure Review |
| CVE Watchdog | Vulnerabilities → CVE / KEV Matcher |
| Phishing Email Analyser | Email & Cloud → Phishing Email Analyser |
| Email Intelligence | Email & Cloud → Email Intelligence or Intelligence & Rules |
| Settings | Settings → General Settings |

Exit expectation:

- The sidebar becomes grouped and collapsible.
- No current working page disappears.
- Unbuilt pages show clear placeholders with build expectations, not raw blanks.
