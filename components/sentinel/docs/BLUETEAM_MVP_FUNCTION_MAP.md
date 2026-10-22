# Blue Team MVP Function Map

This document converts the Sentinel/Fenrir Blue Team roadmap into practical MVP functions. The goal is to avoid building disconnected tabs and instead build a coherent defensive platform where each tool belongs to a clear operational function.

The roadmap now contains:

- **1–50** Core Sentinel/Fenrir Blue Team platform modules
- **51–60** Professional hardening, evidence, usability and response extensions

## Core principle

The platform should answer these defensive questions:

1. Is this device protected?
2. Is this device vulnerable or misconfigured?
3. Is there evidence of compromise?
4. What happened and when?
5. What should be contained, remediated or monitored?
6. Can the evidence be turned into a case, report and risk register entry?
7. Is the evidence trustworthy, auditable and suitable for handoff?
8. Can a non-expert follow guided response steps safely?

---

# MVP Functions

## Function 1 — Detect and Scan

Purpose: Identify suspicious files, indicators, malicious artefacts and risky content.

Included tools:

| No. | Tool | MVP role |
|---:|---|---|
| 1 | AV Scanner | Native file/folder scanning, hashing, entropy, rules, YARA, quarantine |
| 2 | IOC Scanner | Search endpoint artefacts for hashes, IPs, domains, URLs, filenames and registry indicators |
| 30 | Attachment Risk Analyser | Static attachment analysis, macro/script/archive/file risk |
| 35 | YARA Rule Manager | File detection rules and validation |
| 34 | Threat Feed Aggregator | Feeds hashes, URLs, domains and rules into detection |
| 53 | Quarantine Review / Restore Manager | Review, restore, permanently remove or case-link quarantined items |
| 59 | Alert Exception / Suppression Manager | Control false positives, exclusions and temporary suppressions safely |

MVP exit criteria:

- User can scan a file/folder without relying on the old C++ AV.
- IOC scanner can search files, processes, network/DNS evidence and logs.
- Findings show severity, reason, evidence and recommended action.
- Scan results can be attached to an investigation or case.
- Quarantined files can be reviewed and restored only with explicit audit trail.
- Exceptions have scope, reason, owner and expiry date.

---

## Function 2 — Endpoint Investigation

Purpose: Collect and analyse endpoint evidence after an alert or concern.

Included tools:

| No. | Tool | MVP role |
|---:|---|---|
| 4 | Endpoint Investigation Collector | Agent-driven evidence collection |
| 5 | Persistence Scanner | Autoruns, services, scheduled tasks, startup, WMI, profiles |
| 6 | Process Tree Viewer | Parent/child process chain display |
| 7 | Suspicious Command Line Analyser | Encoded commands, LOLBins, suspicious PowerShell/cmd behaviour |
| 8 | Network Connection Monitor | Active connections and listening ports by process |
| 11 | Windows Event Log Collector | Security/System/Defender/PowerShell event summaries |
| 12 | PowerShell Activity Analyser | Script block/module/history/activity review |
| 13 | Timeline Builder | Chronological incident timeline |
| 14 | Evidence Bundle Exporter | Evidence manifest, bundle and hashes |
| 15 | Incident Report Generator | Human-readable investigation report |
| 52 | Evidence Chain-of-Custody Log | Track collection, export, hashes, access and handoff history |
| 57 | Remote Access Tool Detector | Detect legitimate remote access tools that may indicate compromise |
| 58 | Service Path and Permission Auditor | Detect unquoted paths, writable service binaries and risky service permissions |

MVP exit criteria:

- Analyst selects an agent and queues scoped collection.
- Agent collects selected evidence and uploads it.
- GUI shows findings, evidence, timeline and report output.
- Evidence bundle contains manifest and hashes.
- Evidence chain-of-custody records who collected, exported or downloaded evidence.
- Remote access tools and service path weaknesses appear as investigation findings.

---

## Function 3 — Device Health and Hardening

Purpose: Determine whether the device is securely configured and resilient.

Included tools:

| No. | Tool | MVP role |
|---:|---|---|
| 18 | Windows Security Baseline Checker | Defender, firewall, BitLocker, RDP, SMBv1, UAC, Secure Boot, TPM |
| 19 | Patch Status Checker | Windows/browser/software update posture |
| 20 | Installed Software Inventory | Application inventory for patching and CVE matching |
| 22 | Browser Security Checker | Browser versions, extensions, risky permissions |
| 17 | Backup Readiness Checker | Backup status, freshness, coverage and ransomware exposure |
| 24 | Firewall Rule Auditor | Risky inbound/outbound/public profile firewall rules |
| 41 | Security Health Score | Combines posture, patching, CVEs, backup, browser and identity risk |
| 42 | Remediation Guidance Wizard | Converts technical findings into clear fix steps |
| 51 | Asset Criticality / Ownership Register | Track asset owner, importance, role, sensitivity and priority |
| 54 | Certificate and Trust Store Auditor | Detect suspicious root certificates, trust changes and TLS interception risk |
| 55 | Hosts / Proxy / VPN Tamper Checker | Detect local hosts, proxy, WPAD, VPN, DNS and DoH tampering |
| 58 | Service Path and Permission Auditor | Check weak service paths and service permissions as hardening issues |
| 60 | Guided Response Playbooks | Provide step-by-step fix/response guidance for common finding types |

MVP exit criteria:

- User can select a device and see security posture.
- Missing updates and vulnerable software are prioritised.
- Baseline failures include plain-English fix guidance.
- Security Health Score shows top fixes first.
- Device priority considers asset criticality and ownership.
- Trust-store, hosts, proxy and VPN tampering are identified.
- Guided playbooks help non-experts respond safely.

---

## Function 4 — Vulnerability and Exposure Management

Purpose: Identify vulnerable software, exposed services and risky network posture.

Included tools:

| No. | Tool | MVP role |
|---:|---|---|
| 21 | CVE / KEV Vulnerability Matcher | Match inventory to CVEs and known exploited vulnerabilities |
| 19 | Patch Status Checker | Missing updates and obsolete software |
| 20 | Installed Software Inventory | Software source data |
| 24 | Firewall Rule Auditor | Exposure caused by rules and profiles |
| 47 | Cloud/SaaS Audit Importer | Later import of external exposure/security posture data |
| 43 | Risk Register Export | Export unresolved exposure risks |
| 51 | Asset Criticality / Ownership Register | Prioritise exposure by business importance and owner |
| 56 | SMB Share Permission Auditor | Review exposed shares, weak permissions and ransomware spread risk |
| 57 | Remote Access Tool Detector | Flag unmanaged or suspicious remote access exposure |

MVP exit criteria:

- Device inventory can be matched to vulnerability data.
- KEV/known exploited issues are prioritised above ordinary CVEs.
- Results show affected product, installed version, severity and fix.
- Risks can be exported to a risk register.
- SMB shares and remote access tools are included in exposure scoring.

---

## Function 5 — Network and DNS Defence

Purpose: Monitor endpoint/network communications and block or flag suspicious DNS/domain activity.

Included tools:

| No. | Tool | MVP role |
|---:|---|---|
| 8 | Network Connection Monitor | Endpoint process-to-destination evidence |
| 9 | DNS Monitor | DNS cache/recent queries and IOC matching |
| 10 | DNS Protection Tool | Domain blocklist, allowlist and audit overrides |
| 24 | Firewall Rule Auditor | Exposure and network policy review |
| 34 | Threat Feed Aggregator | Malicious domain/IP/URL feeds |
| 55 | Hosts / Proxy / VPN Tamper Checker | Detect traffic redirection and local name-resolution tampering |
| 56 | SMB Share Permission Auditor | Identify weak or overly broad share exposure |

MVP exit criteria:

- App shows active network connections by process.
- DNS evidence can be matched against known-bad feeds.
- Domain blocks and allowlist overrides are auditable.
- Network findings can be included in reports and cases.
- Hosts/proxy/VPN tampering is treated as network defence evidence.

---

## Function 6 — Ransomware and Removable Media Resilience

Purpose: Detect ransomware-like behaviour and reduce removable media risk.

Included tools:

| No. | Tool | MVP role |
|---:|---|---|
| 16 | Ransomware Behaviour Guard | File-change monitoring, shadow copy deletion, ransom-note detection |
| 17 | Backup Readiness Checker | Backup presence, freshness and ransomware exposure |
| 23 | USB Guard | USB detection, scanning, autorun blocking, audit history |
| 1 | AV Scanner | Scan risky USB/removable media files |
| 14 | Evidence Bundle Exporter | Snapshot evidence during ransomware-like activity |
| 56 | SMB Share Permission Auditor | Identify shares that increase ransomware spread risk |
| 60 | Guided Response Playbooks | Ransomware response checklist and containment workflow |

MVP exit criteria:

- App detects ransomware-like behaviour in alert-only mode first.
- USB insertion and risky removable media files are logged.
- Backup readiness is assessed before destructive incidents.
- Evidence snapshots can be generated without unsafe automatic action.
- SMB exposure and guided ransomware playbooks are available.

---

## Function 7 — Identity, Logon and Local Privilege Monitoring

Purpose: Detect local account abuse and privilege changes.

Included tools:

| No. | Tool | MVP role |
|---:|---|---|
| 25 | Local Account/Admin Audit | Local users, admins, guest, stale/new accounts |
| 26 | Logon Event Analyser | Successful/failed/RDP/network/service logons |
| 27 | Privilege Change Monitor | Admin group changes and new privileged accounts |
| 11 | Windows Event Log Collector | Event evidence source |
| 13 | Timeline Builder | Add logon/privilege events to incident timeline |
| 57 | Remote Access Tool Detector | Link remote tools to suspicious logon or access behaviour |
| 58 | Service Path and Permission Auditor | Highlight service-level privilege escalation weaknesses |

MVP exit criteria:

- App can answer who logged in and when.
- App can show who has local admin rights.
- Privilege changes are detected and timestamped.
- Findings include severity, evidence and recommended action.
- Remote access and service privilege risks are correlated with identity findings.

---

## Function 8 — Email and Microsoft 365 Security

Purpose: Investigate suspicious email, attachments, mailbox compromise and Microsoft 365 posture.

Included tools:

| No. | Tool | MVP role |
|---:|---|---|
| 3 | Phishing Email Analyser | Email risk assessment, headers, links, attachments |
| 28 | Mailbox Rule Checker | Auto-forward/delete/hide/external forwarding rules |
| 29 | Email Header Analyser | From/Reply-To/Return-Path/Received/SPF/DKIM/DMARC |
| 30 | Attachment Risk Analyser | File type, hash, macros, scripts, archives, YARA |
| 31 | URL Redirect Tracer | Safe redirect chain and landing-domain analysis |
| 32 | OAuth App Permission Checker | Risky third-party app permissions |
| 33 | Microsoft 365 Security Checker | MFA, legacy auth, admin users, audit logging, risky sign-ins |
| 54 | Certificate and Trust Store Auditor | Support email/browser trust investigations where certificate tampering is suspected |
| 60 | Guided Response Playbooks | Phishing, mailbox compromise and risky OAuth response steps |

MVP exit criteria:

- User can paste/upload an email and receive a risk verdict.
- Headers, URLs and attachments are analysed separately.
- Mailbox rules and OAuth grants can be reviewed where configured.
- M365 checks are read-only and clearly permission-scoped.
- Phishing response playbooks are available for non-experts.

---

## Function 9 — Threat Intelligence and Detection Engineering

Purpose: Manage the detection content that powers the platform.

Included tools:

| No. | Tool | MVP role |
|---:|---|---|
| 34 | Threat Feed Aggregator | Import, deduplicate and version threat feeds |
| 35 | YARA Rule Manager | File detection rules |
| 36 | Sigma Rule Manager | Log detection rules |
| 37 | MITRE ATT&CK Mapper | Map findings/rules to tactics, techniques and data sources |
| 50 | Signed Update and Rule Distribution System | Signed rule/feed update path |
| 59 | Alert Exception / Suppression Manager | Manage rule exclusions, suppressions, review dates and false-positive governance |

MVP exit criteria:

- Rules and feeds can be imported, validated and versioned.
- Rules map to severity and ATT&CK metadata.
- Feed/rule changes are auditable.
- Future update packages can be signed and verified.
- Exceptions and suppressions are time-bound and auditable.

---

## Function 10 — SOC Lite, Case Management and Reporting

Purpose: Turn findings into manageable investigations, reports and risk tracking.

Included tools:

| No. | Tool | MVP role |
|---:|---|---|
| 38 | Case Management | Case creation, status, affected assets, notes, evidence |
| 39 | Mini-SIEM / Log Search | Search imported endpoint logs and evidence |
| 40 | Alert Correlation Engine | Correlate findings across AV, IOC, network, identity and email |
| 41 | Security Health Score | Overall and category scoring |
| 42 | Remediation Guidance Wizard | Actionable fix guidance |
| 43 | Risk Register Export | Business-friendly risk export |
| 48 | Report Signing / Integrity Checker | Report/evidence integrity checks |
| 49 | Role-Based Analyst/Home User Modes | Different views for technical and non-technical users |
| 51 | Asset Criticality / Ownership Register | Add owner, importance and business context to cases/risks |
| 52 | Evidence Chain-of-Custody Log | Preserve evidence provenance and access history |
| 59 | Alert Exception / Suppression Manager | Track approved exceptions and false-positive decisions |
| 60 | Guided Response Playbooks | Guided response workflows linked to case type |

MVP exit criteria:

- User can create a case from a finding or investigation.
- Evidence and reports are linked to the case.
- Logs/evidence can be searched.
- Report output is readable, exportable and integrity-aware.
- Chain-of-custody, asset ownership, exceptions and playbooks are linked to case workflow.

---

## Function 11 — Developer, Cloud and Supply Chain Security

Purpose: Extend the suite to developer and cloud/SaaS environments.

Included tools:

| No. | Tool | MVP role |
|---:|---|---|
| 44 | Secrets Scanner | Detect secrets in files/repos/configs |
| 45 | Git/Repo Security Scanner | Repo posture, branch protection, dependency/config risks |
| 46 | Container Image Scanner | Image/package vulnerability and secret checks |
| 47 | Cloud/SaaS Audit Importer | Cloud and SaaS posture import |
| 48 | Report Signing / Integrity Checker | Integrity for exported reports/evidence |
| 50 | Signed Update and Rule Distribution System | Secure platform/rule update path |
| 51 | Asset Criticality / Ownership Register | Link developer/cloud assets to owners and business impact |

MVP exit criteria:

- Start with local secrets scanning before cloud/container work.
- Developer/cloud findings feed the same case/report/risk model.
- No write/destructive cloud actions in MVP.
- Developer/cloud risks can be linked to owners and asset criticality.

---

# Formal Roadmap Extension — Tools 51–60

The following modules are now formally added to the Sentinel/Fenrir roadmap. They should be treated as professional hardening, evidence, usability and response extensions. They are valuable, but should be built after the core investigation, AV, inventory, patching, CVE and baseline modules are stable.

| No. | Tool | Purpose | Primary function |
|---:|---|---|---|
| 51 | Asset Criticality / Ownership Register | Track asset owner, business importance, device role, department, data sensitivity and priority. | SOC Lite / Device Health |
| 52 | Evidence Chain-of-Custody Log | Record evidence collection, exports, hashes, user actions, timestamps and handoff history. | Endpoint Investigation / SOC Lite |
| 53 | Quarantine Review / Restore Manager | Review quarantined files, restore safely, permanently remove or attach to cases. | Detect and Scan |
| 54 | Certificate and Trust Store Auditor | Check suspicious root certificates, expired certs, weak trust and TLS interception risks. | Device Health / Email / Browser |
| 55 | Hosts / Proxy / VPN Tamper Checker | Detect hosts file changes, malicious proxy settings, suspicious DNS/VPN/DoH configuration. | Network and DNS Defence |
| 56 | SMB Share Permission Auditor | Review exposed shares, weak permissions, anonymous access and ransomware spread risk. | Vulnerability / Network / Ransomware Resilience |
| 57 | Remote Access Tool Detector | Detect legitimate remote tools that may indicate compromise or unmanaged access. | Investigation / Identity / Exposure |
| 58 | Service Path and Permission Auditor | Detect unquoted service paths, writable service binaries and risky service permissions. | Persistence / Baseline / Identity |
| 59 | Alert Exception / Suppression Manager | Manage false positives, approved exclusions, expiry dates, owners and audit records safely. | Detection Engineering / SOC Lite |
| 60 | Guided Response Playbooks | Step-by-step response flows for phishing, malware, ransomware, suspicious login and vulnerable software. | SOC Lite / Remediation |

## 51 — Asset Criticality / Ownership Register

Useful fields:

```text
Asset owner
Business function
Criticality
Device type
Department
Data sensitivity
Internet-facing status
Last seen
Linked cases
Linked risks
```

Why it matters:

- A vulnerable domain controller, payroll laptop and test VM should not be prioritised the same way.
- This improves triage, risk scoring, reporting and risk register output.

Exit expectation:

- Every important asset can be linked to an owner, criticality level and business impact rating.

## 52 — Evidence Chain-of-Custody Log

Record:

```text
Who collected evidence
When it was collected
Which endpoint it came from
Bundle hash
Export hash
Who downloaded/exported it
Whether evidence was changed
Case association
```

Why it matters:

- Makes evidence handoff more credible.
- Supports analyst, business, insurer, solicitor or law-enforcement handoff.

Exit expectation:

- Evidence collection and export events are timestamped, hashed and linked to case records.

## 53 — Quarantine Review / Restore Manager

Show:

```text
Original file path
Quarantine path
SHA256
Detection reason
Time quarantined
Related scan
Related case
Restore option
Permanent delete option
Audit trail
```

Why it matters:

- AV quarantine without review/restore is incomplete and risky.
- Restore must be deliberate, audited and case-aware.

Exit expectation:

- A quarantined file can be reviewed, restored or permanently removed with an audit event.

## 54 — Certificate and Trust Store Auditor

Detect:

```text
Suspicious root certificates
Newly added certificates
Expired or weak certificates
User-installed trusted roots
Browser certificate changes
TLS interception/proxy certificates
```

Why it matters:

- Helps catch adware, malware, browser hijacking and unsafe TLS interception.

Exit expectation:

- The app can flag suspicious trust-store changes and explain why they matter.

## 55 — Hosts / Proxy / VPN Tamper Checker

Check:

```text
Hosts file entries
Malicious domain redirects
Proxy enabled unexpectedly
WPAD configuration
Suspicious PAC files
VPN profiles
DNS server changes
DoH settings where possible
```

Why it matters:

- Malware and adware often tamper with local name resolution or traffic routing.

Exit expectation:

- Suspicious hosts/proxy/VPN/DNS tampering is shown as a readable finding with remediation.

## 56 — SMB Share Permission Auditor

Check:

```text
Open shares
Anonymous access
Everyone/Users write permissions
Admin shares
Mapped drives
Network drive exposure
Share paths
Sensitive folder exposure
```

Why it matters:

- Overly permissive shares increase ransomware spread and data exposure risk.

Exit expectation:

- The app can identify risky shares and explain what permission changes are recommended.

## 57 — Remote Access Tool Detector

Detect:

```text
AnyDesk
TeamViewer
ScreenConnect / ConnectWise Control
Atera
Splashtop
RustDesk
Chrome Remote Desktop
LogMeIn
GoToAssist
Radmin
UltraVNC/TightVNC
```

Output should show whether the tool is:

```text
installed
running
recently used
externally listening
auto-starting
linked to persistence
```

Why it matters:

- Legitimate remote tools are commonly abused during real incidents.

Exit expectation:

- The app can identify known remote access tools and flag unmanaged or suspicious usage.

## 58 — Service Path and Permission Auditor

Detect:

```text
Unquoted service paths
Service binary in writable directory
Weak service permissions
Auto-start services with unknown publisher
Services running as LocalSystem from risky paths
```

Why it matters:

- Weak service configuration can support persistence or privilege escalation.

Exit expectation:

- Risky service paths and permissions appear in baseline and persistence findings.

## 59 — Alert Exception / Suppression Manager

Track:

```text
Reason
Scope
Expiry date
Approver/user
Rule affected
Asset affected
Audit record
Review date
```

Why it matters:

- As detections grow, false positives need controlled suppression rather than permanent blind spots.

Exit expectation:

- Exceptions are scoped, time-limited and auditable.

## 60 — Guided Response Playbooks

Example playbooks:

```text
Suspicious file found
Possible phishing email
Ransomware-like behaviour
Unknown remote access tool
Critical CVE found
Suspicious admin account
RDP exposed
Backup not configured
```

Each playbook should provide:

```text
What happened
Immediate action
Evidence to collect
Containment steps
Remediation steps
Verification steps
Report/export option
```

Why it matters:

- This makes the platform practical for home users, SMBs and junior analysts.

Exit expectation:

- A finding can launch a guided, safe response workflow with evidence and report links.

---

# Coverage Check Against The 60-Tool Roadmap

| No. | Tool | MVP function |
|---:|---|---|
| 1 | AV Scanner | Detect and Scan |
| 2 | IOC Scanner | Detect and Scan |
| 3 | Phishing Email Analyser | Email and Microsoft 365 Security |
| 4 | Endpoint Investigation Collector | Endpoint Investigation |
| 5 | Persistence Scanner | Endpoint Investigation |
| 6 | Process Tree Viewer | Endpoint Investigation |
| 7 | Suspicious Command Line Analyser | Endpoint Investigation |
| 8 | Network Connection Monitor | Endpoint Investigation / Network and DNS Defence |
| 9 | DNS Monitor | Network and DNS Defence |
| 10 | DNS Protection Tool | Network and DNS Defence |
| 11 | Windows Event Log Collector | Endpoint Investigation / Identity Monitoring |
| 12 | PowerShell Activity Analyser | Endpoint Investigation |
| 13 | Timeline Builder | Endpoint Investigation / SOC Lite |
| 14 | Evidence Bundle Exporter | Endpoint Investigation / SOC Lite |
| 15 | Incident Report Generator | Endpoint Investigation / SOC Lite |
| 16 | Ransomware Behaviour Guard | Ransomware and Removable Media Resilience |
| 17 | Backup Readiness Checker | Device Health / Ransomware Resilience |
| 18 | Windows Security Baseline Checker | Device Health and Hardening |
| 19 | Patch Status Checker | Device Health / Vulnerability Management |
| 20 | Installed Software Inventory | Device Health / Vulnerability Management |
| 21 | CVE / KEV Vulnerability Matcher | Vulnerability and Exposure Management |
| 22 | Browser Security Checker | Device Health and Hardening |
| 23 | USB Guard | Ransomware and Removable Media Resilience |
| 24 | Firewall Rule Auditor | Network and DNS Defence / Device Health |
| 25 | Local Account/Admin Audit | Identity Monitoring |
| 26 | Logon Event Analyser | Identity Monitoring |
| 27 | Privilege Change Monitor | Identity Monitoring |
| 28 | Mailbox Rule Checker | Email and Microsoft 365 Security |
| 29 | Email Header Analyser | Email and Microsoft 365 Security |
| 30 | Attachment Risk Analyser | Email and Microsoft 365 Security / Detect and Scan |
| 31 | URL Redirect Tracer | Email and Microsoft 365 Security |
| 32 | OAuth App Permission Checker | Email and Microsoft 365 Security |
| 33 | Microsoft 365 Security Checker | Email and Microsoft 365 Security |
| 34 | Threat Feed Aggregator | Threat Intelligence and Detection Engineering |
| 35 | YARA Rule Manager | Threat Intelligence and Detection Engineering |
| 36 | Sigma Rule Manager | Threat Intelligence and Detection Engineering |
| 37 | MITRE ATT&CK Mapper | Threat Intelligence and Detection Engineering |
| 38 | Case Management | SOC Lite |
| 39 | Mini-SIEM / Log Search | SOC Lite |
| 40 | Alert Correlation Engine | SOC Lite |
| 41 | Security Health Score | SOC Lite / Device Health |
| 42 | Remediation Guidance Wizard | SOC Lite / Device Health |
| 43 | Risk Register Export | SOC Lite / Vulnerability Management |
| 44 | Secrets Scanner | Developer, Cloud and Supply Chain Security |
| 45 | Git/Repo Security Scanner | Developer, Cloud and Supply Chain Security |
| 46 | Container Image Scanner | Developer, Cloud and Supply Chain Security |
| 47 | Cloud/SaaS Audit Importer | Developer, Cloud and Supply Chain Security |
| 48 | Report Signing / Integrity Checker | SOC Lite / Integrity |
| 49 | Role-Based Analyst/Home User Modes | SOC Lite / UX Modes |
| 50 | Signed Update and Rule Distribution System | Threat Intelligence / Integrity |
| 51 | Asset Criticality / Ownership Register | SOC Lite / Device Health / Risk Management |
| 52 | Evidence Chain-of-Custody Log | Endpoint Investigation / SOC Lite / Integrity |
| 53 | Quarantine Review / Restore Manager | Detect and Scan / AV Scanner |
| 54 | Certificate and Trust Store Auditor | Device Health / Browser / Email |
| 55 | Hosts / Proxy / VPN Tamper Checker | Network and DNS Defence / Baseline |
| 56 | SMB Share Permission Auditor | Network / Identity / Ransomware Resilience |
| 57 | Remote Access Tool Detector | Investigation / Exposure / Identity |
| 58 | Service Path and Permission Auditor | Persistence / Baseline / Identity |
| 59 | Alert Exception / Suppression Manager | SOC Lite / Detection Engineering |
| 60 | Guided Response Playbooks | SOC Lite / Remediation Guidance |

All 60 tools are represented.

---

# Tools Not Recommended For The MVP

The following are intentionally not added to the formal MVP roadmap yet:

```text
Full malware sandbox
Kernel-level EDR driver
Automated destructive remediation
Full packet capture IDS
Cloud multi-tenant SOC platform
Dark web monitoring
OSINT person/company monitoring
Exploit validation
Password cracking
Attack simulation
```

Reason:

- They increase risk, complexity, liability or scope too early.
- They should only be considered after the agent, native AV, investigation, inventory, patching, CVE and baseline workflows are stable.

---

# MVP Build Order By Function

## MVP 1 — Core detection and investigation

- AV Scanner
- IOC Scanner
- Endpoint Investigation Collector
- Persistence Scanner
- Process Tree Viewer
- Suspicious Command Line Analyser
- Network Connection Monitor
- Timeline Builder
- Evidence Bundle Exporter
- Incident Report Generator
- Evidence Chain-of-Custody Log
- Quarantine Review / Restore Manager

Exit expectation:

- The app can scan, investigate, preserve evidence and report on suspicious endpoint activity.

## MVP 2 — Device health and vulnerability

- Installed Software Inventory
- Patch Status Checker
- CVE / KEV Vulnerability Matcher
- Windows Security Baseline Checker
- Firewall Rule Auditor
- Browser Security Checker
- Backup Readiness Checker
- Security Health Score
- Asset Criticality / Ownership Register
- Certificate and Trust Store Auditor
- Hosts / Proxy / VPN Tamper Checker
- Service Path and Permission Auditor

Exit expectation:

- The app can tell whether a device is secure, updated, backed up, vulnerable and business-critical.

## MVP 3 — DNS, USB and ransomware resilience

- DNS Monitor
- DNS Protection Tool
- USB Guard
- Ransomware Behaviour Guard
- SMB Share Permission Auditor
- Guided Response Playbooks for ransomware/USB/DNS incidents

Exit expectation:

- The app can detect risky DNS, USB, SMB and ransomware-like behaviour safely.

## MVP 4 — Identity and local privilege

- Local Account/Admin Audit
- Logon Event Analyser
- Privilege Change Monitor
- Remote Access Tool Detector
- Service Path and Permission Auditor

Exit expectation:

- The app can answer who logged in, who has admin rights, whether privileges changed and whether remote tools are suspicious.

## MVP 5 — Email and Microsoft 365

- Phishing Email Analyser
- Email Header Analyser
- URL Redirect Tracer
- Attachment Risk Analyser
- Mailbox Rule Checker
- OAuth App Permission Checker
- Microsoft 365 Security Checker
- Certificate and Trust Store Auditor
- Guided Response Playbooks for phishing/mailbox compromise

Exit expectation:

- The app can investigate suspicious email, attachments, URLs, mailbox rules, OAuth grants and M365 posture.

## MVP 6 — Detection engineering

- Threat Feed Aggregator
- YARA Rule Manager
- Sigma Rule Manager
- MITRE ATT&CK Mapper
- Alert Exception / Suppression Manager
- Signed Update and Rule Distribution System

Exit expectation:

- The app can manage feeds, rules, exceptions and updates safely with versioning and integrity.

## MVP 7 — SOC Lite

- Case Management
- Mini-SIEM / Log Search
- Alert Correlation Engine
- Remediation Guidance Wizard
- Risk Register Export
- Report Signing / Integrity Checker
- Role-Based Analyst/Home User Modes
- Evidence Chain-of-Custody Log
- Asset Criticality / Ownership Register
- Guided Response Playbooks

Exit expectation:

- The app can manage the full lifecycle from alert to case, report, remediation, evidence integrity and residual risk.

## MVP 8 — Developer, cloud and supply chain

- Secrets Scanner
- Git/Repo Security Scanner
- Container Image Scanner
- Cloud/SaaS Audit Importer
- Asset Criticality / Ownership Register

Exit expectation:

- The app can extend beyond endpoints into developer and cloud/SaaS risk.

---

# Priority Guidance

The 51–60 extensions are formally part of the roadmap, but they should not distract from the immediate implementation order.

Build first:

```text
Native AV MVP
Agent-driven investigation
Installed Software Inventory
Patch Status Checker
CVE / KEV Matcher
Windows Security Baseline Checker
```

Then build the 51–60 extensions where they naturally support those core workflows.
