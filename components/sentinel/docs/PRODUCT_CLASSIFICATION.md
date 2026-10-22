# Sentinel / Fenrir Product Classification

## Classification

Sentinel / Fenrir should be classified as a **defensive security operations and endpoint resilience platform**.

It is not simply an antivirus.
It is not just a Blue Team toolkit.
It is not a SIEM on its own.
It is not a random collection of cyber tools.

The closest product category is:

```text
Endpoint-centred defensive security platform for protection, investigation, posture management, vulnerability prioritisation, evidence handling and guided remediation.
```

A shorter public description would be:

```text
A practical defensive security platform for endpoint protection, investigation, vulnerability management and reporting.
```

## Why it became broader than “Blue Team”

The roadmap went beyond a pure Blue Team investigation suite because it started to include:

- AV scanning and quarantine
- endpoint agent tasking
- vulnerability and patch management
- security baseline checking
- backup readiness
- browser security
- USB controls
- DNS protection
- Microsoft 365 checks
- case management
- reporting
- risk register output
- developer and supply-chain checks

Those are not all “Blue Team tools” in the narrow sense. They cross several defensive product categories.

## More accurate category labels

| Area | Correct classification |
|---|---|
| AV Scanner, IOC Scanner, quarantine | Endpoint protection / malware defence |
| Investigator, persistence, processes, logs, timeline | Incident response / endpoint investigation |
| Baseline, patching, backups, browser, firewall | Security posture management / hardening |
| CVE/KEV matcher, exposure, risk register | Vulnerability and exposure management |
| DNS, network monitor, topology | Network defence / exposure visibility |
| Local accounts, logons, privilege changes | Identity security / account monitoring |
| Phishing, mailbox, OAuth, M365 | Email and cloud identity security |
| Feeds, YARA, Sigma, ATT&CK | Detection engineering / threat intelligence |
| Cases, reports, evidence, chain of custody | SOC workflow / incident management |
| Secrets, repo, containers, cloud imports | Developer and supply-chain security |

## Product boundary

Sentinel should keep a clear centre of gravity:

```text
Endpoint-first defensive security.
```

That means modules should primarily support one of these outcomes:

1. Protect the endpoint.
2. Investigate endpoint or user activity.
3. Improve device security posture.
4. Prioritise vulnerabilities and exposure.
5. Produce useful evidence, reports and remediation actions.

## What the app should not become

Sentinel should not become:

- a generic cyber toolbox
- an offensive security toolkit
- a full cloud CNAPP platform
- a full enterprise SIEM replacement
- a full SOAR product
- a general IT management suite
- a developer platform with security features bolted on

Those areas may have useful integrations later, but they should not define the product.

## Corrected product model

The product should be organised as four connected layers:

### 1. Protection layer

Purpose: prevent and detect immediate threats.

Includes:

- native AV engine
- IOC scanner
- quarantine manager
- ransomware behaviour guard
- DNS protection
- USB guard

### 2. Investigation layer

Purpose: answer what happened and collect evidence.

Includes:

- endpoint investigation collector
- persistence scanner
- process tree viewer
- suspicious command line analyser
- network connection monitor
- event log collector
- PowerShell analyser
- timeline builder
- evidence bundle exporter

### 3. Posture and exposure layer

Purpose: reduce future risk.

Includes:

- software inventory
- patch status
- CVE/KEV matcher
- Windows security baseline
- firewall rule auditor
- backup readiness
- browser security
- local account/admin audit
- trust/proxy/share checks

### 4. Workflow and reporting layer

Purpose: turn technical findings into action.

Includes:

- case management
- incident reports
- remediation guidance
- risk register
- evidence chain of custody
- playbooks
- role-based views

## Reframed roadmap decision

The full 60-tool list can remain as a long-term capability map, but the actual product roadmap should be narrowed to staged product outcomes.

### MVP 1 — Protection and investigation

- Native AV Scanner
- IOC Scanner
- Agent-driven investigation
- Persistence scanner
- Process/network evidence
- Timeline
- Evidence bundle
- Incident report

### MVP 2 — Posture and vulnerability

- Installed software inventory
- Patch status checker
- CVE/KEV matcher
- Windows security baseline
- Firewall audit
- Backup readiness
- Browser security

### MVP 3 — Identity, email and resilience

- Local account/admin audit
- Logon analyser
- Privilege change monitor
- Phishing email analyser
- Header/URL/attachment analysis
- Ransomware guard
- USB guard
- DNS monitor/protection

### MVP 4 — SOC workflow

- Case management
- Mini log search
- Alert correlation
- Chain of custody
- Remediation playbooks
- Risk register
- Report signing

### MVP 5 — Advanced integrations

- M365 security checker
- OAuth checker
- threat feed automation
- Sigma manager
- signed rule distribution
- developer/cloud/supply-chain extensions

## Plain-English product statement

Sentinel / Fenrir is best described as:

```text
A defensive endpoint security and investigation platform that combines native scanning, evidence collection, vulnerability prioritisation, posture checks and reportable case workflows.
```

That is broader than traditional Blue Team tooling, but still coherent if every feature supports the endpoint-first defensive workflow.
