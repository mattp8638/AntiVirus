# Sentinel / Fenrir Product Coherence Guardrails

This document exists to prevent Sentinel from becoming a random collection of Blue Team tools.

Sentinel should be treated as a focused defensive security application. Every module must complement the core workflow and improve the product's ability to protect, investigate, harden, prioritise, report or guide remediation.

## Core product identity

Sentinel / Fenrir is a defensive endpoint-centred Blue Team platform.

It should help users answer:

1. Is this device protected?
2. Is this device vulnerable or misconfigured?
3. Is there evidence of compromise?
4. What happened and when?
5. What should be fixed first?
6. Can the evidence be turned into a case, report or remediation plan?

If a proposed tool does not improve one of those answers, it should not be built.

## Core workflow

The platform should follow this workflow:

```text
Protect → Detect → Investigate → Prioritise → Remediate → Report → Improve posture
```

Every tool should fit into one or more of these stages.

## Product pillars

Only build modules that support one of these pillars:

| Pillar | Purpose |
|---|---|
| Protection | AV scanning, IOC checks, ransomware guard, DNS/USB protection |
| Investigation | Endpoint evidence, processes, persistence, logs, network, timeline |
| Posture | Baseline, patching, software inventory, backups, browser security |
| Vulnerability | CVE/KEV matching, exposure, risk register |
| Identity | Local users, logons, privilege changes, mailbox/cloud identity checks |
| Intelligence | Feeds, rules, ATT&CK mapping, detection content |
| Case and Reporting | Cases, reports, chain of custody, playbooks and remediation guidance |

A module outside these pillars should not be accepted into the roadmap.

## Build gating questions

Before building any tool, answer these questions:

1. Which existing Sentinel workflow does it improve?
2. Which existing data does it reuse or enrich?
3. Which finding, score, case, report or remediation output does it feed?
4. Does it reduce risk, improve investigation quality or improve user actionability?
5. Can it be built safely without increasing offensive or destructive capability?
6. Can it be shown in the GUI without becoming another disconnected tab?

If the answer is weak, defer or reject the module.

## Menu discipline

The UI must not expose 60 top-level tools.

The UI should expose a few product areas:

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

However, this is only a navigation model. It does not mean every submenu should be built immediately.

## Practical MVP scope

The practical MVP should focus on these connected capabilities first:

1. Native AV scanning
2. IOC scanning
3. Agent-driven endpoint investigation
4. Persistence/process/network evidence
5. Timeline and evidence bundle
6. Installed software inventory
7. Patch status
8. CVE/KEV matching
9. Windows security baseline
10. Case/report output

These features directly reinforce each other.

## Defer list

The following must not distract from the MVP:

- Full SIEM correlation engine
- Full Microsoft 365 integration
- Container image scanning
- Cloud posture imports
- Developer supply-chain scanning
- Advanced DNS blocking
- Kernel-level EDR work
- Full sandboxing

These may remain in the long-term roadmap but should not be implemented until the core endpoint MVP is stable.

## Acceptance rule for each module

A module is acceptable only if it has:

- a clear user problem
- a clear Sentinel workflow fit
- a clear input source
- a clear output model
- findings with severity and evidence
- recommended action
- case/report integration path
- no raw JSON UI output

## Product direction statement

Sentinel should not become “lots of Blue Team tools”.

Sentinel should become a coherent defensive application where each capability supports the same operational loop:

```text
Find risk → collect evidence → explain impact → prioritise action → report clearly
```

That is the product boundary.
