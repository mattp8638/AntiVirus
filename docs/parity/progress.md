# Parity progress

Maintained across sessions. Each catalogue entry's state lives in `catalogue.csv`; this file records what moved and what comes next.

Baseline of the review: `main` at `790e364`. Work branch: `claude/jolly-goodall-5kpl2t`.

## Catalogue totals (178 entries)

| State | Count |
|---|---|
| verified | 6 (FIX-01 to FIX-05, FIX-08) |
| implemented-unverified | 14 (FIX-07, AGT-04, CORE-03, FLOW-01/02/04/09 and 7 requirements the brief marked U) |
| partial | 119 |
| missing | 38 |
| externally-blocked | 1 (FIX-06) |

Overall parity: **not passed**. MVP: **not yet declared**.

## Reports and branding (roadmap 0-30 days)

Branded PDF and HTML reports (executive, monthly, quarterly business review, vulnerability) built from one structured
document, kept as sent, and emailed on a schedule; MSP branding of the console, sign-in page, reports and Windows agent
window. VULN-20 moves to `partial`; VULN-21 and M365-31 record the progress. `docs/REPORTS_AND_BRANDING.md`,
`tests/test_branding_reports.py`.

## 2026-11-08 re-assessment

21 entries recorded as missing were built in later batches and are now `partial` or `implemented-unverified`, each
citing its code and tests in `catalogue.csv`: VULN-14 (PII discovery), VULN-18 (dark web), GRC-06 (supplier risk),
FLOW-01/02/04/05/08/09, M365-02 (GDAP), M365-12/13 (Conditional Access and standards), M365-18 to 21 (Exchange),
M365-22 to 24 (Intune), M365-25/26 (Teams, SharePoint). No entry became `verified`: that still needs the acceptance
scenario run against real agents or tenants. AGT-02 notes Azure Trusted Signing.

## Completed

| ID | Commit | Evidence |
|---|---|---|
| FIX-01 | `c6de2d9` | Lab/production build profiles. [Smoke run 40590036336](https://github.com/mattp8638/AntiVirus/actions/runs/40590036336) passed: lab build/start, HTTP smoke, production refuses to build without a certificate, packaged-agent checks. |
| FIX-02 | `378c78d` | Coverage-aware OSV verification; `test_scan_integrity.py` (12 cases) |
| FIX-03 | `2eb277a` | Server-side revocable sessions, remote viewer cut-off; `test_sessions.py` |
| FIX-04 | `d07687c` | Unresolved exposure counted regardless of workflow state; `test_exposure_counts.py` |
| FIX-05 | `d87ca95` | Compare-and-swap audit chain head; `test_audit_concurrency.py` (failure reproduced on PostgreSQL 16 before the fix) |
| FIX-08 | `8fda3b7` | Framework revisions: reworded requirements need review, dry-run diff, snapshots, historical export; `test_grc_revisions.py`. Verified in CI ([run 78](https://github.com/mattp8638/AntiVirus/actions/runs/40649462515)). |
| (owner request) | `473eb80` | Remote desktop Ctrl+Alt+Del is now sent by the agent service. Cross-compiled only; not yet tested on a real server (RMM-09/RMM-10). |
| FIX-07 / AGT-03 / AGT-04 | (this milestone) | Signed Linux/macOS agent releases; staged rollouts with automatic pause. See `release_test.go` and `test_rollouts.py`. |
| CORE-01 (API) | (this milestone) | Cross-customer matrix over every API operation. Fixed: customer users could change MSP-wide PSA settings (including the inbound email token); a read-only viewer could edit tickets; non-staff could set staff ticket fields; foreign board/device IDs were accepted on tickets; the portal matched contacts across customers. |
| CORE-04 (API credentials) | (this milestone) | Scoped service identities for integrations: expiry, rotation, revocation and usage tracking; `test_api_credentials.py`. Device key rotation is still open. |
| CORE-06 (audit assurance) | (this milestone) | Checkpoints published outside the database, classified verification, redacted verifiable export, retention to an anchor, legal hold; `test_audit_assurance.py`. |
| CORE-02 (roles) | (this batch) | Custom roles, customer assignments, finer powers. Fixed: a tenant admin could promote anyone, including themselves, to msp_admin. `test_roles.py`. |
| CORE-14 (production mode) | (this batch) | Unsafe production settings stop the server from starting; `/ready`; readiness warnings for platform admins. `test_production_mode.py`. |
| CORE-14 (go-live check) | (this batch) | `deploy/preflight.sh` checks a deployment before customers rely on it, without printing secrets; README step 6. `test_preflight.py`; runs against the full stack in the Phase 2 smoke. |
| RMM-13 (owner request) | `ddca219` | Network topology maps physical connections: switch ports and uplinks over read-only SNMP from Linux/macOS probes. `test_topology_switches.py`, `snmp_test.go`. Not yet run against a real switch. |
| CORE-08 (alerts and metrics) | (this batch) | Degraded/recovered alerts to MSP webhooks from the web process, artifact-storage health, Prometheus `/metrics` behind a token. `test_health_alerts.py`. |
| CORE-04 (device keys) | (this batch) | Two-step device key rotation (on demand and by age) in the cloud and the Go, Windows and Android agents. `test_device_key_rotation.py`, `keyrotation_test.go`, acceptance `key_rotation`. |
| D-06 (owner decision) | (this batch) | Go live without a Windows driver; Defender provides pre-execution blocking. Protection health shows it per Windows device and warns where there is none. `test_pre_execution.py`. |
| AGT-05 (proxy, offline) | (this batch) | Installer `--proxy` for Linux/macOS (kept on repair), Windows automatic WinHTTP proxy for every control-plane call, Go agent offline telemetry spool across restarts. |
| CORE-01 (background jobs) | (this batch) | Every scheduled and hourly job run over two customers' data, including a hostile cross-customer schedule: nothing crosses. `test_background_scope.py` (fails when the target filter is broken). |
| RMM-09 (owner request) | (this batch) | Backstage hidden SYSTEM desktop on Windows (session 0) with a tools launcher; nothing reaches the user's session. Self-test command; Windows CI acceptance check passes on Windows Server 2025 (AT-34, [run 41414209548](https://github.com/mattp8638/AntiVirus/actions/runs/41414209548)). |
| CORE-15 (approvals) | (this batch) | Optional two-person approval bound to the exact request and its devices; `test_approvals.py`. |
| CI | `b5cf672` | Removed the placeholder signing files that the merge brought back. [Run 78](https://github.com/mattp8638/AntiVirus/actions/runs/40649462515) passed, which also verifies FIX-08 in CI. |
| Agent health | `bc4455e` | Every agent's build against the server's, why it is not updating (policy, paused rollout, ring), failures reported in 7 days by component until it recovers, failed commands; paused rollouts are shown. |
| Releases | `51834a6` | Servers follow release tags (stable) or candidates (staging) or a branch; release workflow tests the tag and publishes notes. |
| False positives (CI) | `37445aa` | Clean-software suite scans 400 installed files on Windows CI; it found a Python wheel quarantined at 99 and four reported scripts; fixed (package archives, compressed bytes, admin-only folders report-only on heuristics). Passes with no quarantine. |
| FLOW-02 | `6ce7695` | Vulnerability -> ticket (joined per CVE) -> fix (optionally approved) -> rescan -> resolved, with evidence; failed or unconfirmed fixes reopen. `test_flow_vulnerability.py`. |
| FLOW-04 | `6ce7695` | Monitor tickets close only after recovery and a successful self-heal; recurrences open a new ticket; remediation-package tickets resolve when the check passes. |
| FLOW-01 | `6626608` | Onboarding checklist per customer from real state, with real failures; duplicate customers refused. `test_onboarding.py`. |
| FLOW-05 | `6626608` | Leavers: devices to collect, vault credentials flagged for rotation, billing effect; mailbox hand-over (Exchange). |
| FLOW-09 | `3873aa1` | Customer workspace: tickets, devices needing attention, alerts, incidents, urgent vulnerabilities, M365, backups, onboarding, recent actions. `test_workspace.py`. |
| M365 batch 3 | `7e5182c`, `3a6bf02` | Exchange administration and 11 directory/Exchange security standards with drift. Awaiting owner test (test plan sections 10 and 11). |
| Defender control | `6eb9508`, `d9783e4` | Fenrir is the source of truth for Defender: exclusions both ways (optionally authoritative), scanning, schedules, threat actions, UI lockdown, CFA folders/apps, allowed threats, device actions. Verified on Windows Server in CI (schedule bug found there and fixed). |
| Sign-in protection | `bb77f31` | Impossible travel, new country and password-guessing success from stored sign-in logs, with a playbook (sign out, block, ticket, email). Test plan 12. |
| M365 batches 5, 7, 8 | `d9d4392`, `2993eba`, `1cb507a` | Intune (devices, actions, BitLocker/LAPS, policies, apps, Autopilot), reports with schedules, email security standards, Teams/SharePoint/OneDrive and sharing standards, OneDrive hand-over. Test plan 13-16. |
| Detection (found in CI) | `5f6dc90` | Firefox was quarantined as BlackCat on the Windows CI runner: signature "chain" rules fired on any one marker. Rules now take an optional match count (ransomware chains need every marker), and the installer ships the trusted-publisher, known-good and observe-only lists that only a build tree had. `SignatureRuleMatchTests.ps1` in Windows CI. |

## Microsoft 365 phase (owner request, 2026-11-02)

Goal: one place for Microsoft 365 administration, matching what MSPs use CIPP and AdminDroid for, joined up with Fenrir's PSA, CRM, SOC and
GRC. Delivered in batches; one PR each.

**Exit requirement for every batch:** Claude provides step-by-step test instructions (`docs/M365_TEST_PLAN.md`) and the owner tests
them on their own tenant. A batch is not done until the owner reports the results and any failures are fixed. Simulated-tenant tests
are required but do not count as the exit.

| Batch | Scope | State |
|---|---|---|
| 1 | Tenant workspace: cross-tenant overview, per-tenant workspace (organisation, domains, admins, service health, inactive licensed users), per-feature permission check and Update permissions, background sync, sign-in and audit log store (730 days, search, CSV export) | Built, mock-tested; **awaiting owner test** (AT-35) |
| 2 | Identity: password reset, MFA reset, Temporary Access Pass, temporary admin roles with automatic removal, manager, guests, new groups; resumable new-starter, offboarding and bulk CSV import with PSA ticket and CRM contact | Built, mock-tested; **awaiting owner test** (AT-35) |
| 2b | Hybrid identity (owner request): users synced from AD by Entra Connect are offboarded and created on the domain controller through the Fenrir agent (disable, random password, AD groups, leavers OU, address book, sync; create with OU, groups and manager), then finished in Microsoft 365; waiting steps continue in the background | Built, mock-tested, AD script tested in Windows CI; **awaiting owner test** (AT-37) |
| 3 | Exchange: mailboxes, shared mailboxes, permissions, forwarding, out-of-office, aliases, distribution lists, mail rules, quarantine, message trace; mailbox steps in offboarding | Built (Exchange Online admin endpoint, allowlisted cmdlets), mock-tested; **awaiting owner test** (test plan section 10) |
| 4 | Security: Conditional Access templates and named locations, compromised-account check, SPF/DKIM/DMARC check, alert rules on audit events feeding the SOC | Planned |
| 5 | Intune: device actions, BitLocker and LAPS keys, app deployment, Autopilot | Planned |
| 6 | Standards: from 4 to about 60, templates, tenant groups, drift and exceptions | Planned |
| 7 | Reports (AdminDroid): inactive users, licence waste, external sharing, mailbox sizes, Teams/SharePoint usage, scheduled email reports | Planned |
| 8 | Teams, SharePoint and OneDrive | Planned |

## In progress

- Phase 1 (CORE and AGT).
- Microsoft 365 phase, batches 1 and 2: awaiting the owner's test on their tenant.

## Externally blocked

- **FIX-06 / AV-02:** Windows minifilter. The driver source was removed by the owner. Needs an EV certificate, a Partner Center account and HLK. See `decisions.md` D-06.
- **Live Microsoft 365 verification (AT-14 to AT-17):** needs isolated test tenants.
- The full list is in `decisions.md`, "Other external dependencies".

## Failed / known failing

- None known. AT-13 now passes in automated tests.

## Next actions (Phase 1, in dependency order)

1. CORE-01 remainder: guessed file paths.
2. CORE-07 remainder (fair capacity, poison jobs) and the AGT-05 remainder (NTLM proxies, command results across restarts).
3. CORE-13: load at 10,000 endpoints on declared hardware (AT-27).
4. AGT-01, AGT-02, AGT-06 to AGT-10: installers on clean VMs, final-package signature, identity, support matrix, SBOM, capability reporting.

Needs the owner: a lab acceptance run with a managed switch (`docs/ACCEPTANCE_LAB.md`), the code-signing certificate on the server and a Microsoft 365 test tenant. (The Windows driver decision is made: D-06, option 1.)
