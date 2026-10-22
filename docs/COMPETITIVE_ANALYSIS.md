# Competitive feature map

**Method.** This is a clean-room comparison built from each vendor's public product documentation, datasheets and marketing material. No vendor software was decompiled, disassembled or reverse engineered. Doing that would breach their licence terms, and copying their code or signatures would expose Fenrir to copyright and trade-secret claims. What we can legitimately learn is *which capabilities customers expect*. This map tracks that and Fenrir's status for each.

Status key: **Built** = working in this repo and covered by tests or an end-to-end run · **Partial** = foundation exists, gaps noted · **Planned** = on the roadmap.

| Capability | Who is known for it | Fenrir status | Where |
|---|---|---|---|
| Signature + heuristic anti-malware with cloud reputation | ESET LiveGrid, Defender cloud protection | **Built** (Windows engine; Linux hash engine) + cloud intel bundle | `agent/windows/service`, `pkg/fleet/scanner.go`, `intel.py` |
| Machine-learning static detection | SentinelOne Static AI, Defender | **Built**: LightGBM model trained on SOREL-20M, on-device on Windows (scan + process start) and Linux (scans); 94.6% detection at 0.064% FPR out-of-time | `ml/`, `MlStaticModel.cpp`, `pkg/ml` |
| Behavioural detection / EDR telemetry | SentinelOne Behavioral AI, Defender EDR | **Built**: ETW (Windows), procfs (Linux), Sigma + correlation in cloud | `detection.py`, `rules/sigma/` |
| Attack storyline / process context | SentinelOne Storyline | **Partial**: alerts show ±5 min process lineage; no full graph view yet | `soc.py` `alert_detail` |
| Threat hunting over raw telemetry | SentinelOne Deep Visibility, Defender Advanced Hunting | **Built**: query language + Sigma retro-hunt | `soc.py` `/events`, `/hunt` |
| Ransomware behaviour + canaries | ESET Ransomware Shield, Heimdal REP, S1 | **Built**: canaries, mass-encryption correlation, shadow-copy/backup tamper rules, ransom-note rules | `rules/sigma/ransomware.yml`, `pkg/fleet/sensors.go` |
| Ransomware rollback | SentinelOne 1-click rollback (VSS) | **Partial**: `ransomware.rollback` command, policy and auto-trigger exist; Windows executor still to implement | `commands.py` |
| Controlled folder access | Defender CFA | **Partial**: policy (`protectedFolders*`); enforcement depends on the Windows minifilter path | `policy_schema.py` |
| Attack surface reduction rules | Defender ASR | **Built**: 15 rules enforced per mode on Windows (ETW process-start, terminate on block) and Linux equivalents; without a kernel driver this acts just after start, not before | `BehaviorRules.cpp`, `ProcessGuard.cpp`, `pkg/fleet/protection.go` |
| AMSI script inspection | Defender, ESET | **Built** (Windows AMSI provider) | `agent/windows/provider/amsi` |
| Exploit blocker / memory scanner | ESET Exploit Blocker, Advanced Memory Scanner | **Planned** (policy flags exist) | `edr.exploitProtection`, `edr.memoryScanning` |
| DNS filtering (on and off network) | Heimdal Threat Prevention, Cisco Umbrella | **Built**: per-device DoH resolver, categories, DGA, intel, DoH-bypass blocking, logs | `dnsfilter.py` |
| Web / phishing protection | ESET Anti-Phishing, Defender SmartScreen | **Built** (Windows destination verdict engine) + cloud intel | `agent/windows/service/src/Destination*` |
| Network isolation | All EDRs | **Built** (Windows WFP, Linux nftables) | `NetworkIsolationManager.cpp`, `pkg/fleet/agent.go` |
| Host firewall and network attack protection | ESET Firewall/IDS | **Partial**: policy defined; Windows WFP sensor exists | `firewall` section |
| Device control (USB etc.) | ESET Device Control, Heimdal | **Built** for USB storage, CD/DVD, phones (MTP) and BitLocker-only USB on Windows via documented policies; USB block/read-only with per-device exceptions and Bluetooth on Linux. Per-device exceptions on Windows and printer control still need work | `DeviceControl.cpp`, `pkg/fleet/protection.go` |
| Application control | Heimdal, Defender WDAC | **Built**: deny lists (name, hash, publisher), allow-list mode, unknown-reputation blocking on Windows and Linux | `BehaviorRules.cpp`, `pkg/fleet/protection.go` |
| Privileged access management / JIT elevation | Heimdal PEDM, ThreatLocker | **Partial**: Windows PAM tooling, break-glass and local-admin commands; approval workflow UI to follow | `agent/windows/tools/pamui`, `commands.py` |
| OS and third-party patching | Heimdal Patch & Asset, ConnectSecure, NinjaOne, N-able, Level | **Built**: Windows Update (by KB), winget and apt/dnf/yum/zypper; approval rules per classification, rings with delays, maintenance windows, restart policy, compliance dashboard | `rmm.py`, `RmmExecutors.cpp`, `pkg/fleet/rmm.go` |
| Device health monitoring and alerting | NinjaOne conditions, N-able checks, Level monitors | **Built**: CPU, memory, disks, services, processes, offline, restart pending, missing patches; alert, ticket, self-heal script, email and webhook actions; auto-resolve | `rmm.py`, `routers/rmm.py` |
| Scripting and automation | NinjaOne, N-able Automation Manager, Level, SuperOps | **Built**: library with typed parameters, safe parameter passing, run on device/group/customer, per-device output, schedules | `rmm.py`, Scripts and Automation pages |
| Software deployment | NinjaOne, N-able, SuperOps | **Built**: winget, Chocolatey, hash-checked MSI/EXE, apt, dnf, snap | `routers/rmm.py` |
| Browser remote control | ScreenConnect, NinjaOne Remote, Splashtop, Level | **Built**: pop-out viewer (desktop, terminal, files, processes, services, chat), cloud relay, consent, banner, view-only, audit trail; Linux X11 verified end to end, Windows helper verified under Wine | `remote.py`, `RemoteViewer.tsx`, `pkg/remote`, `fenrir-remote.exe` |
| PSA service desk | ConnectWise Manage, Autotask, HaloPSA, SuperOps | **Built**: boards, statuses, types/subtypes/items, impact × urgency, business-hours SLAs, note types, tasks, merge, workflow rules, email-to-ticket, dispatch | `psa.py`, `routers/psa.py` |
| Time, agreements and invoicing | ConnectWise Manage, Autotask | **Built**: time entries, timesheet approval, agreement coverage and included hours, after-hours rates, additions counted from RMM, invoices | `psa.py`, `routers/business.py` |
| CMDB and client portal | ConnectWise configurations, IT Glue, HaloPSA portal | **Built**: configurations synced from RMM; customer portal for requests, KB, invoices and devices | `routers/psa.py`, `routers/portal.py` |
| Vulnerability management | ConnectSecure, RoboShadow, Defender TVM | **Built**: inventory → OSV.dev, CISA KEV prioritisation, status workflow | `exposure.py` |
| External attack surface scanning | RoboShadow, ConnectSecure | **Built** (ownership attestation required) | `exposure.py` `scan_external` |
| Compliance reporting | ConnectSecure, RoboShadow (Cyber Essentials) | **Built**: 5 frameworks scored from live evidence | `compliance.py` |
| Tamper protection | All | **Built** (Windows); policy-driven | `HardeningManager.cpp` |
| Multi-tenant MSP console | Heimdal, ESET PROTECT, S1 | **Built**: tenant tree, RBAC, per-tenant policy, tuning and reports | `deps.py`, `console/` |
| SOAR / automated response | Defender AIR, S1 | **Built**: policy auto-response, rule responses, automation rules, webhooks | `detection.py` |
| Guided incident playbooks | — (rare in SMB tools) | **Built**: Sentinel playbooks with closure gates | `playbooks/` |
| PSA ticketing + SLAs | ConnectWise, Autotask (not AV vendors) | **Built** and wired to incidents and monitors | `psa.py` |
| CRM + billing | HubSpot/Xero (not AV vendors) | **Built**: lead → customer conversion, per-device invoices | `business.py` |
| Signed agent updates with rings | All | **Partial**: release registry and update-check; Windows updater verifies manifests | `agent_api.py` `update-check` |
| Email security / M365 posture | Heimdal Email, RoboShadow M365 | **Planned** | — |
| Dark-web credential monitoring | RoboShadow | **Planned** (needs a licensed breach-data source) | — |
| Network discovery of unmanaged devices | SentinelOne Ranger | **Planned** | — |
| Remote shell for analysts | SentinelOne, Defender Live Response | **Built** through remote access (PowerShell/ConPTY on Windows, PTY on Linux), gated by `remoteAccess.allowTerminal` | `pkg/remote`, `fenrir-remote.exe` |
| Kernel-level macOS protection | All | **Partial**: Endpoint Security framework agent in Swift | `agent/macos` |

## Where Fenrir is ahead for MSPs

- **One product, one bill.** Security, RMM, remote access, PSA, CRM and billing in one tenant model. Competitors need 3–5 integrated tools to match this (for example SentinelOne + NinjaOne + ScreenConnect + ConnectWise Manage).
- **Security and operations share one record.** A monitor, a detection and a remote session can all land on the same ticket, with the time billed to the right agreement.
- **Policy depth with provenance.** 169 settings, locks at any layer, and every device shows which layer set each value.
- **Open detection.** Sigma rules are portable. Customers can bring the public SigmaHQ library and see exactly why an alert fired.
- **Tenant-scoped tuning.** Suppressing a false positive for one customer never weakens another.

## Honest gaps before "best on the market"

- **Independent test results** (AV-Test, AV-Comparatives, MITRE ATT&CK Evaluations). These need a production-grade engine and a test budget.
- **Ransomware file rollback on Windows** (the command and policy exist; the agent executor does not yet).
- **Pre-execution blocking** needs the signed minifilter driver; see [DRIVER_SIGNING.md](DRIVER_SIGNING.md).
- **SOC 2 / ISO 27001 for the service itself.**
