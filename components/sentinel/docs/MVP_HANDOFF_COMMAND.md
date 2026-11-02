# Sentinel / Fenrir Blue Team MVP Handoff Command

Copy and paste the command below into a new chat or coding agent. It sets the expectations, build boundaries and exit criteria for the next MVP implementation phase.

---

## MVP Handoff Command

You are continuing development on `zy538324/Sentinel`, a defensive Blue Team security suite that must evolve from a collection of early tools into a production-shaped MVP. Do not treat this as an AV-only project. Treat it as an agent-driven defensive security platform for investigation, hardening, vulnerability management, evidence collection and reporting.

The fixed roadmap must not be changed or replaced. The current priority is to build a usable MVP around the existing Sentinel/Fenrir architecture, not to add random new tabs or cosmetic placeholders.

## Current known state

The repo currently has:

- FastAPI backend with routers for IOC validation, ThreatGate, blocklist, endpoint, investigator, exposure, CVE, phish, settings and email-intel.
- React/Vite frontend shell with human-readable card-based UI.
- Endpoint Risk has a better device triage view.
- Investigator has been moved towards an agent-driven workflow.
- CVE Watchdog has been upgraded towards a feed-backed matcher.
- Agent registration, posture ingestion, investigation queueing and evidence upload endpoints exist.
- Local Investigator can collect local host summary, processes, network connections, services, startup items, basic Windows Event Log summaries, findings, a timeline, an HTML report and a ZIP evidence bundle.

However, the platform is still not production-grade. Many modules are partial, stubbed, local-only, in-memory or disconnected from a real agent loop.

## Non-negotiable expectations

Do not produce JSON dumps in the GUI. All data shown to users must be rendered as readable cards, tables, sections, badges, summaries and remediation guidance.

Do not build placeholder-only screens unless the screen clearly states it is not implemented and lists what is missing.

Do not build offensive tooling, exploitation features, credential harvesting or malware execution features. This is a defensive suite.

Do not make broad architectural rewrites unless they directly improve the MVP and do not break existing working modules.

Do not remove working functionality unless it is replaced with a better implementation.

Do not add fake results and present them as real. Seed data may be used only when clearly labelled as seed/demo feed data.

Every new module must answer:

1. What does this tool do?
2. What evidence does it collect or analyse?
3. What is the risk or severity?
4. What should the user do next?
5. Can the output be exported or attached to a case/report?

## MVP objective

Build a working MVP called **Fenrir Investigator / Sentinel MVP** that demonstrates a realistic Blue Team workflow:

1. Register endpoint agents.
2. Ingest posture and inventory from those agents.
3. Select a device for investigation.
4. Queue a scoped investigation.
5. Agent collects evidence according to the requested scope.
6. Agent uploads evidence.
7. Backend stores evidence, findings, timeline and report metadata.
8. Frontend shows clear investigation status, findings, timeline, risk, remediation and downloads.
9. Case/report output can be generated from the investigation.

The MVP does not need every final roadmap module, but it must have a coherent end-to-end investigation and hardening workflow.
## Mandatory implementation order

Do not start Phase 3, 4, 5 or 6 until Phase 1 and Phase 2 are working end-to-end.

The first usable milestone is:

Backend restart-safe storage → agent registration → posture ingestion → queued investigation → agent polling → scoped collection → evidence upload → GUI status/update/download.

If this loop is not working, do not spend time on extra screens, visual polish, phishing, DNS, browser checks, USB guard, SIEM, YARA/Sigma or future roadmap items.

The MVP must favour one complete working workflow over many disconnected partial tools.
## Build Phase 1 — Foundation fixes

### 1. Replace fragile JSON/in-memory storage with SQLite

Implement a small database layer using SQLite.

Required tables:

- agents
- agent_postures
- investigation_requests
- investigation_results
- evidence_files
- software_inventory
- vulnerability_matches
- settings
- audit_events

Exit criteria:

- Restarting the backend does not lose agents, settings, investigation requests, postures or uploaded evidence metadata.
- Existing JSON data can be migrated or safely ignored with clear development fallback.
- Backend functions do not rely on global in-memory dictionaries for production workflow state.

### 2. Harden settings and secrets

Current settings are too development-like. Improve them without overengineering.

Required:

- Store settings persistently.
- Mask secrets in API responses.
- Remove duplicated secret initialisation.
- Require `SENTINEL_SECRET_KEY` or clearly block production mode without it.
- Never return plaintext API keys or SMTP passwords.

Exit criteria:

- Settings survive restart.
- Secrets are masked in the GUI and API responses.
- No hardcoded production secret fallback is presented as acceptable.

## Build Phase 2 — Agent-driven investigation MVP

### 3. Build or complete the agent polling loop

The backend already queues investigation requests. Now implement the actual agent-side loop or a clearly separated Python MVP agent.

Required behaviour:

- Agent registers or reuses an existing agent ID.
- Agent sends heartbeat/posture.
- Agent checks `/api/endpoint/agent/{agent_id}` or a dedicated task endpoint.
- If investigation is pending, agent reads the requested scope.
- Agent runs only the requested collectors.
- Agent creates JSON and HTML output locally.
- Agent creates an evidence bundle.
- Agent uploads bundle to `/api/endpoint/agent/{agent_id}/evidence`.
- Agent reports success/failure status.

Required investigation scopes:

- processes
- process tree / parent-child relationships
- command lines
- network connections
- services
- startup folders
- registry autoruns where available
- scheduled tasks where available
- Windows Event Log summary where available
- PowerShell artefacts where available
- local users/admins where available
- installed software inventory
- suspicious file/hash summary

Exit criteria:

- From the GUI, selecting a registered device and pressing Queue Agent Investigation results in that agent collecting evidence and uploading it.
- The selected device changes state from idle to pending to complete or failed.
- The GUI shows evidence availability and a download link.
- The workflow works after backend restart.

### 4. Split Investigator into reusable collectors

Do not leave all investigation logic in one huge route file.

Create a clean module structure such as:

- `modules/investigator/collectors/processes.py`
- `modules/investigator/collectors/network.py`
- `modules/investigator/collectors/persistence.py`
- `modules/investigator/collectors/eventlogs.py`
- `modules/investigator/collectors/software.py`
- `modules/investigator/analysis/commands.py`
- `modules/investigator/analysis/process_tree.py`
- `modules/investigator/analysis/persistence.py`
- `modules/investigator/timeline.py`
- `modules/investigator/reporting.py`
- `modules/investigator/bundles.py`

Exit criteria:

- The app still runs.
- Existing Investigator features still work.
- Collectors can be tested independently.
- Adding a new collector does not require editing a massive route file.

## Build Phase 3 — Minimum investigation tools

### 5. Standalone Persistence Scanner

Build a proper Persistence Scanner module using existing and new collectors.

Checks:

- Registry Run / RunOnce keys
- Startup folders
- Scheduled tasks
- Services
- WMI subscriptions where feasible
- PowerShell profiles
- Logon scripts where feasible
- Browser extensions if available
- Suspicious user-writable paths
- Unsigned or unknown publisher paths where feasible

Output fields per item:

- name
- location/type
- path/command
- publisher/signature if available
- hash if file-backed
- created/modified time if available
- risk rating
- reason flagged
- recommended action

Exit criteria:

- GUI has a Persistence Scanner view or Investigator section that displays persistence findings as proper cards.
- No raw JSON shown.
- Findings can be included in an investigation report.

### 6. Real Timeline Builder

Improve the timeline from “findings only” to an artefact/event timeline.

Timeline inputs:

- process start times
- suspicious commands
- network observations
- persistence artefacts
- scheduled tasks/services creation where available
- event log entries where available
- file creation/modification evidence where available
- AV/Defender events where available

Exit criteria:

- Timeline entries have timestamp, source, event title, severity, host, user/process if available and evidence reference.
- GUI shows a readable chronological timeline.
- Timeline is exported in JSON and HTML report.

### 7. Suspicious Process and Command Line Analyser

Take current Investigator logic and make it a proper module.

Required detections:

- Office spawning PowerShell/cmd/script interpreters
- Browser spawning script interpreters
- PowerShell encoded command
- PowerShell download cradle
- execution policy bypass
- hidden PowerShell window
- certutil download behaviour
- regsvr32/mshta/rundll32 suspicious use
- shadow copy deletion
- recovery tampering
- execution from AppData/Temp

Exit criteria:

- Findings include matched rule, severity, process, parent process, command line, evidence and remediation.
- Findings appear in Investigator and reports.

### 8. Network Connection Monitor MVP

Build a snapshot-based monitor first, then leave hooks for live monitoring.

Required:

- active outbound connections
- process name/path/PID
- remote IP/port
- listening ports
- suspicious process with connection flag
- external destination detection
- enrichment placeholder for reputation/ASN/country

Exit criteria:

- Investigator collects network evidence from the agent.
- GUI shows readable connection cards or table.
- Suspicious network findings are added to the report.

## Build Phase 4 — Prevention and vulnerability MVP

### 9. Installed Software Inventory

This is essential for CVE Watchdog.

Agent should collect:

- installed software name
- vendor/publisher
- version
- install location if available
- source registry/package manager where available
- browser versions
- update timestamp if available

Exit criteria:

- Software inventory is posted to backend and stored persistently.
- GUI can display installed software per endpoint.
- CVE Watchdog can scan a device’s inventory, not only manual product/version input.

### 10. CVE / KEV matcher connected to inventory

Current CVE Watchdog has local feed matching. Connect it to software inventory.

Required:

- Scan one selected endpoint’s inventory.
- Match installed software against local vulnerability feed.
- Flag known exploited vulnerabilities.
- Prioritise by known exploited, critical/high severity, CVSS and match confidence.
- Show remediation guidance.

Exit criteria:

- User can select a device and run vulnerability matching against its collected inventory.
- Results are stored and visible after refresh.
- Results are human-readable and reportable.

### 11. Windows Security Baseline Checker MVP

Extend Endpoint Risk beyond the current basic checks.

Add checks where feasible:

- Defender enabled
- real-time protection enabled
- firewall enabled
- BitLocker status
- Secure Boot status
- RDP exposure
- SMBv1 disabled
- PowerShell logging
- audit policy
- local admin count
- Windows update status placeholder or real check
- controlled folder access where feasible

Exit criteria:

- Endpoint Risk gives a clear score, band, failed controls and remediation guidance.
- Device triage queue sorts devices by risk.
- Results are stored per endpoint.

## Build Phase 5 — Reporting and case MVP

### 12. Evidence bundle integrity

Improve evidence bundles.

Required:

- manifest file
- SHA256 hashes for each artefact
- collection timestamp
- agent ID and hostname
- investigation request ID
- selected scope
- tool version

Preferred:

- signed manifest or integrity signature placeholder
- encrypted bundle option if key is configured

Exit criteria:

- Every evidence bundle contains a manifest.
- Backend records bundle metadata.
- GUI shows bundle metadata and download link.

### 13. Incident Report Generator MVP

Extend current HTML report into a proper incident report.

Sections:

- executive summary
- affected asset
- investigation reason
- risk/severity
- scope selected
- key findings
- timeline
- evidence collected
- recommended containment
- recommended eradication
- recommended recovery
- residual risk
- technical appendix

Exit criteria:

- User can export a readable HTML report from an investigation.
- Report contains no raw JSON dump.
- Report is useful to a home user, small business or analyst.

### 14. Basic Case Management

Implement a minimal case system.

Required:

- create case
- link affected device
- link investigation request/result
- severity
- status: open, investigating, contained, remediated, closed
- notes/actions
- evidence attachments metadata
- report export link

Exit criteria:

- A case can be created from an investigation.
- Case remains after restart.
- Case page shows status, evidence, findings and notes.

## Build Phase 6 — Start but do not overbuild yet

Start these only after the investigation MVP works end-to-end:

- Phishing Email Analyser: separate from PhishGuard simulation. Must support `.eml`/header parsing, URLs, attachments, SPF/DKIM/DMARC result display where possible.
- DNS Monitor / Protection: start with logging and known-bad domain checks. Do not build unsafe packet interception prematurely.
- Browser Security Checker: collect browser version, suspicious extensions and risky permissions where feasible.
- Backup Readiness Checker: detect backup presence, freshness and restore guidance.
- USB Guard: detection/logging first, blocking later.
- Threat Feed Aggregator: ingest local JSON feeds first, then add external feeds later.
- YARA/Sigma Rule Manager: rule storage, validation, versioning and test mode before enforcement.

## Explicitly out of MVP scope for now

Do not build these until the above MVP is stable:

- full malware sandbox execution
- aggressive network blocking
- kernel driver work
- cloud multi-tenant SaaS architecture
- Microsoft 365 OAuth production integration
- paid/commercial feed integrations
- full SIEM correlation engine
- automated destructive remediation

## GUI requirements

Every tab must be human-friendly.

Required display style:

- summary verdict card
- score/severity cards
- prioritised findings cards
- evidence cards/tables
- remediation text
- clear empty states
- no raw JSON dumps
- no tiny cramped cards for large evidence objects
- expandable/detail sections for technical data

## API requirements

Every API response used by the GUI should have stable fields where possible:

- `status`
- `summary`
- `risk_score` or `severity`
- `findings`
- `evidence`
- `timeline`
- `recommended_actions`
- `metadata`

## Testing expectations

At minimum, add smoke tests or manual test notes for:

- backend starts successfully
- frontend builds successfully
- agent registration works
- posture ingestion works
- investigation queueing works
- agent can read pending task
- evidence upload works
- device triage displays correctly
- CVE scan works with seeded feed
- no GUI tab displays raw JSON
## Required developer response format after each coding pass

After each coding pass, respond using this format:

### Changed
- Exact files changed
- Exact functionality added or modified

### Not changed
- Anything intentionally left untouched
- Any roadmap item not yet started

### How to test
- Commands to run
- Expected result
- Known limitations

### Next safest step
- The next implementation step that moves the MVP forward without breaking existing functionality
## Final MVP exit expectations

The MVP is considered acceptable only when all of the following are true:

1. A user can register or run an endpoint agent.
2. The agent appears in the GUI.
3. The agent sends posture and inventory.
4. Endpoint Risk scores the device and shows remediation.
5. Investigator can queue a scoped investigation to that device.
6. The agent collects scoped evidence and uploads a bundle.
7. The GUI shows pending/complete/failed investigation state.
8. The GUI shows findings, timeline, evidence metadata and download links.
9. CVE Watchdog can scan either manual software input or endpoint inventory.
10. A readable incident report can be exported.
11. Core data survives backend restart.
12. No active GUI module falls back to raw JSON output.
13. The implementation clearly moves the project closer to production grade.

When coding, work in small, safe increments. Prefer preserving working functionality over risky rewrites. After each change, state exactly what was changed, what was not changed, and what must be tested next.
