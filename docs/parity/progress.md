# Parity progress

Maintained across sessions. Each catalogue entry's state lives in `catalogue.csv`; this file records what moved and what comes next.

Baseline of the review: `main` at `790e364`. Work branch: `claude/jolly-goodall-5kpl2t`.

## Catalogue totals (178 entries)

| State | Count |
|---|---|
| verified | 6 (FIX-01 to FIX-05, FIX-08) |
| implemented-unverified | 10 (FIX-07, AGT-04, CORE-03 and 7 requirements the brief marked U) |
| partial | 96 |
| missing | 65 |
| externally-blocked | 1 (FIX-06) |

Overall parity: **not passed**. MVP: **not yet declared**.

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
| RMM-09 (owner request) | (this batch) | Backstage hidden SYSTEM desktop on Windows (session 0) with a tools launcher; nothing reaches the user's session. Self-test command and Windows CI acceptance check. |
| CORE-15 (approvals) | (this batch) | Optional two-person approval bound to the exact request and its devices; `test_approvals.py`. |
| CI | `b5cf672` | Removed the placeholder signing files that the merge brought back. [Run 78](https://github.com/mattp8638/AntiVirus/actions/runs/40649462515) passed, which also verifies FIX-08 in CI. |

## In progress

- Phase 1 (CORE and AGT).

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
