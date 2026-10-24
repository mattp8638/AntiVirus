# Phase 2 — Functional Exit Requirements (strict)

**Scope:** RMM job execution, monitoring, PSA integration, customer-owned CMDB, remote support and the supporting job scheduler. Cosmetic GUI styling is explicitly out of scope.

**Policy:** A checklist item is **FAIL** unless the actual behaviour has passed its tests. Source code existing, a working endpoint, and a green unit test are NOT interchangeable. Phase 2 is **not done** if it needs future code fixes, a skipped feature, or a later visit to complete functionality.

## Must-pass automated gates

1. **Cloud API:** `cd cloud && python -m pytest -q` against SQLite **and PostgreSQL**. All existing and new test suites pass without skips or unexplained warnings. Includes `tests/test_phase2_operational_exit.py`.
2. **Linux agent:** `cd agent/linux && go test ./...`; amd64 and arm64 binary builds pass. Command-receipt tests prove preservation across process restarts, 0600 file permissions, corrupted journal handling and no path traversal.
3. **Windows agent:** build full user-mode service and installer with `ANTIVIRUS_REQUIRE_MINIFILTER_PAYLOAD=OFF`; Windows native compilation succeeds, plus journal persistence/claim tests (not just portable policy unit tests). No missing DLL on a clean Windows 11 VM.
4. **Console:** `cd console && npm ci && npm run build && npm run test:shapes`; technician can open RMM results from the associated service ticket.
5. **Scheduler concurrency:** two independent PostgreSQL cloud worker processes cannot both run the same schedule pass. One lock owner; the other skips. Task rerun uses a new independent job only when deliberately requested.
6. **Security:** all commands, tickets, assets, remote sessions and results remain tenant-scoped. Wrong-tenant device, site, contact and ticket links receive 4xx without changing data.

## Must-pass live end-to-end gates

| ID | User journey | Exact evidence required | Current evidence |
|----|--------------|-------------------------|-----------------|
| P2-01 | Install Windows test agent, reboot twice, recover from network outage | Same device ID, automatic service, new heartbeats, original customer and no duplicate asset | NOT VERIFIED |
| P2-02 | Install Linux agent, restart service, disconnect/reconnect, reboot twice | Same identity; telemetry and commands resume without re-enrolling | NOT VERIFIED |
| P2-03 | Run harmless RMM scripts/commands on both OSes | Actual stdout/stderr, exit code, timings, correct job state, audit entry | NOT VERIFIED |
| P2-04 | Lose connectivity between execution and completion | Stored result resent once; no repeat execution. Interrupted action marked uncertain and not replayed | NOT VERIFIED |
| P2-05 | Cancel one pending and one already-dispatched action | Pending action cancelled; dispatched remains in-progress until endpoint result; no false success | NOT VERIFIED |
| P2-06 | Queue offline command for days, then reconnect | Pending commands execute only while within TTL; seven-day stale commands expire unused; dispatched results reconcile | NOT VERIFIED |
| P2-07 | CPU/disk threshold and offline monitoring | One alert per transition, correct customer and device, proper trigger/clear, no duplicate ticket | NOT VERIFIED |
| P2-08 | Monitoring alert creates ticket + remediation | Ticket exists before remediation; RMM job linked; result accessible from ticket; engineer can resolve | NOT VERIFIED |
| P2-09 | Technician accepts an automatically generated ticket | Recovery adds an internal note but does NOT silently close the assigned ticket | NOT VERIFIED |
| P2-10 | Asset discovery/lifecycle | Enrollment auto-creates one CMDB record, heartbeat refreshes metrics, manual notes remain; cross-customer linking blocked | NOT VERIFIED |
| P2-11 | Remote desktop, terminal and file support where implemented | User consent/policy enforced, no cross-tenant access, working live input/output, session duration and audit/time entries | NOT VERIFIED |
| P2-12 | Patch/software job with failed installation | Accurate non-zero exit failure, partial batch status, safe retry, no duplicate installs | NOT VERIFIED |
| P2-13 | PostgreSQL scheduler with 2 workers | One scheduling owner, no duplicate jobs or ticket creation, recovery after worker crash | NOT VERIFIED |
| P2-14 | Full stack in Docker | Database survives redeploy, console/agents reconnect; no lost secrets, jobs or files | NOT VERIFIED |

**NOTE:** Existing Python and Go tests plus new regressions provide API/implementation evidence, NOT the live evidence above. A passing mocked WebSocket is not proof that desktop control works against a user's actual machine.

## Known remaining blockers to pass Phase 2

- CI workflow runs for latest commits have not been observed on GitHub Actions. They must run and pass on this PR, including both PostgreSQL/SQLite and the Windows cross-build.
- Cannot run a native Windows GUI installer, reboots, actual desktop session, agent scripts or real network outage from the GitHub code connector. These require a disposable, user-authorised Windows/Linux test environment, with captured evidence.
- Native Windows journal and Linux receipt changes must be compiled and exercised on real endpoints before deploy.
- Unsigned hobby build is user-mode only and must coexist with Windows Defender. No unsigned kernel minifilter is claimed.
- Multi-process SQLite scheduling is NOT an approved configuration. Docker uses PostgreSQL; scheduler advisory locking applies to PostgreSQL.
- Test high-risk commands only on disposable lab devices. Do not execute arbitrary script payloads or destructive software/patch operations on customer devices as acceptance tests.

## Exit decision rules

**Does it work?** Only PASS with reproducible passing automated and live tests; never on a source review alone.

**Does it perform its intended function?** Only PASS if the action happened on the target endpoint, the correct customer/device/ticket reflect the actual result, and failed actions are accurately reported.

**Are there bugs?** Only PASS when no known critical/high defects remain in the tested Phase 2 scope. Uninvestigated crashes, flaky tests and silent data loss are FAIL.

**Will unfinished Phase 2 elements require revisiting?** YES means **FAIL**. An unsupported platform capability may be explicitly excluded before feature acceptance, not silently counted as complete.

**As of creation:** PHASE 2 OVERALL = **FAIL / NOT YET EXITED**. The source fixes are development candidates, not proof of production reliability.

### Recommended lab test order

1. Review and merge only after all automated checks are green.
2. Deploy the isolated branch to a disposable cloud test stack backed by PostgreSQL; never change an existing customer database for this experiment.
3. Enroll one Linux VM and one unsigned hobby-mode Windows VM; record device/CMDB IDs.
4. Run command, offline, retry, monitoring, remediation, ticket, remote and restart tests above; retain logs.
5. Reboot each device twice, repeat commands, compare identities/results, verify database backup/restore.
6. Pass the release gate **only after** all P2-01 through P2-14 are evidenced and defects are resolved.
