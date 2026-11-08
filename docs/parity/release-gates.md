# Release gates

There are two separate release states:

- **MVP shipped:** the first usable milestone. The owner declares it once the Phase 0 and Phase 1 exits pass.
- **Full parity verified:** every catalogue entry is `verified`.

Gate answers are **PASS**, **FAIL** or **BLOCKED**. Status on 2026-11-01, after the deployment-readiness batch (go-live check, platform health alerts and metrics, switch-port topology) and the merge of the parallel session's worker split, acceptance harness and load test:

| # | Gate | Answer | Evidence | Remaining defects |
|---|---|---|---|---|
| 1 | Does it work? Install, upgrade, rollback and restore on the declared matrix; CI green | **FAIL** | The lab Compose build/start and HTTP smoke pass in CI. Real Linux and Windows agents install and pass the acceptance harness in CI (AT-29). Whole-platform backup, damaged-backup refusal and restore pass in CI (AT-24). `deploy/preflight.sh` checks a deployment before go-live and runs against the CI stack. | No declared platform matrix (AGT-07). Agent rollback (re-release under a new number) not yet exercised on real endpoints. No signed production build in CI (the certificate is never committed). A brand-new server restores from backup in 128 s in CI (AT-24), on a small dataset. |
| 2 | Does it perform the intended function? Every in-scope operation has an observed real result | **FAIL** | Cloud behaviour is covered by automated tests. | Endpoint and provider results are mostly unobserved (see `acceptance.md`). Microsoft 365 is mocked only. |
| 3 | Are there unresolved material bugs? | **FAIL** | FIX-01 to FIX-05, FIX-07 and FIX-08 are fixed with regression tests. The cross-customer API matrix passes after fixing the PSA leaks. | FIX-06: no pre-execution prevention. Scope is tested for the API and background jobs; not yet for guessed file paths or websockets other than remote. |
| 4 | Does unfinished work remain? | **FAIL** | `catalogue.csv`: 6 verified, 14 implemented-unverified, 119 partial, 38 missing, 1 externally blocked (178) | 172 entries are not verified. |
| 5 | Can an MSP run it? Runbooks, health, permissions, capacity | **FAIL** | A go-live checklist (`docs/GO_LIVE.md`), install, HTTPS, signing, update, backup and restore runbooks (README, `docs/BACKUP_AND_RESTORE.md`) and a go-live check (`deploy/preflight.sh`: secrets, production mode, signing material, proxy, containers, ports, disk, backups, live health and TLS). A separate worker with `/health/background` (scheduler and maintenance heartbeats, stuck jobs, outbox lag, artifact storage); degraded/recovered alerts sent by the web process straight to MSP webhooks; Prometheus `/metrics` behind a token (CORE-08). Per-device telemetry caps and retention tiers; a 300-agent load test (AT-31). Staff controls: required MFA, console networks, Microsoft sign-in, passkeys, an emergency stop, script review and two-person approvals. | Capacity is measured at 300 agents, not the 10,000-endpoint target (CORE-13, AT-27). Off-site backup copies are left to the operator. |
| 6 | Are claims accurate? | **PASS (for current docs)** | `decisions.md` separates functional parity, efficacy, platforms and certification. `DRIVER_SIGNING.md` states that prevention is user-mode only. | Keep marketing and console wording aligned as features land (AGT-10, AV-22). |

## Phase exits

| Phase | Exit status |
|---|---|
| 0 | **Met.** FIX-01 to FIX-05 and FIX-08 are verified. FIX-07 is implemented (Phase 1). FIX-06 is externally blocked (`decisions.md` D-06). |
| 1 | **In progress.** Done or largely done: CORE-01 (API), CORE-02, CORE-04 (API credentials), CORE-06, CORE-08 (health, alerts, metrics), CORE-09 (backup and restore drill), CORE-14 (production mode, go-live check), CORE-15, AGT-03 (Go), AGT-04. Device key rotation (CORE-04) is in. Next: the rest of CORE-01, CORE-07, CORE-13 at scale, AGT-01, AGT-02 and AGT-05 to AGT-10. |
| 2 to 9 | Not started, apart from the partial items noted in `catalogue.csv`. |
| Microsoft 365 (owner request) | **Batches 1 and 2 built, awaiting the owner's test.** Each batch exits only when the owner has run `docs/M365_TEST_PLAN.md` on their tenant and reported the results (AT-35). Batches 3 to 8 planned (`progress.md`). |
