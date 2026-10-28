# Release gates

There are two separate release states:

- **MVP shipped:** the first usable milestone. The owner declares it once the Phase 0 and Phase 1 exits pass.
- **Full parity verified:** every catalogue entry is `verified`.

Gate answers are **PASS**, **FAIL** or **BLOCKED**. Status at the Phase 1 milestone (scope matrix, signed releases, rollouts, API credentials, audit assurance):

| # | Gate | Answer | Evidence | Remaining defects |
|---|---|---|---|---|
| 1 | Does it work? Install, upgrade, rollback and restore on the declared matrix; CI green | **FAIL** | The lab Compose build/start and HTTP smoke pass in CI ([run 40590036336](https://github.com/mattp8638/AntiVirus/actions/runs/40590036336)). | No declared platform matrix (AGT-07). No platform restore (CORE-09); agent rollback (re-release under a new number) is not yet exercised on real endpoints. No signed production build in CI. |
| 2 | Does it perform the intended function? Every in-scope operation has an observed real result | **FAIL** | Cloud behaviour is covered by automated tests. | Endpoint and provider results are mostly unobserved (see `acceptance.md`). Microsoft 365 is mocked only. |
| 3 | Are there unresolved material bugs? | **FAIL** | FIX-01 to FIX-05, FIX-07 and FIX-08 are fixed with regression tests. The cross-customer API matrix passes after fixing the PSA leaks. | FIX-06: no pre-execution prevention. Scope is not yet tested for background jobs, file paths or websockets other than remote. |
| 4 | Does unfinished work remain? | **FAIL** | `catalogue.csv`: 6 verified out of 178 | 172 entries are not verified. |
| 5 | Can an MSP run it? Runbooks, health, permissions, capacity | **FAIL** | Deployment docs exist; `auto-update.sh` exists. | No recovery runbook, health dashboards or capacity evidence (CORE-08, CORE-09, CORE-13). |
| 6 | Are claims accurate? | **PASS (for current docs)** | `decisions.md` separates functional parity, efficacy, platforms and certification. `DRIVER_SIGNING.md` states that prevention is user-mode only. | Keep marketing and console wording aligned as features land (AGT-10, AV-22). |

## Phase exits

| Phase | Exit status |
|---|---|
| 0 | **Met.** FIX-01 to FIX-05 and FIX-08 are verified. FIX-07 is implemented (Phase 1). FIX-06 is externally blocked (`decisions.md` D-06). |
| 1 | **In progress.** Done: CORE-01 (API), CORE-04 (API credentials), CORE-06, AGT-03 (Go), AGT-04. Next: the rest of CORE-01, CORE-02, CORE-04 (device keys), CORE-07 to CORE-15, AGT-01, AGT-02 and AGT-05 to AGT-10. |
| 2 to 9 | Not started, apart from the partial items noted in `catalogue.csv`. |
