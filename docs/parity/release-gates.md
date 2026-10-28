# Release gates

There are two separate release states:

- **MVP shipped:** the first usable milestone. The owner declares it once the Phase 0 and Phase 1 exits pass.
- **Full parity verified:** every catalogue entry is `verified`.

Gate answers are **PASS**, **FAIL** or **BLOCKED**. Status as of commit `473eb80`:

| # | Gate | Answer | Evidence | Remaining defects |
|---|---|---|---|---|
| 1 | Does it work? Install, upgrade, rollback and restore on the declared matrix; CI green | **FAIL** | The lab Compose build/start and HTTP smoke pass in CI ([run 40590036336](https://github.com/mattp8638/AntiVirus/actions/runs/40590036336)). | No declared platform matrix (AGT-07). No rollback or platform restore (AGT-04, CORE-09). No signed production build in CI. |
| 2 | Does it perform the intended function? Every in-scope operation has an observed real result | **FAIL** | Cloud behaviour is covered by automated tests. | Endpoint and provider results are mostly unobserved (see `acceptance.md`). Microsoft 365 is mocked only. |
| 3 | Are there unresolved material bugs? | **FAIL** | FIX-01 to FIX-05 and FIX-08 are fixed with regression tests. | FIX-06: no pre-execution prevention. FIX-07: the Go updater accepts downgrades and unsigned releases. A cross-customer scope matrix has not been run (CORE-01). |
| 4 | Does unfinished work remain? | **FAIL** | `catalogue.csv`: 5 verified out of 178 | 173 entries are not verified. |
| 5 | Can an MSP run it? Runbooks, health, permissions, capacity | **FAIL** | Deployment docs exist; `auto-update.sh` exists. | No recovery runbook, health dashboards or capacity evidence (CORE-08, CORE-09, CORE-13). |
| 6 | Are claims accurate? | **PASS (for current docs)** | `decisions.md` separates functional parity, efficacy, platforms and certification. `DRIVER_SIGNING.md` states that prevention is user-mode only. | Keep marketing and console wording aligned as features land (AGT-10, AV-22). |

## Phase exits

| Phase | Exit status |
|---|---|
| 0 | **Met for FIX-01 to FIX-05.** FIX-08 is implemented and waiting for CI. FIX-06 and FIX-07 constraints are recorded and scheduled (`decisions.md` D-06, D-07). |
| 1 to 9 | Not started, apart from the partial items noted in `catalogue.csv`. |
