# Parity progress

Maintained across sessions. Each catalogue entry's state lives in `catalogue.csv`; this file records what moved and what comes next.

Baseline of the review: `main` at `790e364`. Work branch: `claude/jolly-goodall-5kpl2t`.

## Catalogue totals (178 entries)

| State | Count |
|---|---|
| verified | 5 (FIX-01 to FIX-05) |
| implemented-unverified | 8 (FIX-08 and 7 requirements the brief marked U) |
| partial | 98 |
| missing | 66 |
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
| FIX-08 | `8fda3b7` | Framework revisions: reworded requirements need review, dry-run diff, snapshots, historical export; `test_grc_revisions.py`. Passes locally (321 tests, SQLite and PostgreSQL); waiting for CI. |
| (owner request) | `473eb80` | Remote desktop Ctrl+Alt+Del is now sent by the agent service. Cross-compiled only; not yet tested on a real server (RMM-09/RMM-10). |

## In progress

- Phase 0 records: this file, `catalogue.csv`, `acceptance.md`, `decisions.md`, `release-gates.md`.

## Externally blocked

- **FIX-06 / AV-02:** Windows minifilter. The driver source was removed by the owner. Needs an EV certificate, a Partner Center account and HLK. See `decisions.md` D-06.
- **Live Microsoft 365 verification (AT-14 to AT-17):** needs isolated test tenants.
- The full list is in `decisions.md`, "Other external dependencies".

## Failed / known failing

- **AT-13 for the Go agent:** releases are not independently signed and downgrades are accepted (FIX-07). Scheduled with AGT-03/AGT-04.

## Next actions (Phase 1, in dependency order)

1. CORE-01: a customer-scope test matrix across APIs, jobs, files and websockets (AT-03), and fixes for any leaks it finds.
2. FIX-07 / AGT-03 / AGT-04: signed release manifests for the Go agent, release ordering, rings, pause and rollback. Remove the unused `agent/linux/pkg/updater`.
3. CORE-04: API key and device key lifecycle (rotate, expire, scope, usage).
4. CORE-02: custom roles with customer/site assignments.
5. CORE-06: audit checkpoints, protected export, retention.
6. CORE-07 / AGT-05: command reconciliation after disconnect (AT-05).
7. CORE-08, CORE-09, CORE-14: health and metrics, backup and restore, production-mode hardening.
