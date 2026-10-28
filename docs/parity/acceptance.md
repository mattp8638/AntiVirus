# Parity acceptance journeys

Each scenario from the implementation brief (section 6) with how it is run, the test data it uses, the platforms it covers and the latest recorded outcome. Outcomes are **PASS**, **FAIL**, **NOT RUN** or **BLOCKED**. A mocked provider test is recorded as such. It never counts as a live provider result.

Run the cloud suite with `cd cloud && python -m pytest -q`. For PostgreSQL, set `FENRIR_TEST_DATABASE_URL=postgresql+psycopg://…` first. CI runs both databases in `.github/workflows/phase2-smoke.yml`, and that workflow also builds and starts the lab Compose stack.

Test data is synthetic: tenants "Acme Dental" and "Other Customer", devices enrolled through the API, OSV/Graph responses from `httpx.MockTransport`. No customer data, certificates or credentials are used in fixtures.

| Test | Journey | How it is run | Platforms | Latest outcome |
|---|---|---|---|---|
| AT-01 | Fresh checkout without signing files; separate signed-production configuration | CI `phase2-smoke.yml`: lab Compose build/start, HTTP smoke, "production refuses to build without a certificate", packaged-agent validation (hash, PE x64, ELF, Mach-O) | Ubuntu CI runner, Docker | **PASS**: [run 40590036336](https://github.com/mattp8638/AntiVirus/actions/runs/40590036336) on `d87ca95`. Still open: a signed production build has not been exercised in CI (needs the real certificate, which is never committed). |
| AT-02 | Password/MFA reset, logout, account disable, session revoke | `cloud/tests/test_sessions.py`, `test_foundation.py` | Cloud (SQLite, PostgreSQL 16) | **PASS** (automated). Covers old tokens after password change, admin reset, disable/re-enable, MFA enable/reset, logout, revoke-others, step-up for admin revoke, tokens without a server session, and remote viewer cut-off (close 4401). Not yet covered: SSO and WebAuthn, which do not exist yet (CORE-03). |
| AT-03 | Customer A operator tries B's IDs across modules | `cloud/tests/test_scope_matrix.py`. It walks all OpenAPI operations as customer A's tenant admin, technician and device key, using customer B's IDs in the path, query and body. It hashes every row outside A's scope, and B's rows carry a marker string. A positive control confirms the platform admin does see B's marker. | Cloud (SQLite, PostgreSQL) | **PASS (API)** after fixing the PSA MSP-level writes. Not yet covered: background jobs, guessed file paths, websockets other than remote. |
| AT-04 | ≥64 concurrent audit writers with rollback on PostgreSQL | `cloud/tests/test_audit_concurrency.py` | PostgreSQL 16, SQLite WAL | **PASS**: reproduced the broken chain before FIX-05 and passes after |
| AT-05 | Agent loses connection after receiving and after executing a command | — | Windows, Linux, macOS agents | **NOT RUN** (CORE-07/AGT-05) |
| AT-06 | OSV 503/429, invalid/error JSON, short batch, detail failure, missing inventory, partial coverage | `cloud/tests/test_scan_integrity.py` (12 cases) | Cloud (mock OSV) | **PASS** (mocked OSV). Live OSV is not part of CI. |
| AT-07 | Critical KEV moved to patching/mitigated/accepted | `cloud/tests/test_exposure_counts.py` | Cloud | **PASS** |
| AT-08 | Patch/app deployment that exits zero without change | — | Real endpoints | **NOT RUN** (RMM-06/RMM-07) |
| AT-09 | Monitor → ticket → remediation → stale/broken telemetry | — | Cloud and agents | **NOT RUN** (RMM-04, FLOW-04) |
| AT-10 | Remote desktop/terminal/file matrix | `cloud/tests/test_remote.py` (relay only) | — | **NOT RUN** on endpoints (RMM-09/RMM-10) |
| AT-11 | Isolation, offline sensor, policy downgrade, unisolation | — | Windows | **NOT RUN** |
| AT-12 | EICAR and benign workloads | — | Windows, Linux, macOS | **NOT RUN**. Windows pre-execution prevention is **BLOCKED** (FIX-06). |
| AT-13 | Altered/replayed/downgraded release, bad canary, key rotation | `agent/linux/pkg/fleet/release_test.go`, `cloud/tests/test_rollouts.py`, plus a CI step that builds the image with a throwaway key and verifies the manifests with OpenSSL | Go agent (unit); cloud | **PASS (automated)**. Covers altered binary/manifest, untrusted key, wrong platform, expired manifest, downgrade, replay, rotation, and a bad canary that pauses before the stable ring. Not yet observed on real endpoints; Windows tamper tests are still to do. |
| AT-14 – AT-17 | Microsoft 365 onboarding, offboarding, two-tenant templates, provider failures | `cloud/tests/test_m365*.py` (mocked Graph) | Microsoft 365 | **BLOCKED** for live verification: isolated test tenants needed |
| AT-18 | Scan lab networks; redirect/rebinding/metadata/other-customer targets | — | Lab network | **NOT RUN** (VULN-22) |
| AT-19 | Backup and restore | — | — | **NOT RUN**. No backup engine yet (BDR-01). |
| AT-20 | Mobile enrollment and destructive actions | — | Android, iOS | **NOT RUN** |
| AT-21 | Framework revision with same IDs, changed meaning | `cloud/tests/test_grc_revisions.py` | Cloud (SQLite, PostgreSQL 16) | **PASS** locally on `8fda3b7`: reworded requirement loses "done", unchanged keeps it, dry-run diff, legacy backfill, historical export, customer scope, import removal. CI pending. |
| AT-22 | Approved policy edited, reapproved, assigned to staff | `cloud/tests/test_grc_programme.py` (versions only) | Cloud | **NOT RUN** for staff acknowledgement, which does not exist yet (GRC-08) |
| AT-23 | Supplier risk; revoked auditor and trust access | — | Cloud | **NOT RUN** (GRC-06/GRC-14/GRC-19) |
| AT-24 | Whole-platform restore | — | Deployment | **NOT RUN** (CORE-09) |
| AT-25 | Decommission and reinstate with queued commands and billing | Partial: `docs/DEVICE_REINSTATEMENT.md` journeys | Cloud | **NOT RUN** as specified |
| AT-26 | Secret rotation and disclosure inspection | — | Deployment | **NOT RUN** |
| AT-27 | 10,000-endpoint load, burst, restarts, 24-hour soak | — | Declared hardware | **NOT RUN** (CORE-13) |
| AT-28 | Operator end-to-end tasks from the console | — | Browser | **NOT RUN** |
