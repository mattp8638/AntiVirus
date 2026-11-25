# ISMS rewrite into Fenrir: plan

Status: accepted; Phase 1 in progress. Dates: drafted 20/11/2026, decisions recorded 25/11/2026.

## Goal

Rebuild the standalone ISMS Platform as part of Fenrir. It should run as a native module of `cloud/fenrir_cloud` and the console, not as a second app beside it. When this work is done, Governance in Fenrir does everything the standalone app does, using Fenrir's tenants, users, roles, audit log, worker and evidence.

## Frozen baseline

The standalone app stays as it is, for public release:

- Repository `mattp8638/ISMS`, branch `standalone-release`, commit `514cbb3` (all work to Phase 6.5, including the then open pull request 7).
- Nothing in this rewrite changes that branch. Fixes to the public release happen there, separately.
- Locking (branch protection, release tag, archive) is done in GitHub settings by the owner.

The baseline is the specification for the rewrite: its docs (`docs/01-product-spec.md` to `docs/05-build-plan.md`), its content packs and its tests describe the behaviour to reproduce. Logic is ported, not transliterated line by line.

## How the two map

| Standalone ISMS | In Fenrir |
| --- | --- |
| Tenant, parent tenant (MSP) | `tenants` tree. The MSP root is the parent tenant; customers are tenants |
| Auth.js, local passwords, TOTP | Fenrir sign-in, passkeys, SSO and MFA. No second sign-in |
| ISMS roles (ISMS manager, owner, approver, auditor, executive) | New permissions in `security.py` and roles in `roles.py` |
| Audit hash chain | Fenrir's hash-chained audit log (`audit.py`) |
| pg-boss jobs | Fenrir worker (`worker.py`) |
| Drizzle migrations | `db.py` ordered migrations, additive only |
| Content packs (YAML, zod) | YAML packs under `fenrir_cloud/isms/packs/`, validated with pydantic (`isms/content/`), every item with a `licence` field |
| `packages/domain` (applicability, scoring, risk maths) | `fenrir_cloud/isms/domain/`: pure Python, no database or FastAPI imports, unit tested |
| Next.js pages | Console pages under `console/src/pages/grc/` |
| `docx` package, Gotenberg | `python-docx`, with Gotenberg as an optional service for PDF |
| Fenrir connector (`packages/connectors/src/fenrir.ts`) | Not needed: `grc_automation.py` signals feed evidence directly |
| SeaweedFS evidence storage and scanning | Fenrir evidence storage, scanned with the ClamAV already used by the mail gateway |

## Overlap with Fenrir's current Governance

Fenrir already has programmes (`grcprogramme.py`), a catalogue (`grccatalogue.py`), policies, evidence, a crosswalk, continuous GRC automation, a risk and exception register (`routers/grc.py`), third-party risk (`tprm.py`) and SOC incidents. The rewrite extends these rather than building a parallel set:

| Area | Action |
| --- | --- |
| Frameworks and crosswalk | Replace with the ISMS model: framework packs, groups, requirements, mappings to a common control library, applicability rules. Migrate existing adoptions and answers |
| Requirement answers | Become control assessments against common controls; framework readiness is derived |
| Policies | Keep the tables; add document templates, generated documents, approval immutability and acknowledgement |
| Evidence | Keep; add validity periods, reminders, control links and file scanning |
| Risk register | Replace with the ISMS method: configurable criteria and scales, treatment plans, residual-risk sign-off, review cycles, dated snapshots |
| Suppliers | Keep `tprm.py`; link suppliers to assets, risks and controls |
| Incidents | Keep SOC incidents; add the ISMS view (control links, lessons learned) |
| Statement of Applicability, scope, context, assets, tasks, people and training, internal audit, management review, improvement, objectives, auditor portal, privacy, business continuity, AI management, dashboards | New |

## Decisions

| Id | Question | Decision |
| --- | --- | --- |
| R0 | How ISMS comes in | Ported directly into Fenrir's Python backend and React console, module by module. The standalone TypeScript is not copied into this repository; it stays in its own repository as the reference |
| R1 | Requirement text. Fenrir's library holds short summaries of each ISO 27001 requirement; the standalone app allows identifiers and short titles only | Identifiers and short titles only, with original guidance. The summaries in `grc_library/iso-27001.yml` are removed in Phase 2, when ISO answers move to the new model: removing them earlier would mark every answered ISO requirement as needing review |
| R2 | Tenant isolation. Tests run on SQLite; production refuses SQLite and runs on PostgreSQL | Scope every query by tenant in one shared helper, test that tenant A cannot read tenant B for every new table, and add row-level security on PostgreSQL as a second layer |
| R3 | Existing Governance data | Migrate it into the new model in place; no customer data is dropped |
| R4 | Licence. Code in this repository is Apache 2.0 | The ported module is Apache 2.0, like the rest of Fenrir |
| R5 | AI assistance (standalone Phase 5) | Port last, behind the same tenant opt-in; off by default |
| R6 | Data in the standalone app | Demo only, so no import from a standalone database is needed |
| R7 | How a Fenrir user gets an ISMS role (ISMS manager, approver, control owner, staff, auditor, executive) | A separate ISMS role per person per customer (option 2 below); nobody, MSP admins included, sees a customer's ISMS without one. Staff use the client portal. Roles are managed by Fenrir users with `grc` and by ISMS administrators |
| R8 | Standalone plans and usage limits (`plans.ts`) | Not ported: Fenrir's own tenant plans and modules decide what a customer has |

### R7: ISMS roles for Fenrir users

The standalone app gives each person a role per organization, and owners get extra rights on their own records (`fenrir_cloud/isms/access.py`). Fenrir gives each user one platform role (`security.py`). The options:

1. **Derive from the Fenrir role.** `platform_admin`, `msp_admin` and `tenant_admin` act as ISMS tenant admins, other staff roles with `grc` as ISMS managers, `viewer` as executive viewers. No new table, but approvers, auditors and staff cannot be told apart.
2. **A separate ISMS role per person per customer** (a new `isms_memberships` table), managed on the Governance settings page. Fenrir's `grc` permission still gates the module. Customer staff who only acknowledge policies would be portal (`client`) users with the `staff` ISMS role.
3. **Both:** derive a default from the Fenrir role, and let an ISMS role per customer override it.

Decided 25/11/2026: option 2.

## Proving the port

The standalone engine's outputs are recorded by `scripts/isms/parity_fixtures.mts` (run against a checkout of the frozen baseline) into `cloud/tests/fixtures/isms_parity.json.gz`, and `cloud/tests/test_isms_parity.py` requires the Python port to give the same results: same decisions, same order, same reasons. Each ported piece of domain logic adds its cases to that script. The standalone unit tests are ported to pytest alongside the code.

## Phases

Each phase is a set of small vertical slices: migration, domain logic, API, console page, tests (pytest, console tests, and an isolation test for every new table).

1. **Foundation.**
   - Done: `fenrir_cloud/isms/` package; content pack schema, loader and validator, with the licence check as a test (`tests/test_isms_content.py`); every standalone pack (common controls, ISO 27001, ISO 22301, ISO 42001, Cyber Essentials, NCSC CAF, NIST CSF 2.0, UK GDPR, templates, questionnaires); expression language and applicability engine, held to the standalone engine by the parity test.
   - Done: the rest of the pure domain logic (readiness scoring, risk method, task recurrence, RACI and competence, nonconformity, audit checklist and sampling, objectives, review inputs, digest schedule, CSV import, suppliers, incidents, privacy, business impact analysis, AI management), each held to the standalone engine by recorded cases; ISMS roles and permissions (`isms/access.py`); the tenant-scoping helper (`isms/scope.py`) and its isolation test, which every new ISMS table must join.
   - Done: decision R7. Phase 1 is complete.
2. **Core register.** Organization and scope, context and interested parties, assets, controls and assessments, Statement of Applicability, risk method and register, evidence (validity, reminders, links to automated GRC signals), tasks and calendar. Migrate existing Governance data.
   - Done: ISMS roles (`isms_memberships`, migration 88) with the API (`/api/console/isms`), audit events and the **ISMS roles** tab; row-level security on PostgreSQL (`isms/rls.py`), tested on a real server by `tests/test_isms_rls.py` with a non-superuser account.
   - Found: the official PostgreSQL image makes `POSTGRES_USER` a superuser, and superusers bypass row-level security, so a default install relies on the application's tenant scoping alone. The platform readiness page now says so. Moving installs to a non-superuser database account is a separate deployment change.
   - Done: organization and scope (scope with versions, context issues, interested parties, legal entities, sites) and the asset register with all-or-nothing CSV import (migration 89), with the **Organization** and **Assets** tabs.
   - Next: controls and assessments, then onboarding answers and the Statement of Applicability.
3. **Documents.** Templates, generation to Word and PDF, approval with immutable versions, acknowledgement.
4. **Management system.** People and training, internal audit, management review, improvement, objectives and metrics, ISMS change log.
5. **Assurance and MSP.** Auditor portal, supplier and incident links, portfolio view across customers, template push, dashboards and digests.
6. **Extra packs.** Privacy, business continuity, AI management.
7. **AI assistance**, last and off by default (R5).
8. **Retire the old Governance code** once every page and API has moved and data migration has run on a copy of real data.

## Acceptance

- Every acceptance criterion in the baseline's `docs/05-build-plan.md` is met inside Fenrir.
- The baseline's Phase 2 hand calculation (`docs/08-readiness-hand-calculation.md`) gives the same readiness figures.
- Existing Governance programmes, answers, policies and evidence open unchanged after migration.
- `make test` and the console tests pass.
