# ISMS rewrite into Fenrir: plan

Status: draft for review. Date: 20/11/2026.

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
| Content packs (YAML, zod) | YAML packs under `grc_library/`, validated with pydantic, every item with a `licence` field |
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

## Decisions needed before building

| Id | Question | Recommendation |
| --- | --- | --- |
| R1 | Requirement text. Fenrir's library holds short summaries of each ISO 27001 requirement; the standalone app allows identifiers and short titles only | Identifiers and short titles only, with original guidance. Remove the summaries from the ISO pack |
| R2 | Tenant isolation. Fenrir supports SQLite and PostgreSQL, so row-level security cannot be the only guard | Scope every query by tenant in one shared helper, test that tenant A cannot read tenant B for every new table, and add row-level security on PostgreSQL as a second layer |
| R3 | Existing Governance data | Migrate it into the new model in place; no customer data is dropped |
| R4 | Licence. Code in this repository is Apache 2.0 | Accept: the rewritten module is Apache 2.0, like the rest of Fenrir |
| R5 | AI assistance (standalone Phase 5) | Port last, behind the same tenant opt-in; off by default |

## Phases

Each phase is a set of small vertical slices: migration, domain logic, API, console page, tests (pytest, console tests, and an isolation test for every new table).

1. **Foundation.** `fenrir_cloud/isms/` package; content pack schema, loader and validator (with the licence check in CI); common control library and ISO 27001, Cyber Essentials, NCSC CAF and NIST CSF packs; applicability engine and onboarding questionnaire; ISMS permissions and roles.
2. **Core register.** Organization and scope, context and interested parties, assets, controls and assessments, Statement of Applicability, risk method and register, evidence (validity, reminders, links to automated GRC signals), tasks and calendar. Migrate existing Governance data.
3. **Documents.** Templates, generation to Word and PDF, approval with immutable versions, acknowledgement.
4. **Management system.** People and training, internal audit, management review, improvement, objectives and metrics, ISMS change log.
5. **Assurance and MSP.** Auditor portal, supplier and incident links, portfolio view across customers, template push, dashboards and digests.
6. **Extra packs.** Privacy, business continuity, AI management.
7. **AI assistance**, if R5 is accepted.
8. **Retire the old Governance code** once every page and API has moved and data migration has run on a copy of real data.

## Acceptance

- Every acceptance criterion in the baseline's `docs/05-build-plan.md` is met inside Fenrir.
- The baseline's Phase 2 hand calculation (`docs/08-readiness-hand-calculation.md`) gives the same readiness figures.
- Existing Governance programmes, answers, policies and evidence open unchanged after migration.
- `make test` and the console tests pass.
