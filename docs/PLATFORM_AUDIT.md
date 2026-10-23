# Platform audit and expansion plan

Baseline recorded on branch `claude/jolly-goodall-5kpl2t` before the MSP expansion work.

## What exists

| Layer | Technology | Notes |
|---|---|---|
| Cloud API | Python 3.11+, FastAPI, SQLAlchemy 2 | One `models.py` (by design: modules reference each other), routers per area, `create_all` + `ensure_columns` for additive migrations |
| Database | SQLite (dev/tests) or PostgreSQL 16 (Docker) | Tests run on both (`FENRIR_TEST_DATABASE_URL`) |
| Background work | One 30-second scheduler thread and one hourly maintenance thread inside the API process | RMM tasks, monitors, patch windows, PSA timed workflows, remote session expiry, IMAP |
| Auth | scrypt passwords, HMAC-signed bearer tokens, roles mapped to permissions (`security.ROLE_PERMISSIONS`) | Tenant tree scoping in `deps.Principal` (`check_tenant`, `scoped_tenant`); no MFA, no rate limiting, no step-up auth |
| Audit | Hash-chained `audit_log` with `/audit/verify` | |
| Console | React 18 + Vite + TypeScript, no UI library | Shared components in `components/ui.tsx` (`PageHead`, `Table`, `Modal`, `Tabs`, `Stat`, `Pill`, `Sev`, `useData`, `useAction`) |
| Agents | Windows C++ service + helpers, Linux Go agent, macOS Swift | HTTPS polling + realtime WebSocket wake; commands queued in `commands` table |
| Deployment | `deploy/Dockerfile` (console + agents + API in one image), `deploy/docker-compose.yml` with PostgreSQL | |

### Existing module coverage against the brief

| Brief area | Already present | Gaps |
|---|---|---|
| Endpoint security | Policies (181 settings), quarantine, scans, YARA, ML model, isolation, tamper protection (Windows) | Protection-health rollup, protection-disabled/offline alerting views, safe validation test |
| Vulnerability management | OSV/distro scanning, CVSS, KEV flag, status workflow | Risk acceptance with expiry/approver, ticket linking, verified-fix rule, trends, asset criticality |
| RMM | Scripts, jobs, automation, patching (rings, windows, approvals), software, monitors, remote access | Retry of failed jobs |
| PSA | Boards, SLAs (business hours), workflows, time, agreements, dispatch, email-to-ticket, CMDB, KB, quotes, projects, portal | Ticket↔vulnerability links, problem/change types (board types cover this) |
| CRM | Contacts, leads/pipeline, projects, contracts, invoices | Renewal tracking |
| SIEM/XDR/SOC | Event ingestion (agents), Sigma + correlation rules, alerts, incidents with playbooks and timeline, SOAR automations, IOCs, threat feed, hunting, MITRE coverage | Syslog/cloud ingestion, alert suppression windows, evidence attachments, incident assignment/escalation SLA, source labelling (native vs third-party), metrics |
| Compliance | Continuous scoring of CIS/NIST/ISO-style controls from policy and fleet state | No risk register, policies, evidence store, audits, exceptions, framework libraries (ISO 27001:2022, CE, CAF, UK GDPR) |
| Microsoft 365 | none | whole module |
| Network monitoring | none (external attack-surface scan only) | whole module |
| Backup & DR | none | whole module |
| Documentation & vault | KB articles, CMDB configurations | versioned docs, templates, encrypted credential vault |

## Plan (executed in this order)

1. **Shared foundation**
   - Envelope encryption (`crypto.py`, AES-256-GCM via the `cryptography` library, key from `FENRIR_VAULT_KEY`/`FENRIR_VAULT_KEY_FILE`, tenant-bound associated data, key IDs for rotation).
   - Durable event outbox (`events.py`) with idempotency keys, retries with back-off, dead-lettering and an admin view.
   - TOTP MFA, step-up re-authentication tokens for sensitive actions, login/reveal rate limiting.
   - New permissions (`vault`, `grc`) mapped onto existing roles without removing any existing permission.
2. **Documentation & vault, Microsoft 365, network monitoring** — new tables, routers, console pages, tests.
3. **SIEM/XDR/SOC enhancements** (extending existing events/alerts/incidents, not replacing them) and **GRC/ISMS** (extending `compliance.py`).
4. **Backup & DR**, cross-module event chains (vulnerability → ticket → patch → verification → evidence), documentation, final verification.

Canonical records are reused throughout: `Tenant` (customer), `User`, `Device`/`Configuration` (assets), `Alert`/`Incident`, `Ticket`, `Contract`, `Vulnerability`, `KbArticle`.

Rules followed: changes are additive; no existing route, column or behaviour is removed; new columns are nullable so `ensure_columns` can add them to existing databases.
