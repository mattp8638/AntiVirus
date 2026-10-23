# MSP module increment

This increment builds on merged Phase 1 hardening (main commit `1607f86412133efeee6d2167062fd70202e62c79`). It adds usable workflows across the six agreed module areas. It is not the completion of the full platform roadmap.

## Implemented

| Area | Available behavior |
| --- | --- |
| Documentation and credential vault | Existing KB articles gain revision snapshots, restore history and starter templates. New articles can belong to a selected customer. Encrypted credentials support metadata editing, archiving and audited, freshly authenticated reveal. |
| Microsoft 365 | Customer-specific encrypted application credentials; on-demand, read-only Graph snapshots of users, subscribed licences and Secure Score; secret replacement; failed sync preserves the previous snapshot. |
| Network monitoring | Scheduled TCP availability and latency checks of explicitly configured IP/port pairs; bounded recent samples; alert after three consecutive failures and resolution on recovery; pause/resume and manual check. |
| SIEM/XDR | Tenant-scoped external event ingestion into the existing detection pipeline, source/event deduplication, immutable text evidence with SHA-256 fingerprints and expiring rule suppressions. External events do not apply native agent device-state side effects. |
| GRC/ISMS | Customer risk, policy, evidence, audit and exception records; framework/control references; likelihood/impact scoring; due reviews; reauthentication and future review dates for approval/acceptance. |
| Backup/DR | Protection plans linked to existing configurations and runbooks; idempotent provider-result reporting; RPO freshness; audited recovery exercise request/approval/completion with evidence, duration and RTO assessment. |

New console screens reuse existing tenant selection, authentication, error handling and tables. Related configurations, documents and detection rules are selected by name. The existing KB, device, incident, alert, event, audit and encryption implementations remain canonical.

## Operational boundaries

- Migrations 3 and 4 add new tables. They do not replace existing databases, change agent wire protocols, drop columns or rewrite existing module records. Migration tests cover both legacy adoption and an existing version-2 database.
- Network probes originate from the Fenrir cloud server. A private customer address must be reachable from that server through an operator-managed network path. Only literal IPs are accepted; loopback, link-local/metadata, multicast, unspecified, reserved and IPv4-mapped IPv6 addresses are rejected. There is no discovery scan, SNMP collector or topology engine in this increment.
- A monitor keeps its latest 100 samples. Scheduler batches are bounded to ten monitors, with two-second connection timeouts. Capacity and scheduling latency at MSP fleet scale still need load testing.
- Vault metadata is ordinary customer data; put passwords only in the secret field. Ciphertext uses the existing authenticated encryption/key-rotation registry and tenant/record-specific associated data. The console removes revealed secrets after 30 seconds or when the customer/modal changes.
- Microsoft 365 registration requires application permissions `User.Read.All`, `LicenseAssignment.Read.All` and `SecurityEvents.Read.All`, with admin consent in the customer directory. Synchronization uses Microsoft public-cloud Graph v1.0 endpoints. Pagination stays on that origin and is bounded by page, record and elapsed-time limits. Each HTTP request also has a timeout. No user, licence or policy changes are sent to Microsoft.
- Backup results are operator/API reports from an existing provider. Fenrir does not execute backup or restore jobs in this increment. Approving a recovery exercise records approval; it does not invoke a vendor API.
- GRC framework names and control references are mappings supplied by the operator. They are not complete licensed control libraries, an automated certification assessment or legal advice.
- Suppressions apply to new alert creation for a selected rule and customer until expiry. Existing alerts and ingested events remain available. Text evidence is immutable through this API; the hash verifies content consistency and is not a cryptographic proof of collection provenance.

Microsoft permission references: [List users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0), [List subscribedSkus](https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0), [List secureScores](https://learn.microsoft.com/en-us/graph/api/security-list-securescores?view=graph-rest-1.0).

## API entry points

All paths below are under `/api/console` and use existing console authentication and tenant authorization.

- `/documentation/templates`, `/documentation/{article}/revisions`, `/documentation/{article}/restore/{revision}`; articles remain under `/psa/kb`.
- `/vault/credentials`, `/vault/credentials/{credential}/reveal`.
- `/m365/connections`, `/m365/connections/{connection}/secret`, `/m365/connections/{connection}/sync`.
- `/network/monitors`, `/network/monitors/{monitor}/check`.
- `/soc/ingest`, `/soc/incidents/{incident}/evidence`, `/soc/suppressions`.
- `/grc/frameworks`, `/grc/records`, `/grc/records/{record}/review`.
- `/backup/plans`, `/backup/plans/{plan}/runs`, `/backup/plans/{plan}/exercises`, `/backup/exercises`.

Request schemas and methods are exposed through the application's OpenAPI document.

## Verification and remaining work

Verified locally on 2026-10-23: cloud pytest suite **124 passed** (one upstream Starlette/httpx deprecation warning); TypeScript **passed**; Vite production build **passed**. Browser verification confirmed module navigation, form rendering and saving a synthetic governance record.

Automated coverage includes tenant boundaries, encryption/reveal/rotation/archive, revision restore, Graph pagination and error redaction, retained snapshots, monitor alert/recovery, GRC approval safeguards, backup idempotency and exercise transitions, external-ingest deduplication, native-device-state preservation, evidence hashing, suppression expiry and additive upgrades.

Local console verification uses a separate synthetic SQLite database with scheduler and feed synchronization disabled. No production data or customer credentials are used.

Live Microsoft tenant integration, PostgreSQL execution, customer-network checks and vendor backup execution have not been verified in this environment. Remaining roadmap work includes granular document sharing and richer relationships, M365 administration and scheduled synchronization, network discovery/SNMP/topology, additional SIEM collectors and binary evidence, complete GRC control libraries and richer treatment workflows, and provider-specific backup/restore adapters. These should be delivered in later reviewed increments.
