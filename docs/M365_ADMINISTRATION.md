# Microsoft 365 administration: CIPP reference scope

## Product requirement

The Microsoft integration must grow into a tenant administration workspace with usability and functional coverage comparable to CIPP. Read-only snapshots are the foundation, not the target outcome. This requirement was clarified by the owner on 2026-10-23.

Use CIPP's documented workflows as a product reference. Implement within Fenrir's existing architecture and design system. Feature parity must be tracked explicitly; do not describe unfinished features as available.

## Required workflows

| Area | Target functionality |
| --- | --- |
| Tenant workspace | Searchable tenant switcher; overview, domains, service health, subscription/licence usage, permission and connection health; consistent navigation and contextual actions. |
| Onboarding | Direct-tenant onboarding and partner/GDAP onboarding, relationship status, role mappings, consent and credential-health diagnostics. |
| Identity | User creation and editing; groups and memberships; licence assignment/removal; password reset, session revocation and sign-in controls; supported MFA/authentication-method administration. |
| Lifecycle | Guided onboarding/offboarding templates with a review of each planned step, partial-failure reporting and resumable execution. |
| Exchange | Mailboxes, shared mailboxes, delegation, aliases, forwarding, distribution groups and supported mail-flow/security administration. |
| Collaboration | Supported Teams, SharePoint and OneDrive settings, sharing controls and administration. |
| Devices | Intune device inventory, compliance/configuration policies and supported remote actions, with explicit target and impact review. |
| Security | Supported Conditional Access, Defender and identity-security settings; security posture, audit/sign-in visibility and alert investigation. |
| Standards | Reusable per-tenant or tenant-group baselines with report, alert and explicitly enabled remediation modes; drift history, exceptions and exclusions. |
| MSP operations | Search/filter/export, bulk operations, scheduled work, progress and per-target results, detailed audit records and links to related Fenrir records. |

These are required coverage areas, not assertions that every Microsoft administrative operation is available through an API. Each operation needs a verified supported Microsoft API or management interface and an explicit permission/licensing matrix. Unsupported operations must be identified in the UI and coverage matrix rather than silently simulated.

## Architecture and usability acceptance criteria

- Reuse the existing tenant model, encrypted connection storage and rotation, scoped authorization, reauthentication, audit and durable event mechanisms.
- Keep the current read-only connection flow working. Add capabilities incrementally; do not require broad write consent to retain read-only inventory.
- Separate connection credentials and provider permissions from technician authorization. Introduce specific Microsoft administration permissions rather than granting every write operation to all users with general configuration access.
- Use Microsoft Graph where supported. Verify requirements for Exchange and other workload interfaces before selecting adapters. GDAP/delegated and application-only authentication need separate capability checks.
- Every write action shows the selected customer, target objects, proposed changes and required access. Sensitive/destructive operations require appropriate step-up and explicit confirmation.
- Bulk and scheduled operations use durable jobs, bounded retries, Microsoft throttling guidance, deduplication where supported and per-target results. Never blindly retry an ambiguous non-idempotent action.
- Do not expose application secrets, access tokens, temporary passwords or sensitive request bodies in logs, job results or audit metadata.
- Show refreshed provider state after a successful action. Clearly label cached data, permission failures and partial completion.
- Test permission denial, tenant isolation, provider errors, throttling, retry behavior and sensitive-data redaction. Distinguish mocked integration tests from live-tenant verification.
- Preserve agent protocols and all other modules. No automatic production deployment or merge into main.

## Delivery order

1. Tenant administration shell, capability/permission diagnostics and durable action execution with audit.
2. User, group and licence management; explicit sensitive-action controls.
3. Guided onboarding/offboarding and Exchange mailbox administration.
4. Intune, collaboration and security administration.
5. Standards/drift, bulk scheduling and partner/GDAP lifecycle completion.

Each delivery must contain working UI and API behavior, regression tests and a draft PR. Track features as implemented, mock-tested, live-verified or pending. Full CIPP-equivalent coverage remains pending until those criteria are satisfied.

## Current implementation

The first reviewed write-administration increment is described in [M365_ACTIONS.md](M365_ACTIONS.md), including verified scope and remaining work.

PR #9 provides encrypted direct-tenant application connections and on-demand, read-only users, subscribed licences and Secure Score snapshots. It does not yet implement tenant write administration, GDAP, workload management or baseline enforcement. No live tenant changes have been made as part of this requirement update.

## Reference material

Reviewed official CIPP documentation on 2026-10-23:

- [Recommended first steps: navigation, bulk actions and tenant administration](https://docs.cipp.app/setup/implementation-guide/recommended-first-steps)
- [GDAP management](https://docs.cipp.app/user-documentation/tenant/gdap-management)
- [Tenant onboarding](https://docs.cipp.app/setup/installation/gdap-invite-wizard)
- [Standards and drift](https://docs.cipp.app/user-documentation/tenant/standards)

This document records Fenrir's target scope; it does not claim copied implementation or completed CIPP parity.
