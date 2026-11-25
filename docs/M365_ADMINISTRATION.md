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

## Enterprise apps, app registrations and consent (M365-11)

The **Apps and consent** tab lists:
* app registrations, with their secrets, certificates and directory extension properties;
* enterprise apps (service principals): publisher (this tenant, Microsoft, or another organisation), on or off, and
  their permissions;
* pending admin consent requests.

The code is in `cloud/fenrir_cloud/m365_apps.py`.

**Permission contract.** Every permission is labelled *application* or *delegated*:
* *application* permissions are app role assignments. They work with no user signed in, across the tenant.
* *delegated* permissions are OAuth2 grants. They act only as the signed-in user, and the consent is either admin
  (all users) or one user.

Each app is summarised as acting with application permissions, delegated permissions, or both. High-privilege
permissions (for example `Mail.ReadWrite`, `Directory.ReadWrite.All`, `Application.ReadWrite.All`) are flagged.

**Credential expiry.** Fenrir checks every app daily. Each secret or certificate that has expired, or expires within
30 days, raises one alert: high severity if expired, medium if expiring. The same alert is not raised twice.

**Actions.** You can:
* turn an enterprise app off or on;
* remove an *expired* secret or certificate;
* revoke a delegated consent grant.

Each action requires step-up authentication and typing the app's name, and is audited. A working credential cannot be
removed here, and Fenrir's own app cannot be turned off.

The actions need `Application.ReadWrite.All` and `DelegatedPermissionGrant.ReadWrite.All`. Fenrir does **not**
request them by default (feature *apps.manage* is opt-in), because `Application.ReadWrite.All` can be used to grant
any permission. Consent requests are approved in the Entra admin centre.

## Scheduled absences (M365-09)

The **Absences** tab on a tenant schedules a user's absence: automatic replies, forwarding to a colleague (optionally
without keeping a copy) and calendar access for delegates. The code is in `cloud/fenrir_cloud/m365_absence.py`.

When the absence starts, Fenrir first records the user's current automatic replies and calendar permissions. Then it
applies each part:
* automatic replies use Microsoft's own scheduled window, so they start and stop on time even if Fenrir is
  unreachable;
* forwarding is an inbox rule named "Fenrir: absence forwarding";
* each delegate gets calendar permission.

Each step's progress is saved as it happens, so a retry never repeats a step that already succeeded.

When the absence ends, Fenrir reverts only what it changed:
* it removes the rule it created;
* it removes the calendar permissions it granted (a delegate who already had access keeps it);
* it puts the automatic replies back. A recorded schedule that has already passed is not brought back.

A failed step is retried every minute. After five failures the absence becomes *revert failed*, a high-severity alert
lists exactly what is still in place (for example, forwarding left on), and the audit log records it. **Try reverting
again** retries the revert.

Scheduling forwarding or delegation requires step-up authentication. Absences for the same user cannot overlap. The
connection needs `MailboxSettings.ReadWrite` and `Calendars.ReadWrite` (feature *Scheduled absences*).

## Tenant configuration backup, comparison and restore (M365-14)

The **Configuration backup** tab on a tenant backs up its configuration every day, and on demand. The code is in
`cloud/fenrir_cloud/m365_config.py`.

What is backed up:
* Conditional Access policies and named locations
* the authorization policy (user and guest defaults)
* security defaults
* the authentication methods policy
* Intune compliance policies and configuration profiles

Read-only fields are dropped, and every object gets a SHA-256 (the snapshot gets one too). A resource Microsoft will
not return, for example for lack of permission or licence, is recorded with the reason. It is never stored as empty.

**History.** A new version is kept only when something changed. Each version lists what was added, removed and
changed since the previous one, field by field.

**Comparison.** Any two versions can be compared, including versions from different tenants. References to groups,
users and named locations are compared by name, so the same policy in two tenants matches even though the IDs differ.

**Restore** is planned first. Planning reads the target tenant (the same tenant or another customer's) and writes
nothing. For each chosen object the plan shows one of:
* *create*;
* *update*, with the fields that would change;
* *unchanged*;
* *blocked*, with the reason.

References are translated by name:
* groups by display name;
* users by user principal name;
* named locations by display name. A named location restored in the same run is created first.

A reference with no match in the target blocks the object. Conditional Access policies are written report-only unless
**Keep state** is chosen.

Running a restore requires all of the following:
* step-up authentication;
* typing the number of objects it will change;
* a plan less than 30 minutes old.

A restore runs only once. Each object's result is recorded and audited. A snapshot that no longer matches its SHA-256
is refused.

**Not restored**, as the page says:
* The authentication methods policy is backed up and compared only. Microsoft accepts it one method at a time, with
  group targets.
* Intune assignments are not backed up.
* Intune profiles holding encrypted values (Wi-Fi keys, VPN secrets, encrypted OMA-URI settings) cannot be read back
  from Microsoft, so they cannot be restored.

## Bulk and scheduled actions across tenants (M365-30)

**Microsoft 365 across customers → Bulk actions** runs one action against many tenants, or against many users
across tenants. The code is in `cloud/fenrir_cloud/m365_bulk.py` and `routers/m365_bulk.py`.

Supported actions:
* Check a standard (read-only).
* Deploy a standard. A tenant that is already compliant is skipped.
* Sign users out everywhere.
* Block or allow sign-in.
* Update department, job title or usage location.

Actions that produce secrets (password resets, Temporary Access Passes) and actions that create objects are not
available in bulk.

**Fixed targets.** Each target is checked when the job is created:
* the customer is one you manage;
* the connection is working;
* the connection's last permission check does not show the action missing.

Targets that fail a check are listed with the reason. The rest are stored with a SHA-256 of the list, and the job
cannot be edited. If the stored list no longer matches its hash, the job is refused without running anything.

**Confirming a job.** Creating a job that changes tenants requires step-up authentication and typing the number of
targets.

**Run-time checks.** Before each item runs, Fenrir checks again that the technician who created the job:
* is still active;
* still holds the permission;
* still reaches the customer.

It also checks that the connection still exists. If any check fails, that item is skipped with the reason.

**Throttling.** When Microsoft returns 429 with Retry-After, the item and the rest of that tenant's items wait until
then. Other tenants carry on. After five throttled tries, the item fails.

**Checkpoints and unknown outcomes.** Each item's outcome is committed before the next item starts. An item left
running by a crash becomes `unknown` and is never sent again. **Reconcile** reads the tenant to settle unknown items:
* sign-in state and profile fields are read from the user;
* standards are re-evaluated;
* sign-outs leave no state to read, so a technician must mark them done, not done, or retry.

**Cancelling.** Cancelling stops new items from starting.

**Scheduling.** A job can be scheduled up to 90 days ahead. The scheduler starts it at that time and continues
running jobs every 30 seconds. **Run now** works through a job straight away.

**Results.** Counts are kept per status and per customer, and each customer's audit log gets its own result entry. A
job ends as `completed`, `partial`, `failed` or `cancelled`.

## Reference material

Reviewed official CIPP documentation on 2026-10-23:

- [Recommended first steps: navigation, bulk actions and tenant administration](https://docs.cipp.app/setup/implementation-guide/recommended-first-steps)
- [GDAP management](https://docs.cipp.app/user-documentation/tenant/gdap-management)
- [Tenant onboarding](https://docs.cipp.app/setup/installation/gdap-invite-wizard)
- [Standards and drift](https://docs.cipp.app/user-documentation/tenant/standards)

This document records Fenrir's target scope; it does not claim copied implementation or completed CIPP parity.
