# Microsoft 365 administration scope

Fenrir is not yet a like-for-like CIPP replacement. This is a scope record, not a certification of live Microsoft behaviour.

## Available workflows

**Workspace (batch 1).** Microsoft 365 opens on an overview of every connected tenant: users, guests, MFA registration, Secure Score,
unused licences, global admins, open Microsoft service issues and licensed users who have not signed in for 90 days. Each tenant has a
workspace with its organisation, domains, administrators and their roles, service health and inactive users. Snapshots refresh in the
background every `FENRIR_M365_SYNC_HOURS` (6).

**Permissions.** The Permissions tab reads the connection's own access token and lists each feature as available or missing, with the
Microsoft permission it needs (`m365_permissions.py`). **Update permissions** brings a connection up to date:

- GDAP: Fenrir replaces the customer consent through Partner Center.
- Admin sign-in: sign in again; Fenrir reuses its app and adds the new permissions.
- Platform app or manual app: Fenrir lists what to add.

**Log store.** Sign-in and directory audit records are copied every hour and kept for `FENRIR_M365_LOG_RETENTION_DAYS` (730). Microsoft
itself keeps 7 days, or 30 with Entra ID P1/P2. They can be searched by user, app, IP, place or activity, filtered by result and date,
and exported to CSV. A tenant without P1/P2 has no sign-in log from Microsoft; this is shown, and asked again once a day. A busy tenant
that produces more records than one run fetches catches up through remembered gaps.

**One-off actions (batch 2).** Every change is prepared, shown for review, and needs fresh authentication and an explicit confirmation.
Fenrir never replays a running or unknown write. Available actions:

- edit profile, set manager;
- block or allow sign-in, sign out everywhere;
- reset password: a random password, shown once and never stored;
- reset MFA: removes every method except the password, and reports partial results;
- Temporary Access Pass: shown once;
- temporary admin role for 1 to 72 hours: removed automatically within a minute of expiry, or early on request; an alert is raised if
  removal keeps failing, and Fenrir refuses a role the user already holds;
- assign or remove a licence, add or remove a group member;
- new user, new security or Microsoft 365 group with an owner, guest invitation.

**Onboarding, offboarding and bulk import.** These are planned first (read-only: every change listed), then run step by step. Each step's
outcome is recorded. A failed step can be retried. An unknown step waits until a technician checks Microsoft and marks it done, to
retry, or skipped.

- Offboarding: block, revoke, random password, MFA removal, out-of-office (app connections), ordinary groups, admin roles, licences
  (with the mailbox warning), the Fenrir contact marked as left, and a ticket listing what was done and what is left by hand.
- New starter: user, manager, licences, groups, a Fenrir contact and a ticket, with the temporary password shown once.
- Bulk import from CSV: up to 200 users, with rows that cannot be created listed and skipped. It runs in time-boxed passes so no web
  request is held open, and the passwords are downloadable once.

**Hybrid identity (AD-synced users).** For users that Entra Connect syncs from on-premises Active Directory, AD is in charge:
Microsoft refuses cloud changes to the account's name, sign-in and password, and to synced groups. Fenrir:

- marks each user as managed in Active Directory or Microsoft 365, and explains a refused change instead of failing silently;
- offboards a synced user on the customer's domain controller through the Fenrir agent: disable, a random password generated on the
  DC, removal from AD groups, an optional move to a leavers OU, optional hiding from the address book, the leaving date in the
  description, then an Entra Connect delta sync on the server that runs it. The Microsoft 365 steps follow (sessions, MFA,
  out-of-office, cloud groups, licences);
- creates a new starter in AD (OU, AD groups, manager) with a temporary password shown once, starts a sync, waits for the user to
  appear in Microsoft 365, then sets the usage location, licences and Microsoft 365 groups.

AD changes are an allowlisted agent command (`ad.directory`) that can only be sent by these runs. A new starter's password travels
encrypted and is released once to the domain controller the command went to. Steps waiting on a server or on Entra Connect
continue in the background every minute. Needs the Fenrir agent on a domain controller (and, to sync at once, on the Entra Connect
server); without it the AD part is listed for doing by hand.

Users with the `m365_admin` permission can run changes. Viewing needs `configure`.

## Phase plan and exit

This work is the Microsoft 365 phase in `parity/progress.md`. Each batch exits only when the owner has run
[the test plan](M365_TEST_PLAN.md) on a real tenant and reported the results (AT-35). Remaining batches:

3. Exchange: mailboxes, shared mailboxes, permissions, forwarding, aliases, distribution lists, mail rules, quarantine, message trace.
   This uses the Exchange Online admin interface, because Graph does not cover it.
4. Security: Conditional Access templates and named locations, compromised-account check, SPF/DKIM/DMARC check, audit-event alert rules
   into the SOC.
5. Intune: device actions, BitLocker and LAPS keys, app deployment, Autopilot.
6. Standards: from 4 to about 60, with templates, tenant groups, drift and exceptions.
7. Reports: licence waste, external sharing, mailbox sizes, Teams/SharePoint usage, scheduled email reports.
8. Teams, SharePoint and OneDrive.

Not planned here: Purview (DLP, retention, labels) and Copilot administration (catalogue M365-27, M365-29).

## Verification

Session-revocation tests simulate Microsoft responses: bodyless POST, member-only
validation, unconfirmed results and timeout handling. Existing action tests cover
review, fresh authentication, audit, expiry and duplicate execution protection.
Live tenant consent and endpoint/session behaviour still require a test tenant.

References:
- https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0
- https://docs.cipp.app/user-documentation/tenant/standards
- https://docs.cipp.app/user-documentation/cipp/settings/tenants


## New-user creation

Users > New user supports cloud member accounts in verified managed domains.
Required Graph application permissions: User.ReadWrite.All and Domain.Read.All,
with administrator consent. Microsoft validates its own password policy.
The preview checks domain verification and duplicate sign-in names; execution
rechecks both. Federated provisioning is explicitly unsupported.

The temporary password is entered at execution, sent to Microsoft, and omitted
from stored action parameters, previews, results and audit details. It must be
12–128 characters and is cleared from the form after the execution attempt.
It must be delivered securely by the administrator; no email is sent.
Password change is required at first sign-in. Account creation enables sign-in.
Licence assignment and group membership are subsequent reviewed actions; this
release does not claim atomic onboarding or mailbox provisioning.

A create action uses its request UUID as the action target until Microsoft
returns the real user UUID in result.user.id. A timeout becomes unknown and
must be reconciled in the directory; retries do not repeat the write.
