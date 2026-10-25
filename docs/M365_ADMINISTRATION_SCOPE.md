# Microsoft 365 administration scope

Fenrir is not a like-for-like CIPP replacement. This is a scope record, not a certification of live Microsoft behaviour.

## Available workflows

Select a connection on the Microsoft 365 page, then select a user in Tenant administration.
Users with the `m365_admin` permission can prepare and review profile, sign-in,
licence assignment and supported group-membership changes. Execution requires fresh
authentication. Profile editing currently exposes display name in the UI; the API
also supports department, job title and usage location.

Session revocation is available as `Revoke sign-in sessions`. The application needs
Microsoft Graph application permission `User.RevokeSessions.All`, plus `User.Read.All`
for target lookup, with administrator consent. No Microsoft changes happen merely
by deploying this code. An operator must review and execute an action.

Revocation invalidates refresh tokens and browser sessions. Microsoft may take
several minutes to apply it. It does not block future sign-ins, and external users
must be managed in their home directory. Fenrir rejects guest or unknown user types.
Unknown write outcomes are not replayed automatically. Check Microsoft before
preparing another action.

## Remaining CIPP parity work

- Delegated partner onboarding and GDAP/CPV permission lifecycle.
- User creation, password-reset delivery and complete onboarding/offboarding.
- Exchange mailbox administration, permissions, forwarding and mail-flow tooling.
- Tenant-wide standards, scheduled evaluation, drift alerts and remediation.
- Full Intune policy/application administration and Conditional Access workflows.
- Teams, SharePoint and OneDrive administrative workflows.

Each area needs its own permission model, provider integration, reviewable actions,
error handling and tests. Existing inventory or posture reporting is not equivalent
to management of those resources.

## Verification

Session-revocation tests simulate Microsoft responses: bodyless POST, member-only
validation, unconfirmed results and timeout handling. Existing action tests cover
review, fresh authentication, audit, expiry and duplicate execution protection.
Live tenant consent and endpoint/session behaviour still require a test tenant.

References:
- https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0
- https://docs.cipp.app/user-documentation/tenant/standards
- https://docs.cipp.app/user-documentation/cipp/settings/tenants
