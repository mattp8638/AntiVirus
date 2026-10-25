# CIPP comparability audit — 25 October 2026

## Method and conclusion

Compared official CIPP workflow documentation with Fenrir's Microsoft 365 provider,
API routes, UI and regression tests. This is a workflow-level audit, not a line-by-line
review of CIPP's source or a claim to cover every CIPP feature. Fenrir is not yet a
comparable replacement. Tests mock Microsoft; no live customer tenant was changed.

Implementation evidence: cloud/fenrir_cloud/m365_admin.py,
cloud/fenrir_cloud/routers/m365_admin.py, console/src/pages/M365Administration.tsx,
and cloud/tests/test_m365_*.py. Inventory is not counted as administration parity.

| Workflow | Fenrir state after this batch | Remaining acceptance requirements |
|---|---|---|
| New cloud user | Implemented: verified managed domain, profile, temporary password, review and audit | Live tenant create/sign-in test; bulk import and federated workflows absent |
| User profile | Display name, department, job title, usage location | Broader contact fields, manager and bulk editing |
| Sign-in state | Enable/block actions implemented | Live consent and target-role checks |
| Session revocation | Implemented for member users | Live expiry behaviour; external accounts managed at home tenant |
| Password reset / TAP / MFA methods | Not implemented | Least-privilege permissions, role restrictions, protected secret delivery, audit |
| Licences | Individual assign/remove implemented | Disabled-plan editing, inherited licences, bulk assignments and capacity checks |
| Groups | Add/remove members for supported groups | Create/delete groups, owners, bulk membership, Exchange and dynamic group workflows |
| Onboarding | Create followed by separate licence/group actions | Durable multi-step jobs, partial-failure recovery, templates, scheduling |
| Offboarding | Individual block/revoke/remove-licence actions only | Reviewed ordered workflow, per-step outcomes, mailbox/OneDrive handover and scheduling |
| Exchange | No equivalent management provider | App-only Exchange integration, mailbox types, delegation, forwarding, aliases, auto-replies, mail flow |
| GDAP / partner management | Direct per-directory app connections | Partner consent lifecycle, delegated tenant discovery, relationship expiry and permission refresh |
| Standards and drift | Not implemented for Microsoft tenants | Templates, report/alert/remediate modes, scheduler, exceptions, drift history and rollback limits |
| Conditional Access | No management workflow | Policy preview/diff, validation, exclusions, report-only deployment and change verification |
| Intune policy/application deployment | No equivalent Microsoft workflow | Template import/export, assignments, deployment queue, status and retry behaviour |
| Teams | No management workflow | Create/manage teams, owners and membership; deletion impact review |
| SharePoint / OneDrive | No management workflow | Sites, sharing, permissions, ownership/handover, lifecycle and reporting |
| Microsoft audit/sign-in investigation | Local action history only | Graph audit/sign-in ingestion, filtering, retention and consent/licensing checks |
| Cross-tenant bulk/scheduled actions | Not implemented | Per-tenant permission checks, job state, partial results, rate limiting and cancellation |

## Delivery order and gates

1. Identity: validate new-user creation live, then password reset, guest invitations,
   group lifecycle and licence-plan editing. Gate: successful writes, denied consent,
   invalid target, duplicate request and timeout tests for every operation.
2. Onboarding/offboarding: durable step records with explicit partial outcomes.
   Gate: interrupted execution resumes safely without repeating completed writes.
3. Exchange: a dedicated provider, not assumed Graph coverage. Gate: app permissions,
   actual mailbox changes and licence/retention restrictions verified in a test tenant.
4. Standards, Conditional Access and Intune: reporting first, then reviewed writes.
   Gate: versioned templates, target scope, drift comparison and partial-failure evidence.
5. Teams, SharePoint, OneDrive and partner management: separate provider contracts.
   Gate: customer separation and actual resource effects verified.

Do not label a stage complete on the strength of mocked tests alone. Record live
tenant results, required permissions and unsupported cases alongside each release.

## Official sources reviewed

- Users: https://docs.cipp.app/user-documentation/identity/administration/users
- Offboarding: https://docs.cipp.app/user-documentation/identity/administration/offboarding-wizard
- Exchange: https://docs.cipp.app/user-documentation/identity/administration/users/user/exchange
- Tenant connections: https://docs.cipp.app/user-documentation/cipp/settings/tenants
- Standards: https://docs.cipp.app/user-documentation/tenant/standards
- Intune templates: https://docs.cipp.app/user-documentation/endpoint/mem/list-templates
- Application templates: https://docs.cipp.app/user-documentation/endpoint/applications/application-templates
- Teams: https://docs.cipp.app/user-documentation/teams-share/teams/list-team
- SharePoint: https://docs.cipp.app/user-documentation/teams-share/sharepoint
- User creation contract: https://learn.microsoft.com/graph/api/user-post-users
