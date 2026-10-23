# Microsoft 365 reviewed administration

This increment adds real Microsoft Graph adapters and console workflows on top of the read-only connection model. It is the first write-administration increment toward [the CIPP reference scope](M365_ADMINISTRATION.md), not full CIPP parity.

## Available

- Live, searchable users, groups and subscribed licence inventories.
- Read-access diagnostics for those three resources, plus per-operation application-permission requirements. Read success does **not** establish write consent.
- Profile update API limited to display name, department, job title and usage location; the console currently exposes display-name editing.
- Allow/block sign-in, assign/remove a licence, and add/remove a user from an ordinary supported group.
- Named target preview, explicit confirmation, fresh password/MFA reauthentication, a ten-minute preview lifetime, action history and audit records.
- Dedicated `m365_admin` permission for platform, MSP and tenant administrators within their existing tenant scope. General `configure` access alone cannot submit administrative writes.
- Additive migration 5 creates the action ledger. Existing connections, encrypted secrets, snapshots and agent protocols remain intact.

## Execution and failures

Preparing an action reads Microsoft state and stores an immutable operation, target and parameters. Reusing its request UUID returns the same record; a conflicting payload returns 409. Execution atomically claims the prepared record and **commits the running state before making a provider write**.

Provider writes are intentionally outside the existing retrying event worker: replay after a process crash could repeat an operation that Microsoft already applied. Finished outcomes publish a normal platform event for downstream consumers.

This increment executes one reviewed action synchronously. It does not implement a background bulk/scheduling worker. Running, failed, unknown and completed actions cannot be executed again. A crash can leave a record running; an operator must reconcile Microsoft state before preparing a new action. No automatic retry occurs for throttling, provider failures or ambiguous network responses.

A successful write with a failed read-back is recorded as `succeeded_refresh_pending`, not as a failed write. A network error after dispatch, HTTP 408 or server error is recorded as unknown. Microsoft rejection is recorded as failed with a generic message that does not expose tokens or provider bodies.

Group removal always targets the membership `/$ref`, never the user object. Dynamic, synced, role-assignable and Exchange-managed groups are rejected. An already-assigned licence cannot be assigned again through this workflow, preserving existing disabled service plans. Group-derived licence restrictions and other target-specific constraints remain enforced by Microsoft.

## Permissions and operator setup

Keep the existing read-only consent if only inventory is needed. Additional admin consent is required for writes. The application does not automatically grant permissions.

| Operation | Application permissions used by this increment |
| --- | --- |
| Profile update | User.ReadWrite.All |
| Allow/block sign-in | User.EnableDisableAccount.All and User.Read.All |
| Licence assignment/removal | LicenseAssignment.ReadWrite.All and User.Read.All; subscribed-SKU read access for preview |
| Group membership | GroupMember.ReadWrite.All and User.Read.All |
| Group inventory | GroupMember.Read.All or a suitable higher permission |

These are public-cloud, application-only Graph operations. Privileged-user and workload restrictions can require additional Microsoft roles or a different flow; successful read checks do not bypass them.

Official references: [Update user](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0), [Assign licence](https://learn.microsoft.com/en-us/graph/api/user-assignlicense?view=graph-rest-1.0), [Add group member](https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0), [Remove group member](https://learn.microsoft.com/en-us/graph/api/group-delete-members?view=graph-rest-1.0).

## Verification

- Full cloud suite: **140 passed**, one upstream Starlette/httpx deprecation warning.
- TypeScript check and Vite production build passed.
- Local browser verification against simulated Microsoft responses: select user, edit display name, review before/after, confirm, reauthenticate, execute and observe refreshed name and succeeded action.
- Tests cover dedicated permission and tenant isolation, request deduplication, preview expiry, step-up, single dispatch on repeat execution, unknown outcomes, restricted groups, membership reference deletion, preserving disabled licence plans and success with failed refresh.
- Microsoft writes have **not** been exercised against a live customer tenant. PostgreSQL and hosted CI have not been verified locally. The local preview data and provider stubs are scratch files and are not included in the application.

## Still pending

User creation/deletion, password and MFA administration, lifecycle templates, Exchange/Teams/SharePoint/Intune/Conditional Access management, GDAP, role-granular delegation, bulk scheduling, baseline enforcement and richer reconciliation workflows remain future increments.
