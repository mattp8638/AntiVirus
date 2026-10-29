# Microsoft 365 across customers: GDAP, identity standards and Entra ID reconciliation

Console: **MSP operations → M365 partner & standards**. API: `/api/console/m365/partner`, `/api/console/m365/standards`, `/api/console/m365/reconcile`.

## Partner access (GDAP)

1. Register an app in the MSP's **partner** tenant:
   - multi-tenant, with **Allow public client flows** on;
   - **Delegated** Graph permissions `DelegatedAdminRelationship.ReadWrite.All`, `Directory.Read.All`, `Group.ReadWrite.All` and `offline_access`. They must be Delegated: the partner connection signs in as a partner admin, and Microsoft ignores Application permissions for a signed-in user;
   - the customer-side permissions you need, for example `Policy.ReadWrite.ConditionalAccess`, `Policy.Read.All`, `DeviceManagementConfiguration.ReadWrite.All`, `DeviceManagementManagedDevices.Read.All`, `User.ReadWrite.All`, `AuditLog.Read.All` and `Domain.Read.All`;
   - the **Microsoft Partner Center** API's Delegated permission `user_impersonation`, so Fenrir can consent its app in customer tenants. This is a different API from "Partner Customer Delegated Administration";
   - admin consent for all of them. You don't have to set any of this up in the Entra admin centre first. The partner sign-in asks for the partner Graph permissions by name, plus `DelegatedPermissionGrant.ReadWrite.All` for setup, and a Global Administrator approves them on Microsoft's sign-in page by ticking **Consent on behalf of your organization**.
     - Straight after the sign-in, Fenrir uses the setup permission to grant itself the Partner Center API's `user_impersonation` for the organisation (app ID `fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd`). One sign-in can only approve one API, so this would otherwise need a second sign-in.
     - It then removes `DelegatedPermissionGrant.ReadWrite.All` from its own grant, so it does not keep the power to grant permissions.
     - If that step fails, the partner check offers **Approve Partner Center access**, a second sign-in for Partner Center alone.
2. Enter the partner tenant ID and app ID. A client secret is only needed if public client flows are off. This needs MSP staff with `m365_admin` and `manage_tenants`, plus step-up re-authentication.
3. **Sign in as partner admin** with a device code. Use an account that belongs to the partner tenant (not a guest) and is an **Admin Agent** in Partner Center; Microsoft refuses the GDAP APIs to anyone else ("Access to the resource is restricted"). The device code and the refresh token stay encrypted on the server. Microsoft rotates refresh tokens, and Fenrir keeps the newest.
   - **MFA.** Microsoft only lets a partner admin into a customer tenant with an MFA-verified sign-in; otherwise customer tokens fail with AADSTS50076. The sign-in therefore asks Microsoft for MFA, and Fenrir records whether the sign-in was MFA-verified. If a customer still refuses for lack of MFA, the partner check offers **Sign in again with MFA**. The account needs an MFA method registered in the partner tenant.
   - **Partner check** confirms all of this and lists what to fix: the tenant is registered as a partner (`partnerTenantType`), the account is a member and in AdminAgents, the app's permissions are in the token, and Partner Center accepts the sign-in.
4. **Create with recommended roles** makes a GDAP relationship with 15 least-privilege roles and locks it for approval. Global Administrator is deliberately excluded. The relationship lasts 730 days and auto-extends by 180 days. Send the invitation link to the customer's Global Administrator. Fenrir never approves for the customer.
5. **Create role groups** makes one partner security group per role ("Fenrir GDAP - Exchange Administrator" and so on). Existing groups are reused by name.
6. When a relationship is active, **Assign role groups** maps each group to its role. Existing assignments are left alone. Partner staff get each role through group membership.
7. **Customers in your partner tenant** merges the CSP customer list (Graph `/contracts`), GDAP relationships and GDAP customers, with each customer's GDAP state. **Import all** (or **Import** on one row):
   - creates a Fenrir customer for each Microsoft customer, or reuses one already linked to that directory or with the same name;
   - consents the Fenrir app in the customer tenant through Partner Center (`applicationconsents`), the way CSP partners grant apps without asking each customer;
   - connects Microsoft 365 through GDAP where a relationship is active, as in step 8;
   - with **Import and invite to GDAP**, creates a GDAP relationship for a customer that has none and returns its invitation link.
   With **Import new GDAP customers automatically**, newly active GDAP customers are imported every 6 hours. Invitations are never sent automatically.
8. **Connect** maps a GDAP customer to a Fenrir customer. Fenrir checks GDAP access first, then creates an `M365Connection` with `auth_mode=gdap`. Its delegated tokens are minted from the partner refresh token for the customer tenant. Nothing is installed in the customer tenant, and sync, administration and standards work as for any other connection.

The recommended role IDs are Microsoft built-in role template IDs. Check them against Microsoft's role reference before a first live rollout.

## Identity and device standards

| Standard | Deploys |
|---|---|
| Require MFA for all users | Conditional Access, all users and apps, MFA grant, break-glass accounts excluded |
| Require MFA for administrators | Conditional Access on the privileged directory roles |
| Block legacy authentication | Conditional Access blocking Exchange ActiveSync and other basic-auth clients |
| Windows device compliance baseline | Intune compliance policy requiring BitLocker, Secure Boot, code integrity, TPM, Defender, real-time protection and firewall, assigned to all devices, blocking after a grace period |

- **Report-only first.** Conditional Access policies are created in report-only mode unless **Enforce now** is chosen. Report-only counts as drift until it is enforced.
- **Security defaults.** A tenant with security defaults on already enforces MFA, so it is reported compliant for the MFA and legacy-authentication standards. Fenrir will not create Conditional Access policies there. It explains that an administrator must turn security defaults off first.
- **Idempotent.** Policies Fenrir creates are named `Fenrir: …` and redeploying updates them.
- **Many customers at once.** **Deploy…** applies a standard to every chosen customer with a result per Microsoft tenant, and each tenant's outcome is saved as it completes. It needs step-up re-authentication.
- **Per-customer mode.** `report` records state daily. `alert` opens one Security Operations ticket while the standard is drifted. `remediate` redeploys when drifted, but never escalates a report-only policy to enforced by itself.

## Entra ID reconciliation

Built from the last directory sync. The sync now also collects Intune managed devices (`DeviceManagementManagedDevices.Read.All`) and verified domains (`Domain.Read.All`). Both are optional: without a permission the report says that part is not covered.

| Finding | Meaning | Action in Fenrir |
|---|---|---|
| New starters | Enabled, licensed member accounts with no PSA/CRM contact | Add as contacts |
| Leavers | Contacts at the customer's verified domains whose account is disabled or missing | Mark as left |
| Disabled but licensed | Licence cost to reclaim | Remove through reviewed Microsoft actions |
| Without MFA | Enabled accounts not registered, admins first | Deploy the MFA standard |
| Intune devices without Fenrir | Matched by serial number, then name | Deploy the agent |
| Non-compliant devices | Intune compliance state | Investigate |

**Limits.** All of this is tested against a simulated Microsoft service. No live partner or customer tenant has been changed. GDAP relationship approval, role-group membership and live Conditional Access behaviour must be verified in a test tenant before production use.
