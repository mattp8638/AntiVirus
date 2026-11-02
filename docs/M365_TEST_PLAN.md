# Microsoft 365 batches 1 and 2: owner test plan

These are the exit tests for the Microsoft 365 workspace (batch 1) and identity (batch 2) work. Every step below already passes against a
simulated tenant in CI. This plan checks it against real Microsoft. Record **Pass** or **Fail** for each step, and for a fail, copy the
exact message Fenrir shows. Microsoft's own error text is included in Fenrir's messages, and it usually names the missing permission or role.

Allow about an hour. Steps marked **(changes the tenant)** only touch the test accounts you create in step 3.

## 0. Before you start

- [ ] Take a backup: `sudo deploy/backup.sh`.
- [ ] If you turned on unattended updates, pause them while you test, so the server stays on the test branch:
  `sudo systemctl stop fenrir-auto-update.timer`.
- [ ] Put the test branch on the server:

  ```bash
  cd ~/AntiVirus
  git status --short                # must be empty
  git fetch origin claude/jolly-goodall-5kpl2t
  git checkout claude/jolly-goodall-5kpl2t
  dc build cloud && dc up -d
  dc logs --tail=50 cloud           # no errors at start-up
  ```

  Then reload the console with **Ctrl+F5**. When you are done, go back with `git checkout main && dc build cloud && dc up -d`. The new
  tables are additive, so main keeps working on the same database.

## 1. Workspace and permissions (batch 1)

1. [ ] **Microsoft 365** shows the new overview: four totals at the top and one row per tenant, with MFA, Secure Score, unused licences,
   global admins and service issues. Your tenant is listed.
2. [ ] Click your tenant. Its page opens with the tabs **Overview, Users and groups, Onboarding and offboarding, Logs, Permissions**.
3. [ ] **Permissions → Check permissions.** A table lists each feature as available or missing. Expect the new features (password reset,
   MFA reset, Temporary Access Pass, temporary admin, guests, groups, service health, out-of-office) to show **missing** until the next step.
4. [ ] **Update permissions** (changes the consent, not users):
   - *Connected by admin sign-in:* a sign-in window opens. Get a code, sign in at microsoft.com/devicelogin as a **Global Administrator**
     of your tenant, and wait for "connected". Fenrir reuses its app and adds the new permissions.
   - *Connected through your partner tenant (GDAP):* Fenrir replaces the consent itself and says so. Wait two or three minutes. If it
     says it removed the old consent but Partner Center did not accept the new one, press **Update permissions** again: until it
     succeeds, Fenrir cannot reach that customer.
   - *Platform app or manual app:* Fenrir lists the permissions to add to the app registration. Add them, grant admin consent, then sign
     in again.
5. [ ] **Check permissions** again. Everything is available except anything marked "not possible here". Out-of-office is not possible
   through GDAP until the Exchange batch. Write down anything still missing.
6. [ ] **Sync now.** The **Overview** tab fills in: organisation, domains, Microsoft service health (often empty, which is fine),
   administrators with their roles, and "licensed but inactive for 90+ days". The last list needs Entra ID P1 or P2. Compare the
   administrators with the Entra admin centre (Roles and administrators): they should match.
7. [ ] **Logs → Collect now.** Sign-ins and directory changes from the last 30 days appear, or 7 days without P1.
   - Without Entra ID P1 or P2, the sign-in log says Microsoft needs P1 or P2. That is expected; directory changes still appear.
   - Filter **Result: Failure**, search for a user, open a row to see its details, and press **Export CSV**. Check that the CSV opens in Excel.
   - Compare one sign-in with Entra admin centre → Sign-in logs: same time, app, IP and result.
8. [ ] Leave it an hour, then check **Logs** shows "Last collected" within the hour. That is the background collection. Also check that
   the tenant's "Synced" time on the overview updates within six hours without you pressing Sync.

## 2. Test accounts (batch 2) (changes the tenant)

Use test accounts only. Do not run these on real staff.

1. [ ] **Onboarding and offboarding → New starter.** Name it `Fenrir Test One`, with sign-in name `fenrir.test1@<your domain>` and usage
   location GB. Choose:
   - a manager;
   - one licence you have spare (the list shows how many are free);
   - one ordinary security or Microsoft 365 group.

   Leave "Fenrir contact" and "ticket" ticked. Press **Plan new starter**.
2. [ ] The review lists every step and nothing has changed yet. Check that the user does not exist in Entra yet. Tick the box, then
   **Confirm and run** (you are asked for your Fenrir password).
3. [ ] All steps show **done**, and a temporary password appears **once**. Copy it. In Entra, check:
   - the user exists;
   - the manager is set;
   - the licence is assigned;
   - the user is in the group.

   In Fenrir, check that a contact was added for the customer and a ticket was opened.
4. [ ] Sign in as `fenrir.test1` in a private browser window with that password. Microsoft makes you change it.
5. [ ] Close the review and reopen it from **History**. The password is not shown again.

## 3. One-off actions (batch 2) (changes the tenant)

On **Users and groups**, click `Fenrir Test One` and choose each action. Each one shows a review, then runs after you tick the box and
confirm.

1. [ ] **Reset password**, with "make them change it" ticked. A new password is shown once, and signing in with it works.
   - If Microsoft refuses with "Insufficient privileges", note it. On admin sign-in connections, Microsoft can require the Fenrir app
     itself to hold the Helpdesk or User Administrator role. Tell me and I will add that to the setup.
2. [ ] Register the Authenticator app for the test user (sign in as them and follow the MFA prompt). Then **Reset MFA**:
   - the review lists the methods it will remove;
   - afterwards, Entra shows no MFA methods for the user;
   - at next sign-in, Microsoft asks them to register again.
3. [ ] **Issue a Temporary Access Pass** (60 minutes, usable once). The pass is shown once.
   - If Microsoft refuses, Temporary Access Pass is probably off: Entra → Protection → Authentication methods → Temporary Access Pass.
     Turn it on for a test group, then try again.
   - With the pass, sign in at https://aka.ms/mysecurityinfo.
4. [ ] **Grant a temporary admin role**: choose **Helpdesk Administrator** for **1** hour.
   - In Entra, the user holds the role.
   - In Fenrir, open the action from the **Actions** tab. It shows "held until …". Press **End it now**; the role disappears in Entra.
   - Grant it again for 1 hour and leave it. Within about a minute of the hour passing, the role disappears by itself. Check Entra, and
     check that the action says "removed … system:expiry".
5. [ ] **Set manager**, **Edit user profile** (job title) and **Enable or block sign-in**: check each in Entra.
6. [ ] **Users → Invite guest**: use one of your own personal email addresses. The invitation email arrives, and the guest appears in Entra
   as a Guest. Delete it in Entra afterwards.
7. [ ] **Groups → New group**: make a Microsoft 365 group `Fenrir Test Group` with `fenrir.test1` as owner. It appears in Entra with that
   owner. Delete it in Entra afterwards.

## 4. Offboarding (batch 2) (changes the tenant)

1. [ ] Give `Fenrir Test One` an admin role it will keep (for example Helpdesk Administrator, granted in Entra). Add it to a second group,
   and if possible to a dynamic group or distribution list, to see those skipped.
2. [ ] **Offboard a user** → `Fenrir Test One`. Tick every step.
   - Tick "Remove licences" only if losing the test mailbox is fine.
   - Tick out-of-office only on an admin sign-in connection whose test user has a mailbox, and write a message.

   Press **Plan offboarding**.
3. [ ] The review shows:
   - the groups it will remove, and the dynamic or Exchange ones it will leave, with the reason;
   - the admin roles;
   - the MFA methods;
   - the licence warning about the mailbox being deleted after 30 days.

   Nothing has changed yet in Entra.
4. [ ] **Confirm and run.** All steps show **done**. In Entra:
   - sign-in is blocked;
   - the user is in no ordinary groups;
   - the user holds no admin roles;
   - the user has no MFA methods;
   - the licence is gone, if ticked.

   A sign-in attempt as the user fails. In Outlook on the web, the out-of-office reply is set, if ticked. In Fenrir, the ticket lists
   what was done and what is left to do by hand, and the contact is marked as left.
5. [ ] Run it again from **History**. Nothing runs twice.

## 5. Bulk import (batch 2) (changes the tenant)

1. [ ] Make a CSV file:

   ```csv
   displayName,userPrincipalName,jobTitle
   Fenrir Test Two,fenrir.test2@<your domain>,Tester
   Fenrir Test Three,fenrir.test3@<your domain>,Tester
   Fenrir Test One,fenrir.test1@<your domain>,Already exists
   ```

2. [ ] **Bulk import from CSV**: load it, pick no licence, pick one group, then **Check and plan**. The review shows two users to create
   and the third skipped because it already exists.
3. [ ] **Confirm and run.** Two passwords appear. **Download as CSV** and check the file. In Entra, both users exist and are in the group.

## 7. Hybrid users: synced from Active Directory (changes AD and the tenant)

This needs the Fenrir agent on a domain controller of the same customer (PM-DC). If Entra Connect runs on a server with the agent,
Fenrir also starts the sync itself.

1. [ ] **Users and groups**: users synced from AD show **Active Directory** under "Managed in". Pick one and choose **Enable or block
   sign-in**. Fenrir refuses with an explanation (Microsoft only accepts that change in AD).
2. [ ] **New starter**: under "Where the account lives", choose **Active Directory, synced to Microsoft 365**, then
   **Load them from the domain controller**. Expect to see your OUs, AD groups and UPN suffixes.
3. [ ] Create `Fenrir Hybrid` (`fenrir.hybrid@<your domain>`):
   - pick a test OU and one AD group, plus one spare licence;
   - plan it: the steps show **Active Directory** or **Microsoft 365** against each;
   - run it: the temporary password appears once, marked "Account in: Active Directory".
4. [ ] Watch the run. It creates the account on PM-DC, syncs, waits for the user to appear in Microsoft 365 (a minute or two with
   the sync step, up to 30 minutes without), then applies the usage location and licence. You can close the window: it carries on
   by itself. Then check:
   - the account is in the chosen OU and AD group (Active Directory Users and Computers);
   - the user is in Microsoft 365 with the licence;
   - signing in with the temporary password asks for a new one.
5. [ ] **Offboard** `Fenrir Hybrid`:
   - choose a leavers OU under "Move the account to";
   - run it. The AD steps run on PM-DC, then the sync, then the Microsoft 365 steps.
   - In AD, the account is disabled, has no groups besides Domain Users, sits in the leavers OU and has "Left <date>" in its
     description.
   - In Microsoft 365, sign-in shows as blocked after the sync, and the licence is gone if you ticked it.
6. [ ] Delete `Fenrir Hybrid` in AD when done. Entra Connect removes it from Microsoft 365.

## 8. Remote Ctrl+Alt+Del on a server

1. [ ] After the agent on PM-DC has updated, connect to it while it shows "Press Ctrl+Alt+Delete to unlock" and press
   **Ctrl+Alt+Del**. The password box appears.
2. [ ] Optional: on PM-DC's device page, run **Test remote Ctrl+Alt+Del**. Only do this when nobody minds the security screen
   opening there. The result shows `"worked": true`.

## 6. Clean up

- [ ] Delete `fenrir.test1`, `fenrir.test2` and `fenrir.test3` in Entra (or offboard and then delete them).
- [ ] Go back to `main` if you want (see step 0), and restart unattended updates:
  `sudo systemctl start fenrir-auto-update.timer`.

## Reporting back

Reply with the step numbers that failed and the exact text Fenrir showed. Also say which kind of connection your tenant uses: admin
sign-in, partner (GDAP), platform app or manual. Batch 1 and 2 are done when every step passes or has an agreed explanation. Exchange
(batch 3) starts after that.
