# Privilege management (Windows)

Policy section **Privilege management**. Turn on `enabled` for the switches that depend on it.

## Temporary admin rights (elevation requests)

`elevationRequests`: `off`, `approval` or `auto-approve`. `elevationMinutes` sets how long access lasts (5–480).
Nothing is ever granted on a domain controller.

Every approved request gets **its own temporary local administrator account**, tied to the user who asked and the
request. The user's own account is never added to Administrators. The account is named
`fadm-<user>-<last 4 of the request id>` (for example `fadm-jo-1a2b` for `PC1\jo`), within Windows' 20-character limit.

### Two kinds of request

* **Admin access** (`kind: session`). The user opens the agent window, goes to **Get help → Need admin access?**,
  says what it is for and sends. The other way is **Ask for admin access...** in the Fenrir PAM tray
  (`--pam-session`). Once approved, the window shows the temporary account (`.\fadm-…`) and its
  password with Copy buttons. When Windows asks for an administrator (UAC), the user types those. **I'm done:
  remove the account** ends the session early.
* **Run one program as admin** (`kind: run`). This comes from the **Fenrir PAM** tray app (*Run PowerShell / Command
  Prompt / Disk Cleanup as admin*, *Run application as admin...*). It can also come from
  `fenrir-endpoint-client.exe --pam-run "C:\full\path.exe" --pam-reason "…" [--pam-args "…"]`. The cloud
  only accepts a full Windows path. Once the request is approved, the agent window starts the program as the
  temporary administrator. The user only clicks **Yes** at the Windows prompt and never sees the password. **When
  the program closes, the account is deleted.**

### What happens

1. The request is sent to the cloud with the user, their SID, the reason and, for `run`, the program.
2. **approval**: the request appears under **Security → Admin requests**. A technician approves it (and can change
   the minutes) or denies it with a note. **auto-approve**: it is approved straight away by `policy:auto-approve`.
3. At its next check-in the device creates the account. The account is a member of Administrators and has
   Fenrir's marker comment. Windows' own account expiry is set to the end of the session plus 5 minutes, as a
   backstop. The password is random (20 characters) and is generated on the device. It is kept in the service's
   memory only: it is never sent to the cloud or written to disk. After a service restart a new one is set.
4. The account and its user profile are deleted on the first of these:
   * the time is up;
   * the user clicks **I'm done**;
   * the program closes (`run`);
   * a technician clicks **Revoke**.
   If a profile is still in use, or the cloud can't be reached, the agent retries on its next pass.
5. Any `fadm-` account with Fenrir's marker that no session knows about (after a crash, a power cut or a restored
   image) is deleted on the next pass. Accounts with the same name that Fenrir did not create are never touched.
   A user who is already an administrator gets no account, and the request is recorded as granted.

### Audit trail

Click a request in **Admin requests** to see its timeline: requested, approved, account created, program started,
account removed. Each step is also in the **audit log** with the target `<device hostname>:<user>`. Each entry
includes the request id, device id and name, user, user SID and, where relevant, the account, its SID, the program
and the reason it ended. The audit actions are:

* `elevation.requested`
* `elevation.approved`
* `elevation.denied`
* `elevation.account_created` (or `elevation.granted` when the user was already an admin)
* `elevation.program_launched`
* `elevation.revoked`
* `elevation.account_removed` or `elevation.account_removal_failed`
* `elevation.failed`

The device also sends `elevation.granted`, `elevation.ended`, `elevation.program.launched` and
`elevation.orphan.removed` events to its timeline. `autoApprovePublishers` is not enforced yet.

## Removing standing admin rights

`removeLocalAdmins` (with `enabled`) removes user accounts from the local Administrators group every hour. These
always stay:
* groups such as Domain Admins and Entra roles;
* the built-in Administrator;
* the account LAPS manages;
* the break-glass account;
* Fenrir's temporary admin accounts (and anyone already granted temporary rights) while their session lasts.

The agent never removes the last usable administrator and never runs on domain controllers. The same action is
available per device as **Remove local admins**; **Restore local admins** puts back everyone it removed.

## Local admin password (LAPS)

`rotateLocalAdminPassword`, `localAdminAccount` and `localAdminPasswordDays`. The new password is stored in the
cloud before it is set. Technicians see it in the device's **Local admin** tab (re-authentication required,
audited).

## Break-glass account

**Break-glass admin (4 h)** in the device's Local admin tab, or the `breakglass.enable` command (1–24 hours), turns
on a `FenrirBreakGlass` local administrator with a password stored like the LAPS one. It is disabled
automatically when the time is up or with **End break-glass**. `breakGlassAllowed` turns the feature off.
