# Privilege management (Windows)

Policy section **Privilege management**. Turn on `enabled` for the switches that depend on it.

## Temporary admin rights (elevation requests)

`elevationRequests`: `off`, `approval` or `auto-approve`. `elevationMinutes` sets how long access lasts (5–480).

1. The user opens the agent window, goes to **Get help → Need admin access?**, says what it is for, and sends.
2. **approval**: the request appears under **Security → Admin requests** in the console. A technician approves it
   (and can change the minutes) or denies it with a note. **auto-approve**: the request is granted straight away.
3. The agent adds the user to the local Administrators group and removes them when the time is up. A user who was
   already an administrator is left as they were.
4. Windows keeps the user's current sign-in as it was. When Windows asks for an administrator, the user types their
   own user name and password. Rights can be revoked early from the console.

Requests, decisions, grants and expiries are all audited and sent as `elevation.*` events. Nothing is granted
on domain controllers. `autoApprovePublishers` is not enforced yet.

## Removing standing admin rights

`removeLocalAdmins` (with `enabled`) removes user accounts from the local Administrators group every hour. These
always stay:
* groups such as Domain Admins and Entra roles;
* the built-in Administrator;
* the account LAPS manages;
* the break-glass account;
* anyone with temporary rights.

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
