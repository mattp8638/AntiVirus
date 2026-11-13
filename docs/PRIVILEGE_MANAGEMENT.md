# Privilege management (Windows)

Policy section **Privilege management**. The `enabled` switch turns on removing standing admin rights; admin access requests work on their own.

## Admin access (elevation)

Users get admin rights only when they need them, through Fenrir:

* **Run one program as administrator**: right-click a program, installer (.msi) or script (.bat, .cmd) in Explorer and
  choose **Run as administrator with Fenrir**, use the **Fenrir PAM** tray, or the agent window during admin access.
* **Admin access for a while**: the agent window, **Get help → Need admin access?**.

Once approved, **the program opens already elevated on the user's desktop**. There is no password to type and no
Windows (UAC) prompt, and it works whether or not the agent window is open. The Fenrir service starts it as a
temporary local administrator made for that request (`fadm-<user>-<last 4 of the request id>`), or with the user's own
admin rights if they already are an administrator. The user's own account is never added to Administrators.

During admin access the agent window has **Run a program as administrator…**, and Explorer's menu works without
asking again. The temporary account and its password are also shown, for the rare installer that asks Windows for
an administrator itself.

### Who gets it without waiting

A request is granted straight away when the first of these matches:

1. **An allowance.** On a device, **Admin access → Allow admin access without approval…** lets the signed-in user,
   a named user or anyone use admin access without asking. It can cover:
   * this device or every device of the customer;
   * admin access, running programs, or both, optionally only named programs;
   * how long each session lasts;
   * an end date (1 hour to 30 days), or no end until it is removed.

   Customer-wide allowances can also be given from **Admin access → Allowed without approval**. An allowance works even
   when the policy has requests turned off.
2. **Policy, Privilege management → Admin access requests = auto-approve**: everyone on devices with that policy.
3. **Auto-approve these users**: user names (`jo`), `DOMAIN\user` or `PC\user`.
4. **Auto-approve these programs**, for run requests: a full path, a path with `*` wildcards
   (`C:\Program Files\Vendor\*`), or the file's SHA-256. Avoid folders users can write to (Downloads, Desktop, Temp).
5. **Auto-approve programs signed by**, for run requests: the publisher as shown on the request (for example
   `Adobe Inc.`). The device checks the signature, including Windows' own catalog signatures. `Microsoft Windows`
   covers built-in tools, including Command Prompt and PowerShell, so it amounts to full admin.

Otherwise, with **Admin access requests = approval**, the request waits under **Admin access → Requests** for a
technician to approve it (and set the minutes) or deny it. With **off**, users cannot ask, unless they have an
allowance. This setting works on its own: the **Privilege management** switch only controls removing standing admin
rights. A policy that never chose a value keeps the old behaviour (approval with the switch on, off without it).

A technician can also give the signed-in user admin access at once from the device (**Give … admin access now**).

### What happens

1. The request goes to the cloud with:
   * the user and their SID;
   * the reason;
   * for a program, its path and its verified publisher and SHA-256.
2. Approval, automatic or by a technician, reaches the device within seconds over its live connection. It runs ahead
   of scans and patching.
3. The device creates the temporary account. It is a member of Administrators and has Fenrir's marker comment. Windows'
   own account expiry is set to the end of the session plus 5 minutes, as a backstop. The password is 20 random
   characters, made on the device and kept only in the service's memory: it is never sent anywhere or written to disk.
4. For a program, the service signs the account in and starts the program with its elevated token on the user's
   desktop. It follows the program and everything it starts.
5. Access ends, the account and its profile are deleted, and programs started with it are closed, on the first of:
   * the time is up (a program started for a single request keeps running until it closes, up to 8 hours more);
   * the user clicks **I'm done**;
   * the program and everything it started have closed (single-program requests);
   * a technician clicks **Revoke**.
6. Any `fadm-` account with Fenrir's marker that no session knows about is deleted on the next pass. Accounts of the
   same name that Fenrir did not create are never touched. Nothing is ever granted on a domain controller.

**Asking again always works.** A request still waiting is granted as soon as an allowance or rule allows it. An
approval the device never confirmed within 10 minutes, or a request nobody decided within 24 hours, lapses. Each
device can make 30 requests an hour.

If the service cannot reach the user's desktop, the agent window starts the program the older way and the user
confirms Windows' prompt. The device records an `elevation.launch.fallback` event when this happens.

### Audit trail

Click a request to see its timeline:
* requested, with the publisher;
* approved, and by which allowance or rule;
* account created;
* program started;
* account removed.

Each step is also in the **audit log** with the target `<device hostname>:<user>`. The audit actions are:

* `elevation.requested`
* `elevation.approved` (with `rule` when automatic)
* `elevation.denied`
* `elevation.account_created` (or `elevation.granted` when the user was already an admin)
* `elevation.program_launched`
* `elevation.revoked`
* `elevation.account_removed` or `elevation.account_removal_failed`
* `elevation.failed`
* `elevation.allowance_created` and `elevation.allowance_revoked`

The device also sends these events to its timeline:
* `elevation.granted`
* `elevation.program.launched`
* `elevation.launch.fallback`
* `elevation.ended`
* `elevation.orphan.removed`

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
