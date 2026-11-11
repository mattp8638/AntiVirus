# Migrating to Fenrir from Itarian, Level or another RMM

This guide moves a fleet without a gap in monitoring: Fenrir goes on alongside the old RMM, you check it, and only then
does the old agent come off. Plan a pilot customer first, then the rest in batches.

The product names below are other companies' trademarks. Their consoles change; use their own documentation for exact
menu names. Nothing here needs an export API: everything can be recreated by hand or with scripts.

## 1. Before you start

- **Install the Fenrir server** ([one command](index.md#install-in-one-command)) and run the go-live check
  (`deploy/preflight.sh`) until it passes.
- **Turn on MFA** for every technician, and add their accounts with the right roles (Settings).
- **Create your customers** (Companies). The names do not need to match the old RMM, but it helps.
- **Choose a layout.** If you only used the old tool for RMM and antivirus, switch Settings → Modules to the
  Essentials layout (RMM, protection and patching) so the menu matches what you are used to.

## 2. Inventory what you have in the old RMM

Write down, per customer:

| Old RMM item | Fenrir equivalent |
|---|---|
| Device list, sites, groups | Companies, and Device groups with automatic rules |
| Monitors / alert conditions (CPU, disk, services, event log) | Monitoring rules, applied by policy or device group |
| Scripts / procedures | Scripts (the library, with Jobs & schedules to run them). PowerShell and shell scripts usually run unchanged |
| Custom fields | Custom fields; scripts read them as `FENRIR_CF_<KEY>` variables and write them with `FENRIR-FIELD key=value` lines |
| Patch policies (Windows Update and third-party apps) | Patching and Software (winget on Windows, Homebrew on macOS); the community catalogue covers common apps |
| Antivirus / EDR policy | Protection policies (Fenrir's own engine, and managing Microsoft Defender) |
| Remote control | Remote sessions in the browser: desktop, terminal, files, processes, services |
| Tickets, contracts, time | Tickets, Agreements & billing and Time & timesheets (switch on those modules if you need them) |
| Reports | Reports (PDF client reports, with your branding) |

Export the device list to a spreadsheet if the old tool allows it: you will use it to check every device arrived.

### Notes for Itarian users

- Itarian combines RMM, antivirus and a service desk. Map each part separately: RMM procedures to scripts, profiles to
  Fenrir policies, and the antivirus profile to a Fenrir protection policy.
- Do not run two antivirus engines in real time on the same machine. During the overlap, either put Fenrir's protection
  policy in monitor mode or keep the old antivirus and let Fenrir manage Microsoft Defender afterwards.

### Notes for Level users

- Level focuses on RMM: monitors, automations, scripts, patching and remote access. Its scripts are usually PowerShell or
  shell and can be pasted into Fenrir's library; replace any Level-specific variables with Fenrir's
  `FENRIR_DEVICE_NAME`, `FENRIR_CUSTOMER` and `FENRIR_CF_<KEY>`.
- Level automations triggered by monitors map to Fenrir monitoring rules that run a script or open a ticket.

#### Moving your Level scripts automatically

`scripts/migrate/level_scripts.py` copies your Level script library into Fenrir using the Level CLI. Run it where
`lvl` is signed in (`lvl auth login`, then `lvl auth status`). It needs Python 3 only.

1. In Fenrir: **Settings → API credentials**, create one with the **configure** permission for your MSP (or the
   customer the scripts should belong to). Copy the key; it is shown once.
2. Export from Level (bodies included):
   `python3 scripts/migrate/level_scripts.py export`
   It runs `lvl script list --limit all -o json`, then fetches any script whose body the list leaves out
   (`--show-cmd` changes that command if your CLI version names it differently). Already have the JSON? Use
   `export --from level-list.json`.
3. Plan: `python3 scripts/migrate/level_scripts.py plan` writes `level-plan.csv` with one row per script:
   - **group** and **category**: Level's folder or tag when it has one, otherwise worked out from what the script
     does (Security, Patching, Software, Networking, Users and identity, Maintenance, Monitoring, Inventory, Backup).
     In Fenrir they show as one category, `Level / Security`. Use `--group ""` for no group, or any name you like.
   - **language** and **platforms**, **run_as**, **timeout_seconds**, and the **parameters** found.
   - **notes**: custom fields to create in Fenrir, single-quoted variables to check, renamed duplicates.
   - **import**: set to `no` for scripts you do not want to bring over.
   Open it in a spreadsheet and change anything, then save it as CSV.
4. Import: `FENRIR_URL=https://your-server FENRIR_API_KEY=<your key> python3 scripts/migrate/level_scripts.py import --dry-run`,
   then the same without `--dry-run`.

Level variables written as `{{name}}` become Fenrir script parameters: when the script runs, Fenrir shows them as
a form and sets them as variables (`$name` in PowerShell, `${name}` in shell). Custom-field variables such as
`{{cf_owner}}` read the device's Fenrir custom field instead (`$env:FENRIR_CF_OWNER`). Importing again updates
scripts that changed and leaves the rest alone (`--skip-existing` never touches existing ones). As with any library
change, imported scripts wait for a second person to review them under **Scripts** before they can run.

To file every script by **Operating system › Area › Kind** (for example *Linux › Networking › Fix*), open **Scripts →
Organise categories**. It previews the new category for each script; untick or retype any, then apply. Only the
category changes, so reviews stay as they are. New scripts saved without a category are filed the same way.

## 3. Deploy the Fenrir agent with the old RMM

The fastest way onto existing machines is the RMM you are leaving:

1. In Fenrir: **Deploy agents → Deploy from your RMM**, choose the customer and how long the token should last.
2. Copy the Windows PowerShell script (and the macOS/Linux one if you have those devices).
3. In the old RMM, create a script with it and run it against that customer's devices, as SYSTEM/root.

The script is safe to run more than once: it does nothing on a device where Fenrir is already running. For Group Policy
or Intune there is a per-customer MSI on the same page. Details: [Deploy from your RMM](DEPLOY_FROM_YOUR_RMM.md).

## 4. Check, then switch

For each customer, before removing anything:

- Every device from your spreadsheet appears in Fenrir and checks in (Devices, filtered by company).
- Monitors raise alerts when tested (stop a monitored service on one machine).
- A script runs and returns output; a patch scan completes.
- A remote session opens.

Run both side by side for at least a week for your first customer.

## 5. Remove the old agent

Use the old RMM's own uninstall (its console usually has a "remove agent" action), so it also cleans up its services
and licences. If that is no longer possible, run the vendor's uninstaller from Fenrir as a script. Then cancel the old
subscription.

## 6. Afterwards

- Set up automatic server updates (`deploy/install-auto-update.sh --stable`) and check backups are being copied off
  the server.
- Keep `deploy/.env` and `deploy/signing/` safe and offline: without them you cannot restore the server or update agents.
