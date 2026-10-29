# Acceptance lab: proving Fenrir works before you rely on it

Unit tests show the code does what its authors expected. They do not show that a script actually runs on a
Windows 11 laptop, that a test virus is actually caught, or that a temporary admin account is actually deleted.
Fenrir is free and unsupported, so before you point it at machines that matter, prove it in a lab of your own and
keep proving it after every upgrade.

This page covers three ways to do that, from no effort to most realistic:

1. **CI**, which runs on every pull request. You only need to read it.
2. **A lab** of a few virtual machines, run with one command.
3. **Your own machines** (dogfooding), after the lab passes.

## 1. What CI proves on every pull request

`.github/workflows/acceptance.yml` starts a Fenrir server inside a GitHub runner, installs a real agent on the same
machine, and runs `scripts/acceptance/fenrir_acceptance.py` against it:

| Runner | Agent | Checks |
|---|---|---|
| Ubuntu (GitHub-hosted VM) | Go agent built from `agent/linux`, running as root | check-in, policy, inventory, script output, EICAR detection and quarantine, isolation (dry run), update scan |
| Windows Server (GitHub-hosted VM) | Service built with MSVC from `agent/windows`, installed with `fenrir-agent-service.exe --install` | check-in, policy, inventory, PowerShell script output, EICAR detection, temporary admin account created and then removed |

The run summary shows the report table. The `acceptance-linux` and `acceptance-windows` artifacts hold
`report.json` (with the evidence each check saw), the server log and, on Windows, the service diagnostics.

CI cannot prove everything. A GitHub runner is a server with no signed-in user, no real desktop and no customer
network. Isolation would cut the runner off from GitHub, so it only runs as a dry run on Linux. Remote desktop,
real patching, reboots and Microsoft 365 need the lab.

## 2. A lab in an afternoon

**What you need**

- A Fenrir server installed as in the [README](../README.md), on its own VM or VPS with HTTPS.
- Three or four VMs (Hyper-V, Proxmox, VMware or VirtualBox are all fine), snapshotted before the agent goes on:
  - Windows 11 Pro, joined to nothing, with a standard (non-admin) local user signed in.
  - Windows Server 2022 (optional domain controller: Fenrir behaves differently on one).
  - Ubuntu 24.04 LTS.
  - macOS, if you have Apple hardware.
- A free Microsoft 365 developer tenant, for the Microsoft 365 pages. Never use a customer's tenant.

**Enrol the VMs.** In the console, create a customer called "Acceptance Lab" (or run
`python3 scripts/acceptance/bootstrap.py --server https://your-fenrir --email you@example.com --password …`, which
prints an enrolment token). Download each platform's installer from **Deploy agents** and install it on each VM.

**Sign the harness in as a lab administrator.** Create a dedicated user (for example `lab-admin@…`) with a role that
can run scripts and approve admin access. API credentials will not work: they deliberately cannot run scripts or
grant admin rights, so a leaked integration key can never run code on your endpoints.

**Run every check.**

```bash
python3 scripts/acceptance/fenrir_acceptance.py --server https://your-fenrir --email lab-admin@example.com \
  --password "$LAB_PASSWORD" --mfa-code 123456 \
  --device LAB-WIN11 --device LAB-SRV2022 --device LAB-UBUNTU --disruptive --out lab-$(date +%F)
```

- `--disruptive` adds network isolation, which briefly cuts each VM off; only use it on lab machines.
- `--scenario eicar,pam` runs only those checks; `--list` shows them all.
- `--insecure` accepts a self-signed lab certificate.

The harness exits non-zero if anything failed. `lab-…/report.md` is the table and `report.json` has the evidence.
Keep the reports: they are your record of what was true for each version.

**Then check by hand what the harness cannot see.** Tick these off on the Windows 11 VM:

- [ ] **Remote desktop:** connect from **Devices → Connect**, use the mouse and keyboard, send Ctrl+Alt+Del, try a
  second monitor.
- [ ] **Agent window:** a user asks for admin access, you approve it, they use the account at a UAC prompt, they press
  **I'm done**, and the account disappears from `lusrmgr.msc`.
- [ ] **PAM tray:** run *Run application as admin…* with an installer; it opens after approval and the account goes
  when it closes.
- [ ] **Patching:** approve one real cumulative update in a maintenance window, and check it installs and the restart
  prompt behaves.
- [ ] **Isolation:** the VM cannot browse while isolated but still shows online in the console; release restores it.
- [ ] **Reboot and upgrade:** the service comes back after a restart, and an agent update from **Settings → Agent
  releases** reaches the VM through its ring.

## 3. Your own machines first

Once the lab passes, put the agent on your own team's machines before any customer's, and live with it for a
couple of weeks. Watch for:
- false positives;
- CPU or disk use your users notice;
- anything slower to log in;
- alerts that nobody would act on.

Every problem you find there is one a customer never sees.

## When to run it again

| When | What to run |
|---|---|
| Before each upgrade of the server or agents | The full lab run, on snapshots taken before the upgrade. |
| After changing a policy template you use widely | The lab run. |
| After any failure | Record it in `docs/parity/acceptance.md` with the run or report that showed it. |
