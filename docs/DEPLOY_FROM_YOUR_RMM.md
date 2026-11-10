# Deploy from your RMM, Group Policy or Intune

You don't need to visit each device. Fenrir installs the way you already deploy software:

- **From your current RMM.** Itarian, Level, NinjaOne, Datto or any tool that runs scripts as SYSTEM or root. This lets you run Fenrir alongside your current tool before you switch.
- **Group Policy:** a startup script, or software installation with the MSI.
- **Intune:** a platform script, or a line-of-business app with the MSI.

## Create a deployment

1. Go to **Deploy agents**, then the **Deploy from your RMM, Group Policy or Intune** card.
2. Choose the customer, and optionally a device group for the new devices, plus a label and how long the deployment lasts (7 to 365 days).
3. **Create deployment.** You get a PowerShell script, a shell script and an MSI download.

Copy them straight away: the deployment token inside them is shown only once.

One deployment token covers all of the customer's devices until it expires. Revoke it under **Enrolment tokens** if a script leaks. Revoking it stops both new downloads and new enrolments; devices already enrolled are not affected.

## The scripts

| Script | Use it for |
|---|---|
| `Install-Fenrir.ps1` | Windows: an RMM script (run as SYSTEM), a Group Policy computer startup script, or an Intune platform script (run as SYSTEM, 64-bit) |
| `install-fenrir.sh` | Linux (systemd) and macOS: an RMM script run as root |

How the scripts behave:

- **Safe to schedule.** Where the agent is already installed, the script only makes sure it is running, then exits 0.
- **No questions asked.** The Windows installer runs with `--quiet`: no window, no prompts. It writes its log to `C:\Program Files\Fenrir Endpoint\runtime\last-upgrade.log`.
- **Clear results.** Exit 0 means installed and running; exit 1 means it failed, with the reason printed for the RMM's output pane.
- **The token is never in a URL.** The scripts send the deployment token in the `X-Fenrir-Token` header, so it doesn't appear in proxy logs or browser history.

The installer downloads come from these addresses, all needing the token header: `GET /api/v1/install/windows.exe`, `windows.msi`, `linux.sh` and `macos.sh`. Downloading doesn't use up the token; each device's enrolment does.

### Itarian

Create a custom procedure of type **Script** (PowerShell for Windows, Shell for Linux/macOS), paste the script and run it on the devices. Itarian runs procedures as SYSTEM.

### Level

**Automations**, then a **Run script** step with the PowerShell or shell script, targeted by tag or group.

## The MSI

**Download MSI** builds an MSI for that customer. It installs the customer's own setup program and runs it quietly as SYSTEM.

- **Group Policy:** Computer Configuration › Policies › Software Settings › Software installation › New › Package. Choose *Assigned*, and point it at the MSI on a share that domain computers can read.
- **Intune:** Apps › Windows › Add › *Line-of-business app*. Upload the MSI and assign it to device groups.
- **By hand or from a script:** `msiexec /i FenrirAgent.msi /qn /norestart /l*v %WINDIR%\Temp\FenrirAgent-msi.log`

How the MSI behaves:

- **Upgrades.** Every Fenrir MSI shares one upgrade code, so a newer package replaces an older one.
- **The agent then updates itself.** It doesn't need a new MSI for each release.
- **Uninstalling it leaves the agent.** Removing the MSI does not remove the agent, which is protected against tampering. Remove agents from the console (device › More › Uninstall), which uses the authorised uninstall.
- **Building it.** The server builds the MSI with `wixl` from msitools, which the Docker image includes. On a server run from source, install the `wixl` package first.

## Unsigned builds

Without a code-signing certificate, the Windows installer is unsigned or signed with your own server's certificate.

- **No SmartScreen warning.** Deploying through an RMM, Group Policy or Intune doesn't trigger SmartScreen; only downloads opened in a browser do.
- **Allow-listing.** Where AppLocker or WDAC blocks unsigned software, allow the server's certificate or the agent's folder.
- **Defender.** If Defender flags the agent, see [DEVICE_PRESENCE.md](DEVICE_PRESENCE.md), which covers quarantine recovery and submitting a false positive to Microsoft.
