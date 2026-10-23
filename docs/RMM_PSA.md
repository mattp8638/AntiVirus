# RMM, remote access and PSA

Fenrir now covers the work an MSP would otherwise split between an RMM (NinjaOne, N-able, Level, SuperOps) and a PSA (ConnectWise Manage, Autotask, HaloPSA). Everything runs on the same agents, tenants and console as the security platform.

This was built clean-room from public product documentation: the same concepts, none of their code, branding or assets.

## What you get

| Area | What it does | Where |
|---|---|---|
| **Device health** | Agents send CPU, memory, every disk, uptime, signed-in user, restart pending, stopped automatic services and running processes with each heartbeat. Devices list and device page show them live, with 24-hour charts. | Devices · device → Health |
| **Monitoring** | Conditions such as "C: under 10% free for 5 minutes", "service Spooler not running", "offline 15 minutes" or "critical patches missing". When one triggers it raises an alert and can open a ticket, run a self-heal script, email someone or call webhooks. It resolves itself when the problem clears. | Monitoring |
| **Scripts** | A PowerShell, cmd, Bash and Python library with typed parameters (text, number, yes/no, choice). Run a script on a device, a group or a whole customer. You see each device's exit code, output and errors. Parameters are passed safely: values are quoted for the script's language and also set as environment variables. | Scripts · device → Run script |
| **Automation** | Scheduled tasks (once, every N minutes, daily, weekly or monthly, in any time zone) run scripts, actions or software installs. Every run is a job with per-device results. | Automation |
| **Patching** | Agents report missing Windows updates (through the Windows Update API), third-party app updates (winget) and Linux packages (apt, dnf, yum, zypper). Policies set approval rules per classification, rings with delays, maintenance windows and restart behaviour. You can also approve, reject or install now by hand. A compliance dashboard shows the result. | Patching · device → Patches |
| **Software** | Deploy or remove apps with winget, Chocolatey, signed MSI/EXE (the SHA-256 is checked before running), apt, dnf or snap. A built-in catalogue of common apps is included. | Software |
| **Remote access** | Press **Connect** and a pop-out window opens with the remote desktop, PowerShell or shell terminal, file browser, processes, services and chat. | Any device · ticket page |
| **Service desk** | Service boards with their own statuses and types/subtypes/items. Priority comes from impact × urgency. Each ticket has respond-by and resolve-by SLAs counted in business hours, discussion/internal/resolution notes, time entries, a task checklist, linked configurations, merge, and dispatch. | Service board · ticket page |
| **Time & billing** | Time is billed in 15-minute steps against agreements. Agreements set covered work types, included hours, after-hours rules, per-device pricing and automatic additions (for example, a backup charge counted per server). Timesheets are submitted and then approved, and approved time flows into invoices. | Time & timesheets · Agreements & billing |
| **Dispatch** | A day view with engineers down the side. Drag unassigned tickets onto a time slot; drag bookings to move them. Clashes are flagged. | Dispatch |
| **Workflow rules** | Rules run when a ticket is created or updated, has sat in one status for N hours, or hits an SLA warning or breach. They can set fields, assign (including round robin), add notes, email the contact or notify a member. | Service settings |
| **Email to ticket** | New emails open tickets for the sender's company, matched by contact email or the company's email domains. Replies that keep `[Ticket #1234]` in the subject are added to that ticket and reopen it. Out-of-office replies are ignored. | Service settings → Email to ticket |
| **Companies & CMDB** | Companies with their sites, contacts, agreements, configurations, tickets and projects. Configurations sync from RMM devices, or you add firewalls, licences and domains by hand. | Companies · Configurations |
| **Sales** | A product catalogue with cost and margin, and quotes that print to PDF. | Products & quotes |
| **Projects** | Project phases with their tickets and actual against estimated hours. | CRM & projects |
| **Client portal** | Customer users (role `client`) sign in to raise and follow requests, read public knowledge-base articles, and see invoices and their devices. They never see internal notes or other companies. | `/portal` |

## Remote access in detail

```
browser pop-out ──► cloud relay ◄── agent (Linux) / fenrir-remote.exe (Windows)
```

- **Speed.** Agents hold a realtime channel to the cloud, so a session starts in about a quarter of a second. In testing, the first screen frame arrived 230–400 ms after Connect was clicked.
- **Screen.** The agent sends only the 128×128 tiles that changed, as JPEG. The viewer acknowledges each frame, so a slow link lowers the frame rate instead of lagging behind. Quality, frame rate and monitor can be changed live.
- **Windows.** The service starts `fenrir-remote.exe` in the signed-in user's session as SYSTEM. It can therefore also see and control the sign-in screen and UAC prompts.
  - Keyboard input uses scan codes, so the remote keyboard layout applies.
  - Ctrl+Alt+Del works through `SendSAS`.
  - The user sees a banner with **End session** and **Chat** buttons.
- **Linux.**
  - Desktop control works on X11 (XTEST).
  - Wayland blocks screen capture by design, so on Wayland machines only the terminal, files, processes and services are available.
  - The terminal is a real PTY.
- **Consent and policy.**
  - The remote-access policy section controls consent (never, when a user is signed in, or always), the timeout and what happens if nobody answers, view-only, terminal, file transfer, the banner, the idle timeout, frame rate and quality.
  - The cloud checks the policy before a session starts, and the relay enforces it on every message.
- **Audit.** Each session records who connected, when and for how long, plus every file download/upload, Ctrl+Alt+Del and terminal open. Entries go to both the session history and the hash-chained audit log.
- **Billing.** Ending a session can log its time straight onto the linked ticket.

The wire protocol is in [REMOTE_PROTOCOL.md](REMOTE_PROTOCOL.md).

## Connecting a Windows PC

Copy `fenrir-agent-service.exe`, `fenrir-remote.exe` and `fenrir-amsi-provider.dll` (build target `antivirus-amsi-provider`) to a local folder such as `C:\Fenrir`; a WSL or network path will not work for a service. Then, from an Administrator prompt in that folder:

```powershell
.\fenrir-agent-service.exe --install --server https://<your server> --enroll-token <token from Deploy agents>
Start-Service FenrirAgent
```

`--server` and `--enroll-token` save `ControlPlaneBaseUrl`, `EnrollmentToken` and `ManagedMode=1` under `HKLM\SOFTWARE\FenrirAgent`. A device enrolled with a token goes straight into that customer and is approved. Without a token it lands in **Unassigned**. Running `--console` with the same options does a one-off interactive run. Set `ManagedMode` to `0` to run the agent standalone (updates only, no reporting).

### Keeping the agent running

- The service starts with Windows. Windows restarts it 5, 15 and then every 60 seconds after any crash, kill or error exit.
- An error during one sync cycle is logged and the agent carries on.
- Administrators can't stop, reconfigure or delete it from services.msc, `Stop-Service` or `sc`; they can still start it.
- To stop it on purpose (for example to copy in a new build), run `.\fenrir-agent-service.exe --stop`. Add `--token <uninstall token>` if uninstall protection is on. `--install`, `--repair`, `--upgrade` and `--uninstall` lift the block themselves.
- This stops casual tampering, not a determined administrator, who can still change the service's permissions. Full protection needs the signed ELAM driver (`--elam-driver`).

### Remote sessions on Windows

- The agent connects remote sessions to the same server address it uses for check-ins, so a wrong or unreachable `FENRIR_PUBLIC_URL` doesn't break remote access.
- Sessions start straight away, even while a scan is running.
- Each session writes a log to `C:\ProgramData\FenrirAgent\runtime\remote\<session id>.log`.
- If the device can't start a session, the viewer shows why.

### Console as an app

In Chrome or Edge, click **Install app** in the console's top bar, or use the install icon in the address bar. The console then runs in its own window, and remote sessions open as app windows without browser bars. This needs HTTPS, or `http://localhost`.

## Setting up email

| Setting | Purpose |
|---|---|
| `FENRIR_SMTP_HOST`, `FENRIR_SMTP_PORT`, `FENRIR_SMTP_USER`, `FENRIR_SMTP_PASSWORD`, `FENRIR_SMTP_FROM` | Outbound notifications: acknowledgements, updates, resolutions, workflow emails |
| `FENRIR_IMAP_HOST`, `FENRIR_IMAP_USER`, `FENRIR_IMAP_PASSWORD`, `FENRIR_IMAP_FOLDER` | Inbound mailbox, checked every two minutes |
| Service settings → Email to ticket → *Create a new inbound URL* | Webhook alternative for Mailgun, SendGrid, Postmark or Power Automate. Accepts a raw RFC 822 message or JSON. |

Without SMTP settings, outbound emails are kept in the server log rather than sent.

## Reverse proxy

Remote access and the realtime channel use WebSockets on `/ws/remote/…` and `/api/v1/devices/<id>/realtime`. Caddy and Cloudflare Tunnel pass WebSockets through by default. nginx needs:

```nginx
location / {
    proxy_pass http://fenrir:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 3600s;
}
```

## Upgrading an existing server

New tables are created on start-up. New columns on existing tables (tickets, agreements, projects, devices) are added automatically. Older tickets appear on the Service Desk board with their old status.

## Known limits

- The Windows remote helper is compile-checked with MinGW and was exercised under Wine against the real relay: screen capture, the banner, files, processes and services all worked. It has **not** been run on a real Windows PC yet. Under Wine the ConPTY terminal started but its shell exited at once; Wine's console emulation can't settle whether that also happens on Windows. Test on Windows 10 1809 or later before relying on it.
- The Windows agent runs scans on the same thread as its cloud check-ins. While a long scan runs, new commands and remote sessions wait until it finishes. A fresh install therefore waits a day before its first full-drive scan.
- Automatic quarantine never touches files under `C:\Windows`, `Program Files` or Fenrir's own folders; findings there are reported for review instead. Windows system files signed through catalog (`.cat`) files are now recognised as Microsoft-signed. That check runs only on real Windows, because Wine has no catalogs.
- The relay keeps sessions in one server process. If you run several cloud instances, route `/ws/remote/<session>` by session id (sticky sessions).
- Not built yet:
  - session video recording
  - multi-monitor "all screens" view
  - macOS remote control
  - procurement/purchase orders
  - accounting sync (Xero, QuickBooks)
  - customer satisfaction surveys
  - holiday calendars for SLAs
  - backup and MDM modules
