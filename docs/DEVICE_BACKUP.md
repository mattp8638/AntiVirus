# Device backup

Image backups of Windows servers and PCs, Hyper-V hosts (their VMs, from the host), Linux and macOS machines,
managed from the console under **Devices › Backups** and on each device's **Backup** tab. The engine, agent and CLI
are in `backup/` (Rust); the server side is `cloud/fenrir_cloud/backup.py` with `routers/backup.py` (console) and
`routers/backup_agent.py` (agents). This is separate from `BACKUP_AND_RESTORE.md`, which covers backing up the
Fenrir server itself.

## How it fits together

* **Backup agent** (`fenrir-backup-agent`): its own service, separate from the Fenrir security agent. Windows:
  service `FenrirBackupAgent`, `C:\Program Files\Fenrir-Backup\`, state in `C:\ProgramData\Fenrir-Backup\agent`
  (SYSTEM and Administrators only). Linux: systemd unit `fenrir-backup-agent`. macOS: `uk.fenrir-backup.agent`.
  Only administrators can stop or remove it. It never touches the security agent's `FenrirAgent` service.
* **Server URL**: agents talk to `https://<this server>/backup` (enrol, heartbeat every 15 s, job updates,
  self-update downloads). They always connect out; nothing connects to them.
* **Repositories**: folders on a local disk, a NAS or file server (`\\nas\share\folder`, `smb://`), holding
  encrypted, deduplicated images. The console encrypts the repository passphrase, and any share password, in the
  browser to each machine's own X25519 key. The server stores only those sealed copies and cannot open a backup.
  A recovery key file is made in the browser when a repository is created and is never uploaded.

## Installing the agent

* **From a device page** (Backup tab › Enable backup): the Fenrir agent runs the installer as SYSTEM or root
  (`script.run`). The link inside is bound to that device, lasts a day and works once.
* **Install links** (Backups › Add machines): per customer and role (desktop, server, Hyper-V host). Windows gets a
  `Fenrir-Backup-Setup.exe` (double-click, approve the UAC prompt) and a PowerShell one-liner; Linux and macOS a
  `curl … | sudo sh` line. Links last 1–90 days.
* Builds: `deploy/Dockerfile` compiles the Linux (static) and Windows agents into
  `/app/cloud/downloads/backup/<target>/`. macOS builds come from `.github/workflows/backup.yml`; copy them into the
  same layout (or point `FENRIR_BACKUP_AGENTS_DIR` at a folder). With automatic updates on (the default), agents
  replace themselves with the server's build after checking its SHA-256.

## Who can do what

| Action | Permission |
|---|---|
| View machines, repositories, plans, images, jobs | `read` |
| Back up now, verify, test a connection, run a plan, cancel, place a hold | `respond` |
| Restore to VHDX files or a new Hyper-V VM, boot tests, stop a test VM | `scripts` |
| Install links, repositories, access, plans, share sign-ins, maintenance | `configure` |
| Overwrite a physical disk, release a hold, reclaim space | `destructive` + password re-check |
| Turn automatic agent updates on or off | `platform` |

A disk restore also needs the device name typed exactly. Every change is in the audit log (`backup.*`).

## Network shares

A repository path such as `\\nas\backups\fenrir` can sign in with:

* **Username and password** (domain optional, or `user@domain`): sealed per machine; the agent connects only while
  a job runs, as SYSTEM, out of sight of logged-in users.
* **Computer account**: domain-joined Windows machines connect as `DOMAIN\NAME$`; grant those (or an AD group of
  backup machines) change rights on the share. No password is stored.
* **No sign-in**: the share already accepts the machines.

*Test connection* signs in, writes a test file and reports free space before you create the repository.

## Protection and alerts

Alerts go to the normal alert queue (category `backup`):

* `backup.ransomware_hold` (critical): a backup changed far more than usual and the new data does not compress.
  The repository is put **on hold**: retention and space reclamation stop, so earlier images survive. Release the
  hold once the machine is clean.
* `backup.job_failed`, `backup.boot_failed`, `backup.agent_offline` (24 h), `backup.overdue` (no successful plan
  backup for 3 days). Offline and overdue alerts resolve themselves when the machine recovers.

Retention runs after each successful plan backup. Space is reclaimed on the repository's maintenance machine every
N days (default 7). Boot verification boots each machine's newest image in an isolated VM on a chosen host (Linux
with QEMU/KVM, or Hyper-V) every N days.

## NAS gateway: one machine inside the network serves remote machines (next)

Remote machines (laptops at home, a branch office) often cannot reach the office NAS. The plan, chosen for this
platform:

1. One backup agent inside the network is made a **gateway** for a repository on the NAS. It is the only machine
   that signs in to the share.
2. In the console you choose which remote machines may use that gateway, per repository.
3. Remote agents write to the repository through the gateway, **direct** when they can reach it (LAN, VPN, port
   forward) and otherwise **relayed** through Fenrir Cloud over the existing outbound connections. Neither side
   needs an open inbound port in relay mode.
4. Everything stays end-to-end encrypted: the remote agent encrypts chunks itself with the repository key; the
   gateway and the relay only move sealed objects. The gateway serves the repository **append-only** to remote
   agents (add chunks and images, read for restore; no delete), so a compromised remote machine cannot erase
   backups. Retention and space reclamation run on the gateway itself.
