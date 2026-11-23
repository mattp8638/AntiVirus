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

* **With the Fenrir agent (all-in-one, the default)**: the normal Fenrir installers from **Deploy agents** — the
  Windows `FenrirSetup.exe` and MSI, the RMM / Group Policy / Intune scripts, and the Linux and macOS installers —
  also install the backup agent. It enrols with the same deployment token, works out its role by itself (Hyper-V
  host, server or workstation) and appears under **Backups**; it is linked to the device once the security agent has
  enrolled (by host name, within the customer). Untick **Include device backup** when creating the installer or
  deployment to leave it out (Windows setup also takes `--no-backup` with `--server`/`--enroll-token`).
  * Windows: `FenrirSetup.exe` carries `fenrir-backup-agent.exe` (code-signed with the other components in the
    production build) and installs it last, as the `FenrirBackupAgent` service. Linux and macOS: the installer
    script carries it and installs a `fenrir-backup-agent` systemd unit / `uk.fenrir-backup.agent` LaunchDaemon,
    using the installer's `--proxy` if given.
  * Backup is never allowed to stop the security agent's install: if it cannot be set up, setup says why and
    finishes; add it later from the device's Backup tab.
  * Uninstalling the Fenrir agent leaves the backup agent running, so backups continue and a reinstall keeps
    repository access. To remove it too: `"C:\Program Files\Fenrir-Backup\fenrir-backup-agent.exe" uninstall
    --yes` as administrator, or the uninstallers on the Backups page (Linux, macOS).
  * Linux on ARM gets the backup agent only when the server has an `aarch64-unknown-linux-musl` build (the image
    builds the server's own CPU; CI builds both). Otherwise the installer skips backup with a note.
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
| Browse and restore files; restore to VHDX files or a new Hyper-V VM; boot tests; stop a test VM | `scripts` |
| Install links, repositories, access, plans, share sign-ins, maintenance, gateways | `configure` |
| Overwrite a physical disk, replace existing files with backup copies, release a hold, reclaim space | `destructive` + password re-check |
| Turn automatic agent updates on or off | `platform` |

A disk restore also needs the device name typed exactly. Every change is in the audit log (`backup.*`).

## Boot tests: restore a backup as a VM to prove it works

**Images & restore › Boot test** restores a backup as a virtual machine on a host of your choice and checks that it
starts, with the VM's network disconnected:

* **Hosts**: any Windows machine with Hyper-V (detected by the agent, whatever role it was installed with), or a Linux
  machine with QEMU/KVM. Hosts without access to the repository are listed too: enter the repository passphrase in
  the dialog to give access (encrypted in the browser for that host only).
* **Hyper-V**: the backup is written as VHDX files (dynamic, so about as much space as the data in the backup) in the
  agent's folder or a folder you choose, started as a Generation 1 or 2 VM like the original, and passes when
  Windows' heartbeat integration service answers; otherwise a screenshot shows what was on screen.
* **Keep the VM**: tick it to keep the VM afterwards, so you can log in from Hyper-V Manager and check applications
  and data. It stays (network still disconnected, named `Fenrir check <machine> <date> …`) until you press **Stop and
  remove** in the boot-test dialog or on the host's machine page, which deletes the VM and its disks. QEMU hosts
  keep it running for up to 8 hours.
* Scheduled boot verification (repository settings) tests each machine's newest image regularly and removes the VM
  each time.
* For a lasting copy rather than a test, use **Restore › A new Hyper-V VM** on a Hyper-V host instead.

## Live backups of Linux servers

On Linux the agent backs up the running system (**Whole system** in a plan or Back up now), like VSS on Windows:
every disk holding the system's file systems is imaged while it runs. Logical volumes are read through LVM snapshots
(LVM freezes each file system while taking its snapshot), `/boot` and the EFI partition are copied while frozen, swap
keeps only its header, and the snapshots are removed afterwards (also after a crash, on the agent's next start; other
tools' snapshots are never touched). The image is crash-consistent. The volume group needs free space for the
snapshots during the backup: 10 % of each logical volume, at least 64 MiB; the job says how much is missing. A
system that cannot be snapshotted (a root file system without LVM, LUKS, software RAID) is refused with the reason:
back it up from the recovery media. Disks that only hold the repository are left out. Details:
`backup/docs/design/phase-6.md`.

**Cloning a disk** without a repository (an upgrade to a bigger disk, for instance) is done with the agent's CLI:
`fenrir-backup clone --source /dev/sda --target /dev/sdb --yes --grow [--live]` (Windows: `\\.\PhysicalDriveN`);
see `backup/docs/CLI.md` and `backup/docs/design/phase-5-grow-clone.md`.

## Restoring individual files

**Images & restore › Browse files** (also on a device's Backup tab) opens any backup as a file explorer: pick the
volume (C:, D:, /home…), open folders, tick files or folders and restore them. Nothing is restored to a disk.

* **Who reads the backup**: a backup agent with access to the repository opens the image with the repository key it
  was given, and decrypts only the parts it needs. By default that is the machine the backup came from; any other
  machine with access can do it (useful when the original is broken). The server only relays folder listings, and
  drops them from its records after a day. File contents never pass through it.
* **Where files go**: a folder on the chosen machine (default `C:\Restored\<backup date>`), optionally recreating
  the original folders inside it, or back to the **original location** when restoring on the machine the backup
  came from. If a file already exists: keep both (the backup copy is named `report (restored).docx`), skip it, or
  replace it. Replacing needs the `destructive` permission and a password re-check. Files are written to a
  temporary name and renamed when complete, keep their modification time, and names are made safe for the target
  system. Nothing is written outside the chosen folder, and existing links there are not followed.
* **Permissions**: browsing and restoring files need `scripts`, like other restores. Opening a backup and every file
  restore are audited (`backup.files.browsed`, `backup.files.restore_requested`).
* **Volumes**: NTFS (Windows) and ext2/3/4 (Linux) volumes can be browsed. Windows backups read BitLocker volumes through
  their snapshot, decrypted, so they browse like any NTFS volume (the image is encrypted with the repository key).
  Volumes captured still encrypted (LUKS, a Hyper-V VM's own BitLocker) cannot be browsed: restore the disk or VHDX
  and unlock it there. NTFS
  files that Windows compressed (the folder's "Compress contents" setting) or encrypted with EFS are listed but
  not restored yet. Links and cloud-only placeholders (OneDrive "files on demand") are shown but not restored.
  For other file systems (XFS, Btrfs, FAT, ReFS), restore the volume as a VHDX and open it.
* While someone is browsing, that machine checks in every second instead of every 15, and keeps the backup open
  for 5 minutes after the last request.

## Recovery media: bare-metal restore

For a machine that no longer starts, has a new disk, or is replaced by new hardware.

1. **Backups › Add machines**, choose **Recovery media**, pick the customer and **Create recovery media**, then
   download `fenrir-recovery.iso`. The download carries this server's address and an enrolment code for that
   customer's recovery sessions (valid 1–90 days; revoke it like any install link). Write it to a USB stick
   (balenaEtcher, Rufus in DD mode, `dd`) or attach it to a VM.
2. Start the machine from it; Secure Boot can stay on. It appears under **Machines** as a *recovery session*
   (restores only, nothing installed, everything in memory).
3. **Images & restore › Restore**, choose the session as the machine, give it access (the passphrase is sealed in
   your browser for that session only) and pick its disk. Disks in use on it (its own stick, anything mounted) are not
   offered and are refused by the server and by the agent. A repository on a NAS the session cannot reach is served
   to it through the NAS gateway, if the repository has one.
4. When the restore finishes, remove the stick and restart.

The target disk may be larger (the partition table moves to its end, and with **Use the whole disk**, on by default,
the last partition gets the extra space and its NTFS, ext4 or LVM file system is grown; XFS and Btrfs get the space
and a note to grow them once mounted) or smaller if every partition fits. UEFI systems get the fallback boot loader and a firmware boot entry; if the machine
started in a different firmware mode from the backed-up system, the job says which setting to change. Sessions do not
raise offline alerts and are removed a week after they were last seen. The recovery screen also restores without a
server, from a repository on a USB disk or an SMB share.

**Different hardware.** A restored Windows gets its own storage drivers (AHCI, NVMe, Intel RST, common RAID/SAS
controllers, Hyper-V, VMware, virtio) set to start at boot in its registry, so moving from RAID to AHCI, SATA to NVMe
or a physical machine to a VM does not stop it with INACCESSIBLE_BOOT_DEVICE (a copy of the hive is kept as
`SYSTEM.fenrir-before-hardware`; the job lists the changes).

**BitLocker.** The Windows agent backs volumes up through their VSS snapshot, which reads them decrypted (the image is
encrypted with the repository key instead), so a restored Windows starts without the BitLocker recovery key; the job
reminds you to turn BitLocker on again. Volumes captured still encrypted (a Hyper-V VM's own BitLocker backed up from the
host) need their recovery key on new hardware; the job says which.

**Windows PE media** (optional): for controllers that only have Windows drivers, or to add drivers to the restored
Windows. Build it on a Windows PC with Microsoft's free Windows ADK and Windows PE add-on (Fenrir does not ship Windows
PE): `backup/recovery-env/winpe/New-FenrirWinPE.ps1 -Agent fenrir-backup-agent.exe -Cli fenrir-backup.exe -Settings
fenrir-recovery.json -Drivers <folder>`. The settings file is **Settings file only** of a recovery media link. Driver
packages from `-Drivers`, or from a `fenrir-drivers` folder on any USB stick, are added with DISM after the restore.

**Onto a second disk of a running Windows.** Windows machines can also restore onto a disk that is not their system
disk (Restore › A physical disk): its volumes are locked and dismounted first, and the restore is refused while files
are open on it.

The ISO comes from the backup workflow (artifact `backup-recovery-iso`, built by `backup/recovery-env/build.sh`). Put
it at `<FENRIR_BACKUP_AGENTS_DIR>/recovery/fenrir-recovery.iso` (in the container:
`/app/cloud/downloads/backup/recovery/fenrir-recovery.iso`, for example as a mounted volume); until then the console
says it is missing. Design: `backup/docs/design/phase-2.md`.

## S3 object storage with Object Lock (immutable backups)

Repositories can live on Amazon S3, Wasabi, Backblaze B2, Cloudflare R2, MinIO or any S3-compatible storage: **New
repository › Stored on › S3 object storage**. With **Object Lock** in compliance mode every backup is immutable for the
days chosen: nobody can delete or overwrite it before then, not ransomware holding the keys, not the storage account
owner, not Fenrir.

* Create the bucket with Object Lock enabled (only possible at creation), without a default retention: Fenrir locks
  each object itself. Give Fenrir its own access key limited to the bucket (`PutObject`, `GetObject`, `ListBucket`,
  `DeleteObject`, `DeleteObjectVersion`, `Get/PutObjectRetention`).
* The keys are sealed in your browser for each machine, like a share sign-in; this server never sees them.
  **Test connection** checks the bucket really refuses to delete a locked object.
* Maintenance (weekly by default, and it must run more often than the lock period) renews the locks of backups still
  in use; backups retention no longer keeps are deleted once their lock has run out.
* S3 repositories are reached directly by every machine; the NAS gateway is not used for them.

Design: `backup/docs/design/phase-4-storage.md`.

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

## NAS gateway: machines elsewhere back up to your NAS

Laptops at home or a branch office usually cannot reach the office NAS. One backup agent inside the network — a server
or PC next to the NAS — can serve the repository to them.

1. **Backups › Repositories › Serve through a gateway**: choose the gateway (a machine with direct access to the
   repository). Optionally let it listen for direct connections on a port (default 8475; on Windows it adds a
   Windows Firewall rule for Domain and Private networks) and give an address reachable from outside
   (`host:port`, e.g. a forwarded port or VPN address).
2. **Give a machine access** with **Through the gateway** ticked, for each remote machine. It needs only the
   repository passphrase, not the share sign-in.

How it works:

* Remote machines send each storage request to the gateway: **directly** when one of its addresses answers (the
  address it reports on its own network, then the one you set), otherwise **relayed** through this server over the
  connections both agents already make. No inbound port is needed for the relay. A direct address that fails is
  tried again after five minutes; direct connections never go through a web proxy.
* **End-to-end encryption**: each message is encrypted and authenticated with a key only the two agents can derive
  (X25519 between their own key pairs, HKDF-SHA256, AES-256-GCM; `backup/crates/protocol/src/gateway.rs`). The
  server passes on bytes it can neither read nor forge, and requests older than ten minutes are refused. As
  everywhere in device backup, the agents' public keys come from this server.
* **Append-only**: through the gateway a machine can add backups, verify, browse and restore, but cannot delete or
  overwrite anything except its own lock files. Ransomware on a laptop cannot erase its backup history.
  Retention and space reclamation for the repository run on the gateway (it becomes the maintenance machine).
* The gateway must stay online for remote machines to back up; Backups shows it as offline otherwise. Stop
  serving only after removing the remote machines' access.
* The relay holds messages in memory in the server process (the image runs one worker), at most 512 MiB at a time.
