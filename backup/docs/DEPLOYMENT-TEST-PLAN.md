# Deployment test plan

A checklist for the first real deployment. Work through it in order on test
machines before protecting anything you depend on. Each step says what to
do, what you should see, and what to send back if it does not happen.

**What has and has not been tested before this plan:** everything on Linux
has been run end to end (server in Docker, agent enrolment through the
generated installer, backups, retention, space reclamation, restore to
VHDX checked with qemu-img, ransomware hold, alerts, and booting a
backup as a VM from the UI on a Linux host with QEMU). On Windows, CI
plans a VSS system backup on a real Windows Server VM on every change
(snapshot set, NTFS used-cluster map, reads through each snapshot): this
found and fixed a bug where reads at the very end of C: ran past the
snapshot volume. **A complete Windows system backup and restore, the
Windows service, Hyper-V VM backup and restore, and the macOS agent have
not yet run on real machines.** Sections 3 to 5 are where problems are
most likely; please report everything you see there.

When something fails, collect:

* the job's error (Activity page, or the machine's Activity tab);
* the agent log: Windows `C:\ProgramData\Fenrir-Backup\agent\agent.log`, Linux
  `journalctl -u fenrir-backup-agent` and `/var/lib/fenrir-backup-agent/agent.log`, macOS
  `/Library/Logs/fenrir-backup-agent.log`;
* the server log: `docker logs fenrir`.

## 0. Before you start

* [ ] A server with Docker, reachable from every machine on TCP 8443.
* [ ] A backup target the machines can write to: a NAS share, a second
      disk, or a folder on the server exported over SMB/NFS. Plan for
      roughly 1.5 × the used space of the machines for the first month.
* [ ] One test machine of each kind you will run: Windows 10/11, Windows
      Server, a Hyper-V host with two or three test VMs (one Windows, one
      Linux), Linux, Mac.
* [ ] An email account or Slack/Teams webhook for alerts.

## 1. Server

1. [ ] Set the public address in `compose.yaml`:
       `FENRIR_PUBLIC_URL: https://<server address>:8443`, then
       `docker compose up -d --build`.
       **Expect:** `docker ps` shows the container `healthy` within a minute.
2. [ ] Open the URL, accept the certificate warning, create the
       administrator account.
       **Expect:** the overview with "Get started in three steps".
3. [ ] Settings → Alerts: configure email or a webhook → **Save and send a
       test**. **Expect:** "sent" next to the channel and the message
       arrives. If it says otherwise, the error text is the SMTP/HTTP
       server's answer.
4. [ ] Copy the Windows, Hyper-V and macOS agent builds from the CI bundle
       into the container (see `compose.yaml`) and restart it.
       **Expect:** Add machines no longer marks those platforms as
       unavailable.

## 2. Linux machine

1. [ ] Add machines → Linux → Create installer → run the one-line command
       on the machine as root. **Expect:** "installed and running", the
       machine appears online within a minute.
2. [ ] Repositories → New repository, created by this machine, in a new
       folder on your backup target. Download and keep the recovery key.
       **Expect:** status "Ready" within a minute.
3. [ ] Attach a spare disk (or a USB stick) with some files, then Backup
       plans → New plan for that disk, retention "Short", daily.
       **Run now.** **Expect:** succeeded; the image appears under the
       machine's Backups.
4. [ ] Change a few files on that disk, run the plan again.
       **Expect:** "Incremental", with a small "New data" figure.
5. [ ] Restore → As a virtual disk → a folder on the machine.
       **Expect:** a `.vhdx` file. Check it:
       `qemu-img convert -O raw <file>.vhdx /tmp/r.img` and mount
       `/tmp/r.img` (loop device) and compare a few files.

## 3. Windows workstation / server (not yet run on hardware)

1. [ ] Add machines → Windows → Create installer → download
       `Fenrir-Backup-Setup.exe`, run it on the machine and allow the administrator
       prompt (SmartScreen: More info › Run anyway; the file is not
       code-signed). **Expect:** the window ends with "Done"; `Get-Service
       FenrirBackupAgent` is Running; the machine appears online. (CI runs this,
       the PowerShell one-liner and the script on a Windows runner; this
       step is about a real desktop: SmartScreen, antivirus, UAC.)
2. [ ] Give it access to the repository (Repositories → Give access) or
       create a new one on a share it can write to (it runs as
       LocalSystem: grant the computer account `DOMAIN\NAME$` write access,
       or use a local disk).
3. [ ] **Back up now** with the whole system.
       **Expect:** a VSS snapshot, then progress; "App-consistent" on the
       image. Note the time it took and the "Captured" size: it should be
       close to the used space of C: plus the EFI and recovery partitions,
       not the full disk size.
4. [ ] Run it again. **Expect:** incremental, much faster, little new data.
5. [ ] Restore → As a virtual disk to a local folder; double-click the
       VHDX. **Expect:** Windows mounts it and you can open
       `Users\<you>\Documents` and copy files out.
6. [ ] (Optional) Attach the VHDX to a new Hyper-V VM of the same
       generation and boot it. **Expect:** Windows boots. (This is the
       same check the future boot-verification feature automates.)

## 4. Hyper-V host (not yet run on hardware)

1. [ ] Run the **Hyper-V host** installer on the host itself.
       **Expect:** the host appears with its VMs listed (refreshes every
       five minutes).
2. [ ] Give it repository access. Select one running Windows VM and one
       Linux VM → **Back up selected**.
       **Expect:** Hyper-V Manager shows a short-lived recovery checkpoint
       on each VM that disappears when its backup ends; the images are
       "App-consistent" (a Linux VM without integration services shows
       "Crash-consistent" with a warning, which is expected).
3. [ ] Check that no checkpoint is left behind in Hyper-V Manager and no
       `.avhdx` files remain next to the VM disks.
4. [ ] Restore one VM → **As a new Hyper-V VM**, new name, your switch,
       "Start" off. **Expect:** a new VM with the same generation, CPUs,
       memory and disks; start it by hand and check it boots. The original
       VM is untouched.
5. [ ] Kill test: start a VM backup and restart the `FenrirBackupAgent` service
       halfway. **Expect:** the job is marked failed after a few minutes;
       when the agent starts again it removes the checkpoint it left.

## 5. macOS (not yet run on hardware)

1. [ ] Run the macOS installer with sudo; add `fenrir-backup-agent` to Full Disk
       Access. **Expect:** the Mac appears online with its OS version.
2. [ ] Run **Verify** against the repository. **Expect:** succeeded.
       (System backups of a Mac are not available yet.)

## 5a. Repository on a network share

1. [ ] On the backup server, create a share and a dedicated account with
       change rights on it only.
2. [ ] Repositories → New repository → folder `\\server\share\fenrir`
       → Username and password → **Test connection**. **Expect:** "Signed in
       to the share and wrote a test file" and the share's free space. Try a
       wrong password once: **Expect** "wrong username or password".
3. [ ] Create the repository and back up a machine into it. **Expect:**
       while no backup runs, the machine has no connection to the share
       (`net use` in an elevated prompt shows nothing for it; the share is
       not visible to the logged-in user).
4. [ ] Change the account's password on the server, then Change sign-in on
       the repository. **Expect:** the next backup works on every machine.

## 6. Retention, space and protection

1. [ ] After a few days of nightly backups with "Short" retention, the
       machine keeps about 7 daily + 4 weekly images, and Repositories
       shows a recent "Space reclamation" run.
2. [ ] Ransomware drill on the Linux test disk: fill most of it with random
       data (`dd if=/dev/urandom of=<mounted test disk>/junk bs=1M count=<~80% of size>`)
       and run the plan. **Expect:** the image is flagged "Possible
       ransomware", the repository shows "Deletions on hold", you get an
       alert, and the next retention job stays queued. Release the hold
       (type `release`) and the queue continues.
3. [ ] Recovery key drill: on any machine with the CLI,
       `fenrir-backup --repo <path> --recovery-key <key file> image list`.
       **Expect:** the images are listed without the passphrase.
4. [ ] Verify → Full on the repository once. **Expect:** no damaged data.

## 6a. Boot verification

Needs a Linux machine with QEMU (see DEPLOY.md, "Boot verification"); with
`/dev/kvm` if possible.

1. [ ] Machines → the Linux host shows it can boot VMs: its images get a
       **Test boot** button, and the Test boot dialog lists it as
       "QEMU/KVM".
2. [ ] Test boot the newest image of a Windows machine. **Expect:**
       "Boots" within ~2 minutes with KVM (Windows answers on RDP), and a
       screenshot of the login screen. If it says "Check screenshot", send
       the screenshot.
3. [ ] Test boot with "Keep it running". **Expect:** the host's Overview
       tab lists the VM with ports; with the shown `ssh -L ...` command,
       a VNC viewer on `localhost:<vnc port>` shows the VM's screen and an
       RDP client on `localhost:<rdp port>` reaches the Windows login.
       The production machine is unaffected (the copy has no network).
       Press **Stop**; the VM disappears within a minute.
4. [ ] Repositories → Boot verification → on the host, weekly.
       **Expect:** within a minute a boot check is queued for each
       machine's newest image, one after another.
5. [ ] Hyper-V host (if available): Test boot an image on it. **Expect:**
       progress while the VHDX is written, then "Boots" (heartbeat) and a
       screenshot; afterwards no `fenrir-check-*` VM is left in Hyper-V
       Manager and the scratch folder is empty.

## 7. Failure handling

1. [ ] Unplug a machine's network during a backup. **Expect:** the job
       fails or finishes when it is back; the next run reuses what was
       already uploaded.
2. [ ] Stop the server for an hour. **Expect:** agents keep retrying and
       reconnect by themselves; offline alerts arrive only for machines
       that were really off.
3. [ ] Remove a machine in the UI. **Expect:** its agent is locked out
       and logs "must be enrolled again".

## 8. Upgrades

1. [ ] Deploy a newer server bundle (`docker compose up -d --build`).
       **Expect:** within a few minutes every agent reports the new
       version (Machines → details) without reinstalling.

## Not covered yet (planned)

Bare-metal restore from boot media; S3 / Object Lock storage; live snapshots of a
running Linux system disk; file-by-file restore without mounting a VHDX;
macOS system backups.
