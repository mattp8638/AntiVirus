# Phase 3 design note: boot from backup, automatic boot verification

Status: implemented (KVM/QEMU path tested end to end; Hyper-V path
compile-checked, not yet run on a Hyper-V host). Spec §5: run any system image as a VM without
restoring it first, check that it boots, record the result, and schedule
that check as automatic backup verification.

## 1. NBD export from the chunk store (`crates/nbd-server`)

A read-only server for the NBD protocol (the published `proto.md` of the
NBD project: fixed newstyle handshake, `NBD_OPT_GO`/`INFO`/`EXPORT_NAME`/
`LIST`/`ABORT`, simple replies). One export per image disk, named `disk0`,
`disk1`, ...

* Reads map offset → chunk index → chunk; absent chunks read as zeros.
* Decrypted chunks are kept in an LRU cache (default 256 MiB), so a boot
  touches each chunk once.
* Writes, trim and write-zeroes are refused with `EPERM`; the export
  advertises `READ_ONLY`. The backup can never change.
* The export holds a **shared repository lock** for its lifetime, so a
  prune cannot remove chunks a running VM reads.
* Listens on 127.0.0.1 only, on a random port.

QEMU, `qemu-img` and `qemu-io` are used in tests as independent clients.

## 2. KVM / QEMU boot (`crates/vmboot`)

On a Linux host with `qemu-system-x86_64` (KVM if `/dev/kvm` is usable,
otherwise software emulation, much slower and reported as such):

1. Start the NBD export.
2. Per disk, a qcow2 **overlay** whose backing file is the NBD export. All
   guest writes go to the overlay; it is deleted afterwards.
3. Firmware: UEFI (OVMF) if the image recorded UEFI firmware or has an EFI
   system partition, otherwise BIOS. Machine `q35` + AHCI for UEFI, `pc` +
   IDE for BIOS; NIC `e1000`. These have drivers built into Windows and
   Linux, so no driver injection is needed.
4. Network: QEMU **user-mode networking only** (isolated NAT). A booted
   copy of a production machine never appears on the real network, so no
   IP, name or domain conflicts.
5. A QMP control socket, a guest-agent channel and a serial log.

### Health check

Polled every 5 s until a verdict or the timeout (10 min with KVM, 20 min
without):

| Signal | Strength |
|---|---|
| QEMU guest agent answers `guest-sync` | **verified** |
| A guest service answers through a loopback NAT forward at the application level: an SSH banner (22), an RDP X.224 Connection Confirm (3389), or an HTTP status line (WinRM, 5985) | **verified** |
| The screen (QMP `screendump`) is unchanged for 30 s, not blank, after at least 45 s | **screen**: booted to a stable screen; the screenshot needs a human glance (a firmware error or a blue screen is also stable) |
| QEMU reports `guest-panicked`, `internal-error` or `shutdown`; the firmware log or serial console shows "No bootable device", "BdsDxe: No bootable option" or the UEFI shell; or the screen stays blank | **failed** |

A connection that is merely accepted proves nothing: QEMU's user-mode NAT
accepts and holds connections to forwarded ports while the guest is still
in its firmware. Only an application-level reply counts. The screen rule
also ignores a screen identical to the one seen in the first seconds (the
firmware splash).

Every check stores a PNG screenshot, so the UI shows what the VM looked
like. Results are recorded on the server per image.

### Keep running

"Boot and keep running" leaves the VM up after the check, with VNC on the
host's loopback interface and forwards for RDP and SSH, also on loopback.
Reach them over an SSH tunnel to the host. Running sessions are listed in
the host's inventory and stopped from the UI (or automatically after 8
hours). While a session runs, its repository cannot be pruned.

## 3. Hyper-V boot check (agent role `hyperv`)

Writes the image as VHDX into a scratch folder on the host, creates a VM
with the original generation, CPUs and memory and **no network
adapter connected**, starts it, and waits for the Hyper-V **heartbeat**
integration service to report OK (verified). The thumbnail from
`Msvm_VirtualSystemManagementService.GetVirtualSystemThumbnailImage`
becomes the screenshot. The VM and files are removed afterwards. (Not a
copy-free boot: Hyper-V cannot use NBD; materialising takes as long as a
restore.)

## 4. Scheduling and results

* Agents advertise `boot_kvm` / `boot_hyperv` when they can boot VMs.
* New job kinds: `boot_check { image_id, keep_running, memory_mb, cpus }`
  and `stop_vm { session_id }`.
* Repository setting **Boot verification**: a boot host and an interval
  (e.g. weekly). The scheduler queues a boot check of the newest image of
  each machine in the repository that has not been checked within the
  interval.
* Server table `boot_checks` (image, time, host, outcome, method, seconds,
  firmware, acceleration, message, screenshot). The overview shows the
  last verified boot; image lists show each image's latest result.

## Tests

* NBD: `qemu-img convert` reads an export byte for byte; `qemu-io` writes
  are refused; export list; our own client for protocol errors.
* Boot: CirrOS (a 20 MB Linux) backed up into a repository, then booted
  from the backup under QEMU (software emulation in CI): expect
  **verified** (its SSH port answers through the forward), a screenshot,
  and the backup unchanged afterwards (full verify). A non-bootable image
  must not be reported as verified.
* Server: results stored and shown, scheduler queues checks per interval.
* End to end (manual, recorded in `docs/DEPLOYMENT-TEST-PLAN.md` §6a):
  server + agent, repository created in the UI, CirrOS disk backed up,
  "Test boot" with "keep running" from the UI: verified by SSH in about
  70 s under software emulation; screenshot shown; SSH reachable on the
  loopback forward; prune refused while the VM runs; Stop powers it off.
* Hyper-V path: compile-checked; parsing unit-tested; needs a Hyper-V host.
