# Phase 2 design note: recovery media and bare-metal restore

Status: done.

Goal: a machine whose disk has died, been wiped or been encrypted by
ransomware can be put back from a backup without any operating system on it.
Boot it from a USB stick or ISO, and either restore from the web UI (the
stick connects to the server by itself) or, with no server, from a text
wizard on the machine's screen.

## 1. What ships

| Piece | Where | Licence notes |
|---|---|---|
| Recovery ISO (Debian 13, x86_64, UEFI + Secure Boot, legacy BIOS) | `recovery-env/` build scripts, built in CI | Assembles Debian packages (various, incl. GPL); nothing in a Rust crate links them |
| Recovery agent mode (`fenrir-backup-agent recovery`) | `crates/agent` | permissive deps only |
| Restore to a different-size disk, boot fix-ups | `crates/engine` (`fit.rs`, `bootfix.rs`) | adds `fatfs` (MIT) |
| Personalised ISO download, recovery machines, restore-to-disk flow | `crates/server`, `ui/`, and Fenrir Cloud | none new |
| Optional WinPE media builder (§6) | `recovery-env/winpe/` PowerShell, run by the user with their own Microsoft ADK | WinPE is never redistributed |

## 2. Recovery ISO

Built with `mmdebstrap` from Debian stable, no live-build:

* Root filesystem: `linux-image-amd64`, `live-boot`, `systemd-sysv`,
  firmware packages from `non-free-firmware` (NICs, storage), `network-manager`
  (wired DHCP automatically; `nmtui` for Wi-Fi and static addresses),
  `efibootmgr`, `cifs-utils`, `ntfs-3g`, `parted`, `whiptail`,
  `ca-certificates`. Plus `fenrir-backup` and `fenrir-backup-agent` from the
  same CI run. Compressed to `live/filesystem.squashfs`.
* Boot: Debian's Microsoft-signed `shimx64.efi` and Debian-signed
  `grubx64.efi` and kernel in an EFI System Partition image (El Torito, UEFI),
  `grub-pc` for BIOS; `xorriso` writes a hybrid ISO that also works when
  written to a USB stick byte for byte. Secure Boot stays on.
* `recovery-env/THIRD_PARTY.md` lists the packages and their licences,
  generated from the image's `dpkg` database at build time. Source for every
  GPL package is available from Debian (`deb-src`, snapshot.debian.org); the
  build records the exact package versions.
* Nothing is written to any disk at boot. Disks are not mounted unless the
  user asks the wizard to read a repository from one (read-only).

### Personalised downloads

The ISO contains `/fenrir/recovery.json`, a fixed 4096-byte file that starts
with the marker `FENRIR-RECOVERY-CONFIG-V1\n` and is padded with spaces.
When a user downloads the ISO from the web UI, the server streams the stock
ISO and replaces those 4096 bytes (found once by scanning for the marker,
then cached) with:

```json
{"server": "https://backup.example.lan:8443", "pin": "<sha256 of cert or empty>",
 "token": "<enrolment token, role recovery>", "expires": 1767225600}
```

ISO 9660 has no file checksums, and the file is outside the signed boot
chain, so Secure Boot is unaffected. The stock ISO (marker only) works
too: the agent then looks for `fenrir-recovery.json` in the root of any
FAT, exFAT or NTFS volume (a second USB stick), then asks on screen.

Recovery enrolment tokens are multi-use (one stick, many machines), expire
after 30 days by default and can be revoked. A recovery agent can do
nothing until an administrator gives it access to a repository, which seals
the repository secret to that boot's key in the browser as for any machine.
Keys never leave the client: each boot generates a fresh X25519 key pair
in RAM.

## 3. Recovery agent mode

`fenrir-backup-agent recovery [--config FILE]`:

* State lives in RAM (`/run/fenrir-recovery`, or `X:\fenrir` on WinPE).
* Enrols with role `recovery`, hostname `recovery-<DMI serial or MAC>` and
  `machine_id` = DMI product UUID when present, so booting the same machine
  again updates the same entry instead of adding one.
* Inventory: every disk with size, model, serial and logical sector size;
  the disk the stick booted from and any disk with a mounted partition are
  marked `system` and cannot be chosen. Also reports the firmware mode it
  booted in (`uefi` / `bios`) and whether Secure Boot is on.
* Capabilities: `restore_disk` and `browse` only. No backups, no
  self-update, no gateway serving.
* On tty1 a status screen (`recovery-env/overlay/usr/local/sbin/fenrir-console`,
  whiptail) shows network state and "connected to *server* as *name*:
  continue in the web UI", and a menu: network settings, offline restore
  (§5), shell, reboot, power off.

The server lists recovery machines separately ("Recovery sessions"), shows
them online while booted, and deletes offline ones after 7 days.

## 4. Bare-metal restore (engine)

Restore of one image disk to one target disk, as today, plus:

### 4.1 Different-size target (`engine::fit`)

* **Larger:** written as today, then the GPT is moved to the real end:
  primary header gets the new `alternate_lba` and `last_usable_lba`, a
  backup header and entry array are written at the end, CRCs recomputed,
  the stale backup header at the old end is zeroed. MBR needs nothing.
  Partitions are not grown: the extra space is unallocated and can be added
  with Disk Management / `growpart` afterwards (growing NTFS or ext4 is
  Phase 5).
* **Smaller:** allowed only when every partition ends at or before the new
  last usable LBA (GPT) or the target end (MBR), i.e. the original disk had
  unallocated space at its end. Writes past the target end are then only
  the old backup GPT, which is clipped. Otherwise refused, naming how much
  space is needed.
* **Different logical sector size** (512 vs 4096): refused; LBAs in the
  partition table and file systems would be wrong.

The rewrite uses the partition-table bytes stored in the manifest, not what
was just written, and is checked by parsing the result with the same parser
backup uses.

### 4.2 Boot fix-ups (`engine::bootfix`)

New hardware has no firmware boot entry for the restored system:

* **UEFI fallback loader:** on the restored ESP (FAT, via `fatfs`), if
  `\EFI\BOOT\BOOTX64.EFI` is missing, copy Windows'
  `\EFI\Microsoft\Boot\bootmgfw.efi`, or a Linux shim
  (`\EFI\<distro>\shimx64.efi` with its `grubx64.efi` and `mmx64.efi`), or
  a lone `grubx64.efi`. Existing files are never overwritten.
* **Firmware entry:** in the recovery environment, booted in UEFI mode,
  the agent adds an entry with `efibootmgr` pointing at the same loader
  (run as a separate program; skipped where unavailable).
* **Firmware mode check:** an image from a UEFI machine will not boot on a
  machine started in legacy BIOS mode and vice versa. The UI warns before
  the restore; the job result repeats it with what to change in the
  firmware settings.
* BitLocker: the Windows agent reads volumes through their VSS snapshot,
  above BitLocker, so the image holds them decrypted (encrypted by the
  repository key). They restore unencrypted and start without the recovery
  key; the partition tail outside the snapshot (NTFS backup boot sector) is
  synthesised from the decrypted boot sector rather than copied as
  ciphertext. The job reminds the administrator to turn BitLocker on again.
  Volumes captured raw (Hyper-V guests' own BitLocker, unsnapshotted
  volumes, Linux backups of Windows disks) stay encrypted; the job says
  their recovery key is needed on new hardware.

Driver injection for different storage controllers is Phase 5.

### 4.3 Whole machine

A machine with several disks is restored disk by disk; the UI queues one
job per disk mapping (image disk → target disk), each with its own typed
confirmation of the target.

## 5. Offline restore (no server)

`fenrir-console` → **Restore from a repository here**: choose where the
repository is (a USB disk or local disk, mounted read-only; or an SMB share),
enter the passphrase or pick a recovery-key file, choose an image and disk,
choose the target from the list (system/boot disks excluded), type the
target's name to confirm. It runs
`fenrir-backup restore disk ... --yes` with `--fit` and `--boot-fixup`
(new CLI flags matching §4), showing progress.

## 6. WinPE (optional)

Windows refuses raw writes to sectors of a mounted volume, so a whole-disk
restore on Windows (Windows PE, or a running Windows onto a disk other than
its own) first takes the target over (`snapshot_win::win::disks`):

* the disk must be a listed physical disk, not the one holding the running
  Windows, the Windows PE medium (`sources\boot.wim`, `fenrir\recovery.json`)
  or a page file;
* an offline or read-only disk is made online and writable for this boot;
* every volume on it is locked (`FSCTL_LOCK_VOLUME`, which fails while files
  are open: the restore is refused and nothing is written) and dismounted;
* the disk is written through `\\.\PhysicalDriveN` in whole sectors (the
  boot fix-up goes through a sector-aligned adapter);
* afterwards `IOCTL_DISK_UPDATE_PROPERTIES` makes Windows read the restored
  partition table, and the old volume handles are released.

Windows PE identifies the machine from SMBIOS (system UUID and serial), the
same values the Linux ISO reads, so either medium updates the same recovery
session entry. Tested on a Windows CI runner with two virtual disks
(`ci/windows-disk-restore.ps1`); the media build is tested there too with
the ADK installed.


`recovery-env/winpe/New-FenrirWinPE.ps1` on a Windows PC with the Windows
ADK and WinPE add-on: `copype amd64`, mounts `boot.wim`, adds the Windows
agent and CLI and a `startnet.cmd` that runs `wpeinit` then
`fenrir-backup-agent recovery`, optionally injects drivers from a folder
(`-Drivers`), and produces an ISO or writes a USB stick. Useful where Linux
lacks a storage driver. Not built or published by this project.

## 7. Safety

* Nothing is written to any disk except the target the administrator chose
  and confirmed by typing its device name (UI), or `--yes` (CLI).
* The boot medium and mounted disks are refused by the engine
  (`check_block_device_unused`), not just hidden in the UI.
* Boot fix-ups only add missing files on the restored ESP of the target.
* `efibootmgr` only adds an entry; it never deletes or reorders existing
  ones except to put the new entry first in `BootOrder`.

## 8. Tests

* `fit`: grow and shrink GPT (512 and 4K sectors) and MBR on synthetic
  disks, re-parse with `partition::read_table` (both headers valid, CRCs);
  shrink refused when a partition does not fit; sector-size mismatch refused.
* `bootfix`: build a FAT ESP in memory with each loader layout, run the
  fix-up, check the fallback files and that existing ones are untouched.
* Agent: recovery config search order, machine id, inventory marks the
  boot disk as system.
* Server: ISO personalisation replaces exactly the placeholder; recovery
  tokens; recovery machines listed and cleaned up.
* CI: build the ISO, boot it in QEMU (OVMF with Microsoft Secure Boot keys
  enrolled, and SeaBIOS) with a server on the host network; the recovery
  agent enrols, a restore job writes a test image to a second virtual disk,
  which then boots.
