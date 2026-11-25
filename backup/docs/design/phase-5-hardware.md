# Phase 5 design note (part): restoring Windows onto different hardware

Status: done for storage drivers. Cloning and growing file systems are later
parts of Phase 5.

## Problem

Windows starts only the storage drivers it needed where it was installed.
Restored onto a machine with another disk controller (SATA AHCI instead of
Intel RST RAID, NVMe instead of SATA, a Hyper-V or VMware VM instead of a
physical machine) it stops with `INACCESSIBLE_BOOT_DEVICE`. Network and
other drivers do not stop Windows from starting; Plug and Play installs
them afterwards.

## What the restore does

After a bare-metal restore from recovery media (a recovery session, or the
offline wizard on its screen), when the restored disk holds Windows:

1. Find the Windows volume: the NTFS partitions on the restored disk,
   largest first; the first with `Windows\System32\config\SYSTEM`.
2. Read `Select\Current` from the SYSTEM hive for the current control set.
3. For each of Windows' own boot-critical storage drivers (list in
   `crates/agent/src/hwfix.rs`: AHCI, NVMe, IDE, Intel RST/VMD, common
   SAS/RAID HBAs, Hyper-V, VMware and virtio storage) whose service key
   exists and whose driver file is in `System32\drivers`: set `Start` to 0
   (boot) and delete its `StartOverride` key (Windows 8 and later keep
   per-boot-configuration overrides there). A boot-start driver for hardware
   that is not there loads and does nothing; this is the long-standing
   manual remedy, applied automatically.
4. On Windows PE recovery media only: add driver packages with
   `DISM /Image:<volume> /Add-Driver /Driver:<folder> /Recurse` from the
   media's own `X:\fenrir\drivers` (added when the media is built) and from
   a `fenrir-drivers` folder in the root of any attached drive. Unsigned
   drivers are never forced.

Nothing else is changed. A copy of the hive is kept as
`System32\config\SYSTEM.fenrir-before-hardware`, and the job result lists
every change (`windows`: control set, drivers set to boot start, overrides
removed, driver packages added).

A hive whose base-block sequence numbers differ has changes only in its
transaction logs; Windows would replay them over an offline edit, so it is
left alone and the job says so. Images taken through VSS are consistent
(the registry writer flushes the hives), so this is rare.

## Tools

* Linux recovery ISO: the volume is mounted with the kernel's `ntfs3`
  driver (or `ntfs-3g`); the hive is read with `hivexget` and changed with
  `hivexregedit --merge` (Debian's `libhivex-bin` and `libwin-hivex-perl`,
  LGPL, in the recovery image only, run as programs). Extra driver
  packages cannot be installed from Linux; the job says to use Windows PE
  media for those.
* Windows PE: `reg.exe load/query/add/delete/unload` and `dism.exe`, both
  part of Windows PE.

## Boot configuration (BCD)

Windows' boot configuration names its boot and system partitions by the
disk's GPT disk GUID (or MBR signature) and the partitions' GUIDs (or
offsets). A restore or clone writes the partition table as it was, so those
identities are unchanged and the BCD stays valid on any hardware; nothing is
rewritten. Restored disks boot in CI (`ci/e2e-recovery.py`).

The one case where it changes: a clone made on a running Windows while the
source disk is still attached. Windows sees two disks with the same identity
and gives the copy a new one, so the copy's BCD points at the source. Remove
the source before the copy is first attached, or boot the copy alone. If it
already happened, run `bcdboot X:\Windows /s S:` from Windows PE, where X: is
the copy's Windows volume and S: its EFI system partition. Fenrir-Backup does
not run `bcdboot` itself on a running Windows, because it also changes that
machine's firmware boot entries.

## Tests

* `hwfix` unit tests build a real registry hive (regf: base block, hbin,
  nk/vk/lh/sk cells) with services in different states, run the change
  with hivex, and check the values: storage drivers with files set to 0,
  their StartOverride gone, drivers without files and other services
  untouched, other values kept, a second run changes nothing, a dirty hive
  is not touched.
* The Windows PE path is checked on a Windows CI runner against a hive
  saved with `reg save` (see the WinPE work in `phase-2.md` §6).

## Other drivers (Linux recovery media)

Windows PE media add any driver package with DISM. The Linux recovery media cannot run DISM, so it stages
them instead: every `fenrir-drivers` folder (on the medium, or in the root of any partition not on the restored
disk, such as a USB stick) is copied to `Windows\Fenrir\Drivers\NN` in the restored Windows, and
`%SystemRoot%\Fenrir\Drivers` is added to `DevicePath` (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion`),
the folders Windows searches, with their subfolders, for drivers of hardware it finds. When Windows starts it
installs network, chipset, graphics and other drivers from there by itself. Drivers Windows needs before it can
start (a storage controller it has no driver for) cannot be staged this way and still need Windows PE media.

## Linux

Restoring a Linux system onto different hardware from the recovery media, after the image is written, finds the
restored root file system (partitions and logical volumes of the restored disk with `etc/os-release` and
`etc/fstab`), mounts it with its `/boot` and `/boot/efi` from fstab, and inside it (chroot):

* dracut (Red Hat, Fedora, SUSE; host-only by default): `dracut --force --no-hostonly --regenerate-all`;
* initramfs-tools with `MODULES=dep`: writes `conf.d/zz-fenrir-restore` with `MODULES=most` and runs
  `update-initramfs -u -k all`;
* initramfs-tools with `MODULES=most` (Debian and Ubuntu's default) already has the drivers: unchanged.

The result is reported with the restore (`linux`). Network interfaces may be named differently on the new
hardware; settings tied to an interface name or MAC address are left for the administrator.

Code: `crates/agent/src/linuxfix.rs`; tests: the tool detection and fstab parsing (unit tests), and the driver
staging with a real registry hive (`driver_packages_are_staged_for_windows_to_find`, run where the hivex tools
are installed, as in CI).
