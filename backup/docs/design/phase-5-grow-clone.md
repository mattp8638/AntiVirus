# Phase 5 design note (part): growing the last partition, and cloning disks

Status: implemented. The other part of Phase 5 (restoring Windows onto
different hardware) is in `phase-5-hardware.md`.

## 1. Growing onto a larger disk

`--fit` (Phase 2) lays an image onto a larger disk and moves the GPT to the
new end, but leaves the extra space unused. `--grow` (CLI, agent restore job,
web UI, recovery console) also gives it to the last partition:

1. **Partition table** (engine, all platforms, also for image files): the
   partition that ends last on the disk is extended to the last usable byte,
   rounded down to a whole MiB. GPT: its entry's last LBA, the entry array
   CRC in both headers. MBR: a primary partition's sector count (at most
   2 TiB with 512-byte sectors); a logical partition is not grown.
   Only file systems that can be grown are given the space: NTFS, ext2/3/4,
   XFS, Btrfs, an LVM physical volume, a LUKS container. Anything else
   (FAT, swap, BitLocker, unknown) is left as it was, with a note.
2. **File system** (after the write, on the machine doing it):

   | File system | Linux (recovery media, CLI) | Windows (WinPE, CLI) |
   |---|---|---|
   | NTFS | `ntfsresize` (recovery media) | `diskpart` "extend filesystem" |
   | ext2/3/4 | `e2fsck -f -y`, then `resize2fs` | not possible: note |
   | LVM PV | `pvresize` (the volume group gets free space; logical volumes are not extended) | note |
   | XFS, Btrfs, LUKS | note: they grow while mounted (`xfs_growfs`, `btrfs filesystem resize max`, `cryptsetup resize`) | note |

   An image file target is attached as a loop device (Linux) for the tool.
   A tool that is missing or fails leaves the partition grown and the file
   system at its old size (still valid), with a note saying what to run.

## 2. Cloning a disk

`fenrir-backup clone --source DISK --target DISK --yes [--fit] [--grow]
[--boot-fixup] [--live]` copies a disk straight onto another, without a
repository. It reuses the backup planning (partition table, used extents:
free space in NTFS is not copied) and the restore steps (fit, GPT move,
grow, fallback boot loader). The target gets the same safety checks as a
restore (never the system disk, never a disk in use, `--yes`). The source
must not be in use, or `--live` takes it through a snapshot: LVM on Linux
(Phase 6), VSS on Windows (the system disk). Source and target must differ.

## 3. Tests

* Engine: growing GPT and MBR tables (entries, CRCs, alignment, the
  partition that may grow, file systems that may not); cloning a disk image
  onto a larger file with fit and grow, compared byte for byte inside the
  partitions.
* CI (Linux, loop devices): an image holding ext4 and NTFS partitions is
  restored with `--grow` onto a larger device and the file systems report
  the new size and pass `e2fsck`/`ntfsfix -n`; a clone with `--grow` the same.
* CI (Windows): the whole-disk restore test restores with `--grow`; the NTFS
  volume fills the larger disk.
