# Phase 6 design note: live images of running Linux systems

Status: in progress.

Until now a Linux disk could be imaged only while unmounted (from the
recovery media, or a data disk), or explicitly "inconsistent". Phase 6 makes
"Back up this machine" work on a running Linux server, the way VSS does on
Windows, using LVM snapshots.

## 1. What is captured, and how

`fenrir-backup-agent` (job `backup_system`) and `fenrir-backup backup system`
image every disk that holds a mounted file system of the running system
(`/`, `/boot`, `/boot/efi`, `/home`, ...). For each disk the source is the raw
disk with overlays, like the Windows composite source (moved from
`snapshot-win` to `engine::composite` so both platforms share it):

| Part of the disk | Captured from | Consistency |
|---|---|---|
| Partition table, gaps, unmounted partitions | the raw disk | nothing writes there |
| LVM physical volume: metadata area (`0..pe_start`) | read **before** any snapshot exists | the volume group as it was, without our snapshots |
| LVM linear logical volumes on the PV | an LVM snapshot of each LV, mapped back onto the PV extents of each segment | LVM freezes the file system while it creates the snapshot: file-system consistent |
| Extents of our own snapshots' copy-on-write areas | zeros | they are free space in the captured metadata |
| Mounted partition without LVM, up to 4 GiB (`/boot`, the ESP) | copied to a temporary file while the file system is frozen (`fsfreeze`; FAT cannot be frozen and is copied as is, it is almost never written) | consistent |
| Active swap (partition or LV) | header page kept, the rest zeros | swap holds nothing needed after a restart |

A mounted file system that cannot be snapshotted (a plain partition larger
than 4 GiB, such as a root file system without LVM; thin-provisioned LVs; RAID
or striped LVs) makes the backup fail with an explanation, unless the plan
allows an inconsistent image (then it is read live and the image is marked
`inconsistent`). Those systems are imaged consistently from the recovery
media, or by moving to LVM.

Only the PV's metadata areas and the extents of its logical volumes are
captured; free extents are not. Another tool's snapshot LV is not imaged
(a warning says to remove it after a restore). Inactive LVs are read from
the disk (nothing writes to them). LUKS-encrypted volumes and software RAID
holding mounted file systems are refused (the plaintext seen through a
snapshot does not match the disk): image them from the recovery media. A
disk holding only the repository is left out of an automatic selection.

Snapshots are taken one LV after another (LVM cannot snapshot several thick
LVs atomically); each is consistent in itself. The image is marked
`crash` consistent (file systems clean, applications not told).

## 2. Snapshot size and clean-up

A thick snapshot needs free extents in the volume group for blocks written
during the backup: 10 % of the LV, at most the volume group's free space,
at least 64 MiB. Without enough free space the job says how much is needed.
If a snapshot fills up during the backup, LVM invalidates it and reads fail:
the job fails and says to free space in the volume group.

Snapshots are named `fenrir-snap-<lv>-<random>`. Their names are recorded in
the agent's state folder before they are created and removed after the
backup; a crash leaves the record, and the agent removes those (and only
those) snapshots when it starts.

## 3. Tests

* Unit tests: parsing `pvs`/`lvs` JSON reports, mapping LV segments to disk
  offsets, the composite reader with offset overlays and in-memory and zero
  overlays.
* CI (GitHub runner, real LVM on a loop device): a GPT disk with a small
  ext4 `/boot` and an LVM PV holding an ext4 root LV, mounted, with a writer
  changing files during the backup. The live image is restored to another
  loop device: `fsck` passes on every file system, the volume group has no
  snapshot LV, files written before the backup are intact, and no snapshot
  is left behind. A recorded leftover snapshot is removed by the next run,
  another tool's snapshot is kept.
