# Decision record: changed-block tracking for physical machines

Status: **Linux built (dm-era), Windows not planned** (a kernel filter driver
needs Microsoft attestation signing, which is not available). See section 6. Hyper-V VMs already
have changed-block tracking through RCT (`frequent-backups.md` §3.1).

## 1. Problem

Every backup of a physical machine reads all used blocks of its disks
(NTFS bitmap on Windows, snapshotted extents on Linux). Deduplication keeps
storage small, but reading takes roughly the used size at the disk's read
speed, so a backup every few minutes only suits small servers.
Changed-block tracking (CBT) reads only blocks written since the last
backup.

## 2. What is already in place

* The engine takes changed ranges per disk (`engine::ChangedSince`): a chunk
  is reused from the previous image only if none of its bytes changed and
  its used ranges are unchanged; about one chunk in 64 reported unchanged is
  read anyway and compared, and a mismatch fails the run before a manifest
  is written (the agent then reads everything). Disks are read in full at
  least weekly.
* Any tracker plugs in by supplying, per disk, the byte ranges written since
  a named earlier image. Hyper-V RCT does this today.

The risk with any tracker is the same: a missed write silently copies an old
block into a new image. The safeguards above limit that, but the tracker
must be exact by design.

## 3. Options

### Windows

| Option | Exact? | Effort and cost | Notes |
|---|---|---|---|
| **Own volume filter driver** (records written ranges per volume in a bitmap, persisted across reboots, reset after each backup) | Yes, by design | A kernel driver: weeks of work, HLK testing, EV code-signing certificate, Microsoft attestation signing (WHQL for Windows Server). Ongoing maintenance with each Windows release. | The standard approach of commercial products. Unclean shutdowns and driver updates must trigger a full read. |
| NTFS change journal (USN) mapped to clusters | No | Small | Lists changed files, not blocks. Misses metadata moves (defragmentation, compression, directory indexes) and file moves into recently freed clusters. Rejected. |
| VSS differential area | No | n/a | Only covers the life of one snapshot. |
| Compare with the previous image | Exact | None | What happens now: still reads everything. |

### Linux

| Option | Exact? | Effort | Notes |
|---|---|---|---|
| **Thin LVM** (`thin_delta` between the previous and the new thin snapshot) | Yes (block level, pool chunk size) | Medium | Only for thin volumes. The live backup images the physical disk with overlays of linear LV extents; thin volumes must instead be imaged as their own devices (from their thin snapshot), which is a change to `live.rs`. The previous snapshot is kept until the next run. |
| `dm-era` target under the file system | Yes | Medium | Needs a device-mapper layer inserted under the file system (unmount once, as CDP's `log-writes` does). Opt-in per volume. |
| CDP journal (`cdp.md`) | Yes | Small, where CDP is on | Volumes with CDP enabled already journal every write; the journal can supply changed ranges for image backups too. |
| File system metadata (ext4 change times, btrfs generations) | ext4: no; btrfs: yes | Small (btrfs) | `btrfs send`-style generation comparison is exact for btrfs only. |

## 4. Recommendation

1. **Windows: build the filter driver** only if 5-to-15-minute backups of
   physical Windows servers with large data sets are a product requirement.
   Most customers' servers are VMs, where Hyper-V RCT already applies;
   physical servers with modest data read fast enough hourly.
2. **Linux: start with the CDP journal** (cheapest, exact, reuses existing
   code), then **thin LVM** for thin volumes. Treat `dm-era` as a later
   option.
3. Keep the engine safeguards for every tracker, and prove each one on real
   hardware before turning it on by default.

## 5. Decisions needed

* Is CBT on physical Windows servers a requirement? If yes: budget for an EV
  code-signing certificate, a Microsoft Partner Center account for
  attestation signing, HLK test machines, and driver maintenance.
* Linux test hardware or VMs with LVM (thin pools) and device-mapper, in CI
  or a lab. The build container used so far has no device-mapper, so
  neither thin LVM nor `dm-era` can be exercised there.
* Patent check before shipping: block-level change tracking and
  continuous data protection are crowded patent areas; a freedom-to-operate
  review is advised (the techniques above are long-standing and documented
  publicly, but this is not legal advice).

## 6. What was built (Linux)

`fenrir-backup cbt` (CLI; `crates/cdp/src/era.rs`):

* `cbt enable --name N --volume /dev/vg/lv` (unmounted): a 32 MiB metadata LV
  `<lv>-fenrir-era` and the device-mapper `era` target over the volume,
  `/dev/mapper/fenrir-era-N`, which is mounted from then on (as with CDP).
* `cbt backup --name N`: with the file system frozen (`fsfreeze`), the era is
  checkpointed and an LVM snapshot of the volume made; the file system is then
  thawed. The blocks written since the previous backup's checkpoint are listed
  by `era_invalidate --written-since` from a metadata snapshot, and the engine
  reads only those (`ChangedSince`), taking every other chunk from the previous
  image after checking about one in 64 of them. The first backup, or `--full`,
  reads everything. The saved era only moves forward after a backup succeeds,
  so a failed backup makes the next one read more, never less.
* Recovery is unchanged: the images are ordinary disk images of the volume.

Proof: CI job `cbt` (`ci/e2e-cbt.sh`) on a real kernel: after 1 MiB of a 40 MiB
file changes, the second backup reads only the changed blocks (more than 30 MiB
taken unread from the first image) and its restore gives a clean ext4 with
byte-identical files.

Windows physical machines keep reading their used blocks (VSS) on each backup;
Hyper-V VMs use RCT.
