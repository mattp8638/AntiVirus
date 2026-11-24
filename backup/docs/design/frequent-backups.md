# Design note: frequent backups (short RPO)

Status: implemented (schedules and retention). Changed-block tracking:
implemented for Hyper-V VMs (RCT, §3.1), not yet validated on a Hyper-V
host; physical Windows and Linux machines still read all used blocks.

## 1. Schedules down to 5 minutes

A plan's interval is hours and minutes (`{"type": "interval", "hours": 0,
"minutes": 15}`), from 5 minutes to 31 days; plans saved with hours only are
unchanged. A plan never has more than one unfinished job, so when a backup
takes longer than the interval the next one starts after it finishes, and a
machine that was offline catches up with one run, not one per missed slot.

## 2. Retention for many restore points

A new GFS rule, `keep_hourly`: the newest image of each of the latest N clock
hours (UTC) that have one. With backups every 15 minutes, "Frequent" keeps
24 hourly, 14 daily, 8 weekly and 12 monthly images: every restore point of
the last hour (by `keep_last`, if wanted) and one per hour for a day.

## 3. What each run reads

Every run reads the used blocks of the disks (NTFS bitmap on Windows, the
snapshotted extents on Linux) and stores only chunks the repository does
not have, so storage grows with the change rate, not with the frequency.
Reading is the cost: roughly the used size at the disk's read speed. That
suits servers whose used data reads in a few minutes; larger systems should
use a longer interval.

Changed-block tracking (reading only blocks written since the last backup)
needs reliable knowledge of every write. The candidates were weighed:

* A Windows volume filter driver records writes exactly. It is a signed
  kernel driver (attestation signing through Microsoft's hardware program),
  a separate deliverable and a business decision.
* The NTFS change journal (USN) lists changed files, not blocks; mapping
  them to clusters misses metadata moves (defragmentation, compression,
  directory indexes), and a missed block silently corrupts an image. Not
  used.
* Hyper-V Resilient Change Tracking (RCT) gives exact changed ranges of a
  VM's virtual disks through the documented WMI API: the right first step,
  for VM backups from the host.
* Linux: thin-provisioned LVM snapshots can report changed blocks
  (`thin_delta`); thick snapshots cannot.

### 3.1 Hyper-V RCT (agent `rct.rs`, engine `ChangedSince`)

1. Backup as before: a recovery checkpoint freezes the VM's disks. The
   checkpoint output now carries each frozen disk's virtual disk ID and size.
2. If the agent recorded a reference point for this VM *in this repository*
   (`hyperv-rct.json` in its state directory, key `<repo id>/<VM id>`),
   `Msvm_ImageManagementService.GetVirtualDiskChanges` is asked, per disk,
   for the ranges written since that reference point's RCT ID, looping on
   `ProcessedByteLength`.
3. The engine reads only the chunks those ranges touch. A chunk is taken
   from the previous image without reading it only when none of its bytes
   changed *and* its used ranges are the same as in the previous image.
   Every image still lists every chunk (self-contained), as before.
4. After a good image the checkpoint is converted to a reference point
   (`ConvertToReferencePoint`; Hyper-V merges the differencing disks as with
   `DestroySnapshot`), its RCT IDs are matched to the disks by virtual disk
   ID and saved, and the previous reference point is removed
   (`Msvm_VirtualSystemReferencePointService.DestroyReferencePoint`).

Safety rules, each falling back to reading the disks in full:

* no record for the VM in this repository, a disk added, replaced (other
  virtual disk ID) or resized, an RCT ID that cannot be matched;
* the previous image is gone (retention), of another machine or of another
  chunk size; the query fails or returns a range outside the disk;
* the weekly full read (`FULL_READ_EVERY_SECS`) is due;
* the plan setting `full_read` is set (checkpoints are then destroyed as
  before and no reference point is kept);
* spot checks: about one chunk in 64 reported unchanged is read anyway and
  compared with the previous image. A difference fails that run with
  `ChangeTrackingMissed` before any manifest is written; the agent backs up
  again reading everything and reports a warning on the job.

The job result's `images[]` say how each image was read: `read_mode`
("full" or "changed_blocks"), `changed_base`, `bytes_unchanged` and
`full_read_reason`.

Not yet proven: the WMI calls have only been exercised through unit-tested
script text and output parsing. Before relying on it, run on a Hyper-V host
(VM configuration version 6.2 or later): back up a VM twice, check the second
job reports `changed_blocks` with a small `bytes_read`, restore both images
and compare, then run a full `verify`. Known gap: if the agent stops between
converting the checkpoint and saving its state, that reference point is
left behind (harmless metadata, removable with WMI); the next backup reads
in full.

## 4. Tests

* Change tracking (engine): a tracked backup reads only the changed chunk
  and restores exactly; a missing base image or untracked disk reads in
  full; a chunk whose used ranges changed is read; spot checks catch a
  write the tracker missed and no image is written.
* Change tracking (agent): queries only for matching disks, weekly full
  read, resized or replaced disks, scripts take ids and paths as data,
  change and reference point output parsing, state file round trip.

* Schedules: minute intervals validate from 5 minutes, hours-only plans
  still parse, next run times.
* Retention: a backup every 15 minutes for 10 hours keeps one per hour.
