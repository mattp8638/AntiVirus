# Design note: frequent backups (short RPO)

Status: implemented (schedules and retention); changed-block tracking is
future work, see §3.

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

## 4. Tests

* Schedules: minute intervals validate from 5 minutes, hours-only plans
  still parse, next run times.
* Retention: a backup every 15 minutes for 10 hours keeps one per hour.
