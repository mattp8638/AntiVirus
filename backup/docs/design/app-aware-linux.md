# Application-aware live images on Linux

Windows images coordinate with applications through VSS writers (app-aware.md). On Linux there is no
system-wide equivalent, so a live backup (phase-6.md) coordinates with what runs on the machine itself,
from just before the first frozen copy until every LVM snapshot exists. Code: `crates/snapshot-linux/src/apps.rs`.

## What is coordinated

| Application | How | Coordinated when |
|---|---|---|
| Hooks | Each executable in `/etc/fenrir-backup/hooks.d` (sorted by name) runs with `freeze` before and `thaw` after (reverse order), 120 s limit each. | It exited 0 on `freeze`. |
| MySQL / MariaDB | One client session runs `FLUSH TABLES WITH READ LOCK`, holds it while the snapshots are taken, then `UNLOCK TABLES`. | Its data folder and InnoDB log and data folders are in one snapshot. |
| PostgreSQL | `CHECKPOINT` (so starting from the image replays little), then nothing held. | Its data folder, `pg_wal` and every tablespace are in one snapshot. |

PostgreSQL's documentation allows a file system snapshot as a backup when the snapshot holds the data folder
and the write-ahead log at the same instant: the server then starts from it as after a power cut, losing
nothing committed before the snapshot. That is exactly what one LVM snapshot gives. Several logical volumes
are snapshotted one after another and are not one instant, so a cluster spread over them is listed as not
coordinated (a low-level backup with `pg_backup_start` would need WAL archiving, which is not assumed).

MySQL's read lock stops writes to every table, so the snapshots of several volumes agree, but InnoDB still
flushes pages in the background; the same one-volume rule applies to its data and logs.

An application whose files are not on the imaged disks at all is left alone and not listed (imaging a data disk
of a machine whose database is elsewhere). Each MySQL/MariaDB server is reached through the socket it was
started with (`--socket=`), as root over socket authentication by default, or with the options in
`/etc/fenrir-backup/mysql.cnf` (`[client]` `user=`, `password=`); keep that file readable by root only.

## Result

Every application found is listed in the image (`applications`, as on Windows) with whether it was coordinated
and why not. The image is `application`-consistent when at least one application was found and all of them were
coordinated; otherwise `crash`-consistent as before. Failing to coordinate never fails the backup.

## Safety

* Hooks run as root, so they and their folder must be owned by root and not writable by group or others;
  anything else is listed as not run.
* Everything frozen or locked is released however the backup ends (errors included), before the image is read.
  A MySQL session that stops answering is closed, which releases its lock.
* Nothing here is configured from the server: hooks and credentials exist only on the machine.

## Tests

`ci/e2e-app-aware-linux.sh` (CI job `app-aware-linux`): a running PostgreSQL cluster and MySQL server on an LVM
volume, each with a writer inserting rows during the backup, and a hook. The image must be application-consistent
and list both databases and the hook; the hook ran `freeze` then `thaw`. Restored onto another disk, both start on
the restored files with every row committed before the backup, no MySQL row from after it, and amcheck and
`CHECK TABLE` clean.
