# Design note: application-aware backups (Windows VSS writers)

Status: implemented.

## 1. What changes

Windows images were taken in VSS "non-component" mode: every writer froze
and thawed around the snapshot, but none was told which of its data was
backed up. SQL Server then records no backup, Exchange never truncates its
logs, and the image cannot say which databases it holds consistently.

Images are now taken in **component mode** (the documented requester
sequence: `SetBackupState(selectComponents = TRUE)`, `GatherWriterMetadata`,
`AddComponent`, `PrepareForBackup`, `DoSnapshotSet`, then
`SetBackupSucceeded` for each added component and `BackupComplete`):

* Every writer's components are read from its metadata
  (`IVssExamineWriterMetadata`, `IVssWMComponent`, declared by hand from the
  public `vsbackup.h` because the Windows crate does not include them), with
  the paths of the files each component lists, resolved to volumes.
* Top-level components (no ancestor component of the same writer) whose
  files are all on the snapshotted volumes are added; adding one includes
  its subcomponents. A component with files on a volume that is not being
  imaged is not added and the image says which disk to add.
* The Hyper-V writer is left out of whole-system images (it would take a
  checkpoint of every VM; VMs are backed up per VM from the host).
* After the image is stored, each added component is marked as backed up,
  then `BackupComplete`: SQL Server records the backup in `msdb`, Exchange
  can truncate its logs.

The backup type keeps its meaning: **COPY** (default) does not disturb
other backup tools (SQL Server records a copy-only backup, logs are kept);
**FULL** (`--vss-full`, plan option "VSS full") lets SQL Server and Exchange
treat it as a full backup and truncate their logs.

## 2. What is recorded

The manifest gains `applications`: per top-level component, the writer,
logical path and name, caption, whether it was coordinated, and a note (its
subcomponents, or why not). A summary warning lists writers that were only
partly coordinated. Agents report it with the image; the web UI and the
Fenrir Cloud console show the applications under each image's consistency.

## 3. Data disks

`backup system --data-disks-only --include-disk N` images only the given
disks, still through VSS with the writers: a server's database disks without
its system disk.

## 4. Tests

* Unit tests: component selection (top-level only, nested logical paths,
  case, volumes outside the snapshot, the Hyper-V writer, unknown volumes).
* Server API: an image's applications are stored and returned.
* CI `windows-sql`: SQL Server Express with a database on a data disk. A COPY
  backup makes SQL Server record a copy-only backup and the image lists the
  database as coordinated; a FULL backup is recorded as a full backup; the
  image restored to a new disk attaches as a database with the rows from
  before the backup, and DBCC CHECKDB passes.
