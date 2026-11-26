# Design note: restore evidence (BDR-03)

Status: implemented. The agent reports what it wrote, the server keeps a hashed record of every finished restore, and
CI checks both on Linux, Windows and macOS (`ci/e2e-agent-roundtrip.py`).

## 1. Read-back verification of disk restores

`engine::restore_disk` writes chunks in parallel. With `RestoreOptions::verify` (on by default), once everything is
written and synced it reads every restored chunk back from the target and computes its content ID with the
repository's chunk-ID key. Each one must equal the chunk ID in the manifest. Zero-filled ranges must read back as
zeros. This runs before a resized target's partition table is rewritten, so it checks exactly what was copied.

The report (`Verification`) gives:
* chunks and bytes checked;
* zero ranges checked;
* mismatches (count and the first 20 offsets);
* chunks beyond the end of a smaller target;
* `content_sha256`, the SHA-256 of the disk's chunk map (index and content ID, in order). It names exactly the
  content restored and can be recomputed from the manifest.

Targets that can be read back are files, block devices, Windows physical disks (through the same `FileTarget`) and
Azure page blobs (ranged GETs). Virtual-disk containers (VHDX, QCOW2, VDI, VMDK) are written once and are not read
back chunk by chunk. Their files are hashed instead (§2), and the report says `supported: false` rather than claiming
a check.

A mismatch turns the job into a warning: the target does not hold exactly the backup's data.

## 2. What the agent reports

Every restore result carries `evidence`:

| Restore | `outputs` | `verification` | `checks` |
|---|---|---|---|
| Disk / bare metal | target device and bytes | read-back of every chunk | — |
| VHDX, Hyper-V VM, QEMU/VirtualBox/VMware files | each file's SHA-256, read back from disk | file-sha256 | — |
| Azure VM disks | blob URL and bytes | read-back through ranged GETs | — |
| AWS VM disks | S3 object, the VHDX's SHA-256 before upload | file-sha256 | — |
| Files and folders (to a folder or the original place) | SHA-256 of each restored file (first 10,000), read back | file-sha256 | — |
| SQL Server / Exchange database | SHA-256 of each restored file, taken before any attach | file-sha256 | SQL Server: `DBCC CHECKDB` result and each user table's row count |

The backup data itself is authenticated chunk by chunk (AEAD) whenever it is read, so `outputs` and `verification`
check the step after that: that the target holds what was read.

## 3. The server's record

When a restore job finishes, the server builds `fenrir-restore-evidence-v1`:
* job, machine and requester;
* the image, its kind and **recovery point**;
* `requestedAt`, `startedAt` and `finishedAt`;
* `durationSeconds`, which is finished − started;
* `rtoSeconds`, which is finished − requested;
* `rpoSeconds`, which is requested − recovery point. This is the data a failure at the moment of the request would
  have lost.
* the agent's outputs, verification and checks;
* `verified`;
* warnings.

The record is stored as canonical JSON (keys sorted) with its SHA-256 (`restore_evidence`, migration 16).
`GET /api/jobs/{id}/evidence` returns it and recomputes the digest (`intact`). **Activity → Restore evidence**
downloads it as a file. Fenrir Cloud builds the same record from its own job table.

## 4. Tests

* Engine:
  * every chunk is read back and matches;
  * a byte changed on the target afterwards is found at its offset;
  * a write-only target says the check was not supported.
* Agent:
  * hashes match what is on disk;
  * a mismatch makes the job a warning;
  * CHECKDB names are never spliced into SQL, and its result parses.
* Server: RPO, RTO and duration are computed from the job and image times; a tampered record no longer matches its
  digest.
* CI (AT-19 round trip, three systems):
  * the disk restore's evidence shows every chunk read back and matched;
  * the folder restore's evidence lists the same SHA-256 for each file as the source;
  * both have a recovery point, RPO and RTO.
* CI (`windows-sql`): after attaching the restored database, the agent's CHECKDB result is clean and lists the table
  with its 5,001 rows.
