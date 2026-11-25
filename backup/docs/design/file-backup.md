# Design note: backups of chosen files and folders

Status: implemented (crate `filebackup`, agent `folders.rs`, VSS paths in
`snapshot-win`).

Disk images protect whole systems. Laptops, file servers and NAS shares
often need only some folders, more often, and smaller.

## 1. Storage

A folder backup uses the layout of SaaS backups (`saas::store`): an image of
two disks.

* Disk 0, the index (JSON): every file, folder and symbolic link backed up,
  with its path, size, modification time, BLAKE3 hash, attributes (Unix
  mode and owner, or Windows attributes) and its chunks.
* Disk 1: the files' bytes, each file starting on a chunk of its own.

The image's OS family is `files`; its machine ID is `files:<agent machine
ID>`, so retention and lineage are kept apart from the same machine's disk
images, while Fenrir Cloud lists it with that machine's backups (by agent).
Encryption, deduplication, verification, off-site copies, Object Lock and
prune work unchanged.

## 2. Incremental forever

A file whose size and modification time match the previous folder backup of
the machine is not read: its chunks are taken from the previous index. Every
backup lists every file, so each restores on its own and any of them can be
deleted by retention. New and changed files are read and stored, and
unchanged chunks are deduplicated as usual. Large files are streamed one
chunk at a time.

## 3. What is read

* Paths are full local paths (`C:\Users\anna\Documents`, `/home/anna`) or
  network shares (`\\server\share\folder`, read with the agent's sign-in).
  They are recorded with `/` separators, a share under `UNC/server/share`.
* Exclusions: names with `*` and `?` wildcards (`*.tmp`, `~$*`,
  `node_modules`), or full paths (that folder and everything in it). Paging
  and hibernation files, the recycle bin, System Volume Information,
  `Thumbs.db`, `.Trash-*` and `lost+found` are always left out. Matching
  ignores case.
* On Windows, the local volumes holding the paths are snapshotted with VSS
  (copy backup, so application logs are left alone) and files are read from
  the snapshot: open and locked files are copied as they were at one moment.
  Without a snapshot (VSS failed, a share), files are read live and the job
  says so.
* Symbolic links are recorded, not followed. Devices, sockets and pipes are
  skipped. A file that cannot be read is reported (at most 200 listed) and
  the backup goes on.

### macOS: the whole Data volume from an APFS snapshot

On macOS the agent makes an APFS local snapshot (`tmutil localsnapshot`), mounts the Data volume's snapshot
read-only (`mount_apfs -s`) and reads the chosen paths from it, so every file is as it was at one moment; the
snapshot is deleted afterwards. Choosing `/` backs up the whole Data volume (users' folders, applications,
`/Library`, `/private`, `/usr/local` and so on): the sealed, signed system volume is not backed up, since it is
restored by installing macOS (from macOS Recovery), after which the Data volume is restored into it. The agent
needs to run as root with Full Disk Access (System Settings › Privacy & Security); without a snapshot the files are
read live and the backup says so. The job result names the snapshot used (`APFS …`, or `VSS` on Windows), and
the CI round trip runs on macOS too. GitHub's hosted macOS runners refuse local snapshots (tmutil has no
Full Disk Access there, and creating APFS snapshots any other way needs an entitlement Apple grants only to
signed apps), so CI checks that the backup falls back to the live files and says so, and that the restore is
byte-exact; the snapshot path itself needs a Mac where the agent has Full Disk Access.

## 4. Restore

The index is presented as a browsable volume (`IndexVolume`), so
Images & restore › Browse files lists it, and file restore, downloads to the
browser and malware scans work as for disk images. Each file is checked
against its BLAKE3 hash as it is read. **Where each item was** (target
`@original`) puts each chosen item back in its original folder on the
machine. Disk restore and boot tests are refused for folder backups.

## 5. Not covered yet

* Windows ACLs and alternate data streams are not kept (attributes are);
  Unix mode and owner are recorded but restored files get the restoring
  account's defaults.
* Sign-in details for shares other than the agent's own.
* Changed-file detection reads directory metadata each run; a journal (USN,
  fanotify) would avoid even that.

## 6. Tests

* `filebackup`: back up a tree with exclusions, browse and read back through
  the index (names ignore case), an incremental run reads only the changed
  file, the older backup keeps the old version, restore through `filebrowse`
  (empty folders included), unreadable paths reported, a damaged chunk
  detected by its hash, exclusion patterns, share paths.
* `snapshot-win::paths`: paths map into the snapshot of their volume
  (deepest mount point first); shares and unsnapshotted drives read live.
* Agent: original-location parents for drives, Linux paths and shares.
* `cloud/tests/test_device_backup.py`: validated paths and exclusions,
  capability check, plans, listing with the machine, disk restore and boot
  test refused, `@original` only for folder backups.
