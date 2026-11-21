# Phase 1 design note: format, local repository, Windows VSS image backup, CLI, verify

Status: implemented on this branch. Later phases get their own note in `docs/design/`.

## Scope

In:

- `core-format`: repository layout, key management, chunk encoding, signed
  manifests, local-path storage backend, read-only reference reader
  (`fenrir-reader`).
- `engine`: whole-disk image backup from any `DiskSource`, dedup against the
  repository, restore of a disk image to an explicitly chosen target, verify
  (quick, sample, full).
- `snapshot-win`: VSS snapshot set through the COM API with writers
  (application-consistent), used-cluster bitmap via `FSCTL_GET_VOLUME_BITMAP`,
  exclusion of `pagefile.sys`, `hiberfil.sys`, `swapfile.sys` via
  `FSCTL_GET_RETRIEVAL_POINTERS`, partition layout from the physical disk.
- `snapshot-linux`: Phase 1 only provides a raw file / block-device
  `DiskSource` (used for tests and for imaging an unmounted disk). Snapshots
  are Phase 6.
- `cli` (`fenrir-backup`): `repo init`, `repo info`, `key add-recovery`, `backup disk`,
  `backup system` (Windows), `image list|show`, `verify`, `restore disk`.
  `--json` everywhere; documented exit codes.

Out (later phases): recovery environment, bootloader repair, NBD, VMs,
retention/prune, S3/SMB/SFTP, Linux snapshots, agent REST API, UI. Crates for
those exist as empty skeletons so the workspace layout is fixed now.

## Key decisions

1. **Chunking.** Fixed 4 MiB chunks aligned to disk offset 0. Chunk *i* of a
   disk covers bytes `[i*4MiB, min((i+1)*4MiB, disk_size))`. Fixed alignment
   makes restore a pure offset write and makes NBD serving (Phase 3) a single
   lookup per request.
2. **Unused space is zeroed before hashing.** Bytes outside the used-extent
   map are replaced by zeros in the chunk buffer. Stale data in free clusters
   is never stored, and chunks that differ only in free space dedupe.
   A chunk that is entirely zero is not stored at all; the manifest simply
   omits it.
3. **Chunk IDs are keyed hashes.** `id = BLAKE3-keyed(id_key, plaintext)`
   where `id_key` is derived from the repository master key. A plain hash
   would let whoever holds the storage confirm guesses about content (e.g.
   "does this machine contain file X"). Dedup still works across all images
   in a repository because every client shares the master key.
4. **Compress then encrypt.** zstd (default level 3), then
   XChaCha20-Poly1305 with a random 192-bit nonce and the chunk ID bound in as
   associated data, so a chunk cannot be swapped for another one under a
   different name. If compression does not shrink the chunk it is stored
   raw (flagged in the header).
5. **Keys.** A random 256-bit master key. It is stored only wrapped:
   once per passphrase (Argon2id KDF) and once per recovery key (256-bit
   random key in a file the user keeps offline; no KDF needed). Subkeys are
   derived from the master key with BLAKE3 `derive_key` and fixed context
   strings. Nothing secret is ever sent to a storage backend unwrapped.
6. **Manifests are encrypted and signed.** The manifest body is JSON. The
   exact bytes of the body are signed with Ed25519, then the envelope
   `{body, signature}` is compressed and encrypted like a chunk. Signing the
   exact bytes (not a re-serialisation) removes any canonical-JSON
   ambiguity for third-party readers. Each machine has its own signing key;
   the private half is stored in the repository wrapped by the master key so
   that a bare-metal restore needs only the passphrase.
7. **Storage writes are create-only.** `Backend::put` fails if the object
   exists. Chunks are content-addressed so a collision means "already
   stored", which makes interrupted backups resumable for free: rerun and
   every chunk already written is skipped. Manifests are written last, so a
   killed backup never leaves a manifest pointing to missing chunks. This is
   also the shape the Phase 4 append-only server mode needs.
8. **Partition table byte-exact.** The sectors holding the partition table
   (MBR sector 0; for GPT also LBA 1, the entry array, the backup entry
   array and backup header; for MBR the EBR chain) are always included in the
   used-extent map, so they are inside the chunk data, and are also kept in
   the manifest (base64) for inspection and later resized restores.
9. **ESP, MSR and recovery partitions** are imaged in full (no bitmap
   reduction): they are small and their contents are what make the image boot.
10. **Concurrency.** A reader thread produces chunk buffers; a pool of worker
    threads hashes, compresses, encrypts and stores. A bounded channel keeps
    memory at roughly `(workers + queue) × 4 MiB`. An optional byte-rate
    limit throttles reads.

## Windows system backup flow

1. Find the physical disk(s) backing the system volume
   (`IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`).
2. Read the drive layout (`IOCTL_DISK_GET_DRIVE_LAYOUT_EX`) and geometry
   (`IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`), and the raw partition-table sectors.
3. Map each partition to a volume GUID path (enumerate volumes, compare
   disk extents).
4. Create one VSS snapshot set (backup type FULL, component mode, writers
   included) containing every volume on that disk that VSS supports.
   `GatherWriterMetadata` → `PrepareForBackup` → `DoSnapshotSet` →
   `BackupComplete` after the image is stored (or aborted on error).
5. For a snapshotted NTFS volume: read the bitmap with
   `FSCTL_GET_VOLUME_BITMAP` on the shadow device, clear the clusters of
   `pagefile.sys`, `hiberfil.sys`, `swapfile.sys`, and read used clusters
   from the shadow device.
6. Partitions without a snapshot (MSR, unmounted recovery partitions, ESP
   when not snapshot-capable) are read raw from the physical disk in full.
   They are not written to by Windows during normal operation.
7. A `DiskSource` composes these: reads at a disk offset are routed to the
   shadow device for the partition containing it, otherwise to the physical
   disk.

The physical disk is opened read-only with `FILE_SHARE_READ|FILE_SHARE_WRITE`.
Nothing in the backup path opens any device for writing.

## Restore (Phase 1 subset)

`fenrir-backup restore disk` writes one disk image to a target path (file or block
device). Safety rules, enforced in the engine, not just the CLI:

- The target must be named explicitly; there is no default.
- `--yes` is required, else the CLI exits with code 6 and writes nothing.
- On Linux, the target must not be mounted or be a holder of a mounted
  partition; on Windows, the target disk must not host the system volume.
- The target must be at least the image's disk size (resized restore is
  Phase 2/5).

Bootloader repair, partition resizing and firmware checks are Phase 2.

## Verify levels

- `quick`: the manifest decrypts and its signature verifies; every
  referenced chunk object exists.
- `sample=N%`: quick, plus a random N% of referenced chunks are fetched,
  decrypted and re-hashed.
- `full`: every referenced chunk is fetched, decrypted and re-hashed.

Failures name the chunk and the images that reference it; exit code 3.

## Tests written first

- core-format: chunk round-trip, tamper detection (header, ciphertext, ID
  swap), wrong key, key wrap/unwrap with passphrase and recovery key,
  manifest sign/verify and tamper, GPT/MBR parse, local backend
  create-only semantics.
- engine: synthetic GPT disk (ESP + data partition with a sparse used map):
  backup → restore → byte compare of used regions; second backup after
  modifying one block uploads exactly one new chunk; free-space garbage is
  not stored; corrupted chunk is detected by `full` verify; backend that
  fails mid-backup → rerun completes and dedups; restore refuses without
  confirmation and refuses a too-small target.
- cli: end-to-end through the binary with `--json`, exit codes.

Windows VSS code is compile-checked in CI for `x86_64-pc-windows-msvc` and
exercised by the Windows VM integration job (see `docs/TESTING.md`).
