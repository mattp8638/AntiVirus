# Fenrir-Backup repository format, version 1

This document specifies the repository format completely, so that anyone can
write a compatible reader. The reference implementation is the `core-format`
crate; `fenrir-reader` (in that crate) is a small read-only reader built on it.

Conventions: integers in binary structures are little-endian. "JSON" means
UTF-8 JSON (RFC 8259). Binary fields inside JSON are standard base64 with
padding (RFC 4648 §4). UUIDs are lowercase hyphenated text. Hex is lowercase.

## 1. Layout

A repository is a set of objects addressed by slash-separated keys. On a
local filesystem each key is a relative path under the repository root.

| Key | Content | Encrypted |
|---|---|---|
| `config.json` | Repository parameters (§2) | No |
| `keys/<slot-uuid>.json` | Master key wrapped by a passphrase or recovery key (§3) | Wrapped key only |
| `signers/<key-id>.json` | Manifest signing key record (§6) | Secret half |
| `chunks/<aa>/<id>` | Chunk object (§4); `<id>` is 64 hex chars, `<aa>` its first two | Yes |
| `manifests/<image-uuid>` | Image manifest object (§5) | Yes |
| `locks/<id>.<seq>.json` | Repository locks (§8) | No |
| `tmp/` | Writer scratch space; readers ignore it | — |

Keys match `[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*` and never contain `.` or `..`
segments. Objects are immutable: writers create them once and never modify
them. A key that exists is complete (writers publish atomically).

A repository is valid once `config.json` exists; writers create key slots
before `config.json`.

## 2. `config.json`

```json
{
  "format": "fenrir-repository",
  "version": 1,
  "repo_id": "3f0c...-uuid",
  "created": "2026-11-20T10:00:00Z",
  "chunk_size": 4194304,
  "zstd_level": 3,
  "hash": "blake3-keyed",
  "encryption": "xchacha20poly1305"
}
```

* `chunk_size`: power of two, 65 536 ≤ n ≤ 67 108 864. Fixed for the life of
  the repository.
* `zstd_level`: level writers use; readers do not need it.
* Readers must reject `format` ≠ `fenrir-repository` and any `version`
  they do not know.

`config.json` is not authenticated. Everything a reader relies on is
re-checked: chunk size is repeated inside each signed manifest.

## 3. Keys

### 3.1 Master key and subkeys

The master key `MK` is 32 random bytes. It is only ever stored wrapped.
Subkeys are derived with BLAKE3 in key-derivation mode
(`blake3::derive_key(context, MK)`, BLAKE3 spec §2.5):

| Name | Context string (exact bytes) | Use |
|---|---|---|
| `K_id` | `Fenrir-Backup 2026 v1 chunk id` | Keyed hash for chunk IDs |
| `K_chunk` | `Fenrir-Backup 2026 v1 chunk encryption` | Chunk AEAD key |
| `K_manifest` | `Fenrir-Backup 2026 v1 manifest encryption` | Manifest AEAD key |
| `K_signer` | `Fenrir-Backup 2026 v1 signer key wrap` | Signer secret AEAD key |

### 3.2 AEAD

All encryption is XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03): 32-byte key,
24-byte random nonce, 16-byte tag appended to the ciphertext.

### 3.3 Key slots: `keys/<slot-uuid>.json`

```json
{
  "format": "fenrir-key-slot",
  "version": 1,
  "slot_id": "uuid (equals the file name)",
  "kind": "passphrase" | "recovery",
  "kdf": { "alg": "argon2id", "m_cost_kib": 65536, "t_cost": 3, "p_cost": 1, "salt": "base64(16 bytes)" },
  "nonce": "base64(24 bytes)",
  "wrapped": "base64(ciphertext||tag of MK)"
}
```

`kdf` is present for passphrase slots only.

Associated data for the wrap:

```
AAD = "fenrir-key-slot-v1" || repo_id (16 bytes, RFC 4122 byte order)
      || slot_id (16 bytes) || kind_byte      ; kind_byte: 1 = passphrase, 2 = recovery
```

* Passphrase slot: `KEK = Argon2id(password = UTF-8 passphrase, salt,
  m_cost_kib, t_cost, p_cost, version 0x13, output 32 bytes)`.
  Readers must bound the parameters before running the KDF
  (reference: 8 ≤ m ≤ 4 194 304 KiB, 1 ≤ t ≤ 100, 1 ≤ p ≤ 64).
* Recovery slot: `KEK` = the 32-byte key in the recovery key file.

`MK = XChaCha20-Poly1305-Open(KEK, nonce, AAD, wrapped)`. Authentication
failure means a wrong passphrase or key. To unlock with a passphrase, try
every passphrase slot.

### 3.4 Recovery key file

Kept by the user, never in the repository:

```json
{ "format": "fenrir-recovery-key", "version": 1,
  "repo_id": "uuid", "slot_id": "uuid", "key": "base64(32 bytes)" }
```

## 4. Chunks

A disk is divided into chunks of `chunk_size` bytes aligned to disk offset 0:
chunk *i* covers `[i·cs, min((i+1)·cs, disk_size))`. The last chunk of a
disk may be shorter.

**Plaintext.** Bytes of the chunk range that lie outside the image's
`used_extents` (§5.3) are replaced with zeros before hashing. An all-zero
chunk is never stored; it is simply absent from the manifest's chunk list.

**ID.** `id = BLAKE3-keyed(K_id, plaintext)`, 32 bytes, written as 64 hex
characters. Keyed hashing stops the storage provider from confirming guesses
about content; dedup works across all images in a repository.

**Object** (`chunks/<aa>/<id>`), the *sealed object container*:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Magic `FNRC` (`46 4E 52 43`) |
| 4 | 1 | Container version = 1 |
| 5 | 1 | Flags: bit 0 = payload is zstd-compressed; other bits 0 |
| 6 | 2 | Reserved = 0 |
| 8 | 4 | Plaintext length (u32) |
| 12 | 24 | Nonce |
| 36 | … | Ciphertext ‖ 16-byte tag |

```
AAD     = header bytes [0, 36) || id (32 raw bytes)
payload = XChaCha20-Poly1305-Open(K_chunk, nonce, AAD, ciphertext||tag)
plain   = flags.bit0 ? zstd_decompress(payload) : payload    ; RFC 8878 frame
```

A reader must check, in order: magic, version, flags and reserved bytes,
plaintext length ≤ 256 MiB, AEAD authentication, decompressed length equals
the declared length, and `BLAKE3-keyed(K_id, plain) == id`. Any failure is
corruption or tampering. Decompress only after authentication, and bound
decompression by the declared length.

## 5. Manifests

### 5.1 Object

`manifests/<image-uuid>` is a sealed object container exactly as in §4 with
magic `FNRM`, key `K_manifest`, and the 16 bytes of the image UUID (RFC 4122
order) in place of the chunk ID in the AAD. Its plaintext is the envelope.

### 5.2 Envelope

```json
{
  "format": "fenrir-manifest-envelope",
  "version": 1,
  "signer": "32 hex chars: key id",
  "signature": "base64(64-byte Ed25519 signature)",
  "body": "<the manifest body, a JSON document, as a string>"
}
```

The signature is Ed25519 (RFC 8032) over the UTF-8 bytes of the `body`
string exactly as stored. Verify before parsing `body`. Then parse `body`
and check that its `image_id` equals the object's name and its `repo_id`
equals the repository's.

### 5.3 Body

```json
{
  "format": "fenrir-image-manifest",
  "version": 1,
  "image_id": "uuid",
  "repo_id": "uuid",
  "created": "2026-11-20T10:00:00Z",
  "created_unix": 1795600000,
  "kind": "full" | "incremental",
  "parent": "uuid (optional)",
  "label": "string (optional)",
  "machine": { "machine_id": "string", "hostname": "string" },
  "consistency": "application" | "crash" | "offline" | "inconsistent",
  "chunk_size": 4194304,
  "hash": "blake3-keyed",
  "compression": "zstd",
  "encryption": "xchacha20poly1305",
  "disks": [ DiskImage, ... ],
  "boot": BootConfig,
  "os": { "family": "windows|linux|unknown", "name": "", "version": "", "build": "", "arch": "" },
  "drivers": [ { "name": "", "provider": "", "version": "", "class": "", "inf": "" } ],
  "excluded": [ { "path": "C:\\pagefile.sys", "bytes": 4294967296 } ],
  "warnings": [ "string" ],
  "stats": { "bytes_read": 0, "chunks_total": 0, "chunks_new": 0, "bytes_new_stored": 0, "duration_ms": 0 },
  "vm": VmInfo (optional)
}
```

**VmInfo** (present when a VM was imaged from its host; one image disk per
virtual disk, in the same order as `vm.disks`):

```json
{
  "hypervisor": "hyper-v", "host": "HV01", "vm_id": "uuid", "name": "SQL-PROD",
  "generation": 2, "cpu_count": 4, "memory_mb": 8192, "secure_boot": true,
  "disks": [ { "controller": "SCSI 0:0", "path": "D:\\VMs\\sql.vhdx" } ],
  "network_adapters": [ { "name": "Network Adapter", "switch": "LAN", "mac": "00155D010203" } ],
  "config_version": "10.0"
}
```

The machine ID of a VM image is `hyperv-vm:<VM GUID>`.

`incremental` images share chunks with earlier images but are still
self-contained: they list every chunk they need. `parent` records lineage
only. Readers must ignore unknown fields.

**DiskImage**

```json
{
  "index": 0,
  "size": 512110190592,
  "logical_sector_size": 512,
  "physical_sector_size": 4096,
  "model": "", "serial": "", "device": "\\\\.\\PhysicalDrive0",
  "partition_table": PartitionTable,
  "partitions": [ PartitionRecord, ... ],
  "used_extents": [ [offset, length], ... ],
  "chunks": [ [index, "64 hex id"], ... ]
}
```

* `used_extents`: sorted, non-overlapping, non-adjacent byte ranges that were
  read from the source. Everything else restores as zero.
* `chunks`: strictly increasing `index`; each `index < ceil(size / chunk_size)`.
  A missing index is an all-zero chunk.

To reconstruct a disk: create a `size`-byte zero-filled output; for each
`[index, id]`, decode the chunk and write it at `index · chunk_size`.

**PartitionTable**

```json
{
  "scheme": "gpt" | "mbr" | "none",
  "sector_size": 512,
  "disk_guid": "uuid (GPT)",
  "mbr_signature": 305419896,
  "first_usable_lba": 34, "last_usable_lba": 1000215182,
  "backup_table_valid": true,
  "partitions": [ PartitionEntry, ... ],
  "raw_regions": [ { "offset": 0, "data": "base64" }, ... ]
}
```

`raw_regions` are the exact sectors holding the table: for GPT the protective
MBR, primary header, primary entry array, backup entry array and backup
header; for MBR sector 0 and every EBR. They are also inside `used_extents`,
so the chunk data alone restores the table byte-exact.

**PartitionEntry** (also the first fields of PartitionRecord)

```json
{
  "number": 1, "start": 1048576, "length": 104857600,
  "type_guid": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
  "unique_guid": "uuid", "mbr_type": 7,
  "name": "EFI system partition", "attributes": 0, "bootable": false,
  "role": "esp" | "msr" | "recovery" | "bios_boot" | "data" | "swap" | "lvm" | "extended" | "unknown"
}
```

GPT GUIDs are given in their canonical text form (the on-disk mixed-endian
encoding is decoded).

**PartitionRecord** = PartitionEntry fields plus

```json
{
  "filesystem": "ntfs|fat12|fat16|fat32|exfat|ext|xfs|btrfs|swap|luks|bitlocker|lvm_pv|refs|unknown",
  "capture": "snapshot_bitmap" | "snapshot_full" | "raw_full" | "raw_bitmap",
  "captured_bytes": 0,
  "volume": "\\\\?\\Volume{...}\\ (optional)",
  "mount_points": ["C:\\"],
  "encryption": "bitlocker | luks (optional)"
}
```

**BootConfig**

```json
{
  "firmware": "uefi" | "bios" | "unknown",
  "secure_boot": true,
  "uefi_entries": [ { "name": "Boot0001", "description": "Windows Boot Manager", "path": "hex of EFI device path" } ],
  "boot_order": ["Boot0001"],
  "bcd": "path of BCD store (optional)",
  "grub": "optional", "systemd_boot": "optional",
  "notes": []
}
```

## 6. Signer records: `signers/<key-id>.json`

```json
{
  "format": "fenrir-signer", "version": 1,
  "key_id": "32 hex chars",
  "public_key": "base64(32-byte Ed25519 public key)",
  "nonce": "base64(24 bytes)",
  "sealed": "base64(ciphertext||tag)"
}
```

* `key_id = hex(BLAKE3(public_key)[0..16])`.
* `sealed` opens with `K_signer`, AAD = `"fenrir-signer-v1" || repo_id (16 bytes) ||
  public_key (32 bytes)`, to JSON `{ "machine_id": "...", "seed": "base64(32 bytes)" }`.
* A reader must open `sealed` and check that the seed's Ed25519 public key
  equals `public_key`. This authenticates the record with the master key, so
  an attacker who can write to storage cannot plant a signer.

Each machine has its own signer.

## 7. Versioning

Every JSON document carries `format` and `version`; binary containers carry
a version byte. A reader must refuse versions it does not know. New
optional JSON fields may appear in a version; readers ignore unknown fields.

## 8. Locks

Writers coordinate through lock objects so that pruning (deleting chunks
no manifest references) never races with a backup that has decided to
reuse a stored chunk.

```json
{ "kind": "shared" | "exclusive", "hostname": "web01", "pid": 1234, "created": 1795000000, "refreshed": 1795000120 }
```

* Key `locks/<id>.<seq>.json`, `<id>` 32 hex characters, `<seq>` a decimal
  counter. Refreshing writes `<seq + 1>` before deleting `<seq>`; the
  highest sequence of an id is current.
* A lock whose `refreshed` is more than 1800 seconds old is stale.
* Backup, restore, verify and retention ("forget") hold a shared lock;
  prune holds the exclusive lock. Acquire by writing your lock, then
  listing: a shared acquirer backs off if a fresh exclusive lock exists; an
  exclusive acquirer backs off if any other fresh lock exists, and may
  delete stale ones.
* Read-only readers that cannot write a lock may read without one.

A third-party writer must follow this protocol; a read-only reader may
ignore locks.

## 9. Reading checklist

1. Read `config.json`; check format and version.
2. Unwrap `MK` from a key slot (§3); derive subkeys.
3. List `manifests/`; for each, open the container (§5.1), verify the
   envelope signature with the signer record (§6), parse and validate the
   body (§5.3).
4. Rebuild disks from chunks (§4, §5.3), checking every chunk's ID.
