# Design note: off-site copies (repository to repository)

Status: implemented.

## 1. What it does

Images are copied from one repository to another: a local NAS to S3 or
Azure, one site to another. It replaces copying repository files with a
generic sync tool, which cannot work: each repository has its own keys
(chunk IDs are keyed hashes, chunks and manifests are encrypted with keys
from the repository's own master key), so another repository's objects are
unreadable there.

The machine doing the copy holds access to both repositories, sealed to it
as for any job. For each image the destination does not have:

1. Each chunk is read and decrypted from the source (its hash is checked),
   its ID is computed with the destination's key, and it is encrypted and
   stored there unless already present (deduplication across images).
2. The manifest is rebuilt for the destination (repository ID, chunk IDs)
   and signed with the destination's key for that machine.
3. The copied images are verified in the destination: manifests open and
   their signatures check, every chunk is present (a full verify re-reads
   and re-hashes every chunk).

Nothing leaves the machine unencrypted; the server only queues the job.

## 2. Image IDs

A copy has its own image ID in the destination, derived from the
destination's repository ID and the source image ID (BLAKE3 derive-key,
RFC 9562 version 8). The same image always gets the same ID in a given
destination, so a later run sees it is already there, and the chain of
parents is kept (copied oldest first). Two repositories never hold the same
image ID, which keeps the catalogue unambiguous. An image whose parent is
not in the destination stands alone there (marked full).

Both repositories must use the same chunk size (chunk indexes are offsets).

## 3. Where

* Plans: "Off-site copy" names a second repository; after each successful
  backup the server queues a copy of the new images on the same machine,
  before retention. The machine needs access to both.
* API: `POST /api/repositories/{id}/copy` (`agent_id`,
  `target_repository_id`, optional `images`, `full_verify`).
* CLI: `fenrir-backup copy --to REPO [--image ID]... [--full-verify]`, with
  the destination's passphrase in `--to-passphrase-file` or
  `FENRIR_TO_PASSPHRASE`.
* Fenrir Cloud: the same plan option and job.

## 4. Tests

* Engine: two backups copied, oldest first with their own IDs and the chain
  kept, shared chunks written once, verified; the copy restores to the same
  bytes as the source; the destination's chunk objects are all different
  from the source's; a second run copies nothing; one image into a third
  repository stands alone; a repository cannot copy into itself.
* Server: a plan with an off-site copy queues the copy after its backup,
  with both repositories' access; copies are listed in the destination;
  copy now; the plan's copy can be turned off; a plan cannot copy into its
  own repository.
* CLI: copy with the destination's own passphrase, then restore from it.

## Offline media rotation

For copies kept away from the network (an air gap), several removable drives are rotated: one is attached to the
machine that makes the copies while the others are stored off-site. Each drive is a repository of its own (its
own passphrase and recovery key) and all of them are given the same **offline media set** name (Repositories ›
Offline media set). A plan's off-site copy pointing at any drive of the set then goes to whichever drive is
attached: the server sends the other drives as alternatives and the agent uses the first that opens. A drive
receives every backup it does not have yet, not only the latest, since it may have been away for weeks. The copies
are listed under the drive that received them. When no drive of the set has had a copy for 8 days, an alert asks
for the next drive of the rotation to be attached; when no drive is attached at all the copy job says so.
