# Phase 4 design note: S3 storage with Object Lock

Status: done. Retention, pruning and the ransomware hold came earlier
(`phase-4-deploy.md`). This note adds S3-compatible object storage and
immutable backups with S3 Object Lock.

## 1. Why

A repository on a NAS can be deleted by anyone who gets administrator rights
on a machine that writes to it, or on the NAS. With S3 Object Lock in
**compliance** mode, every object of a backup is immutable until its lock
expires: nobody can delete or overwrite it, including the storage account
owner, ransomware holding the credentials, or Fenrir-Backup itself.
Governance mode is the same except that a principal with
`s3:BypassGovernanceRetention` may remove it.

## 2. Repository location

`s3://<bucket>/<prefix>` plus, stored with the repository on the server (not
secret):

| Setting | Example | Notes |
|---|---|---|
| endpoint | `https://s3.eu-west-2.amazonaws.com`, `https://s3.wasabisys.com`, `https://<account>.r2.cloudflarestorage.com`, `http://minio.lan:9000` | |
| region | `eu-west-2` (`us-east-1` for most S3-compatible services) | |
| path style | on for MinIO and most self-hosted services | `https://host/bucket/key` instead of `https://bucket.host/key` |
| lock mode | `none`, `governance`, `compliance` | must be enabled on the bucket (it needs versioning) |
| lock days | 30 | ≥ 1; see §5 |

The access key and secret are entered in the browser and sealed to each
machine like a share sign-in; the server never sees them. They need
`s3:PutObject`, `GetObject`, `ListBucket`, `DeleteObject`,
`GetObjectRetention`/`PutObjectRetention` (lock), and for `ListBucketVersions`
and `DeleteObjectVersion` for space reclamation. A machine that only backs
up can be given keys without delete permissions at all.

## 3. Backend (`crates/s3store`)

Implements `core_format::backend::Backend` with plain HTTPS (ureq, rustls)
and AWS Signature Version 4 (HMAC-SHA256; checked against AWS's published
example).

* `put`: `PUT` with `If-None-Match: *`, so an existing object is never
  replaced (create-only, as the format requires); `412` → already exists.
  With a lock: `x-amz-object-lock-mode` and
  `x-amz-object-lock-retain-until-date` = now + lock days, and
  `Content-MD5` (required by S3 for locked uploads). Objects under `locks/`
  (repository locks, short-lived) are never locked.
* `get`, `exists` (`HEAD`), `size`: as usual; `404` → not found.
* `list`: `ListObjectsV2`, paginated.
* `delete`: on a locked (versioned) bucket a plain DELETE would only add a
  delete marker and leave the data in place, so the backend deletes the
  object's current version by version id. While its lock lasts S3 refuses
  (`403`), which the backend reports as `Error::Locked`: the caller keeps it
  and tries again after expiry. Without a lock: plain DELETE.
* `extend(key, until)`: `PUT ?retention` for the current version (compliance
  locks can only be extended; S3 refuses shortening).

Network errors and `5xx`/`503 SlowDown` are retried with backoff (4
attempts).

## 4. What is locked

Every object a backup writes: chunks, manifests, key slots, signer records,
`config.json`. Not `locks/`.

## 5. Locks and retention

A chunk written once is reused by later backups for as long as data does not
change, so its lock must keep moving forward while any image uses it:

* Every **maintenance** run (space reclamation, on the repository's
  maintenance machine, weekly by default) extends the lock of every object
  referenced by a kept image, and of the key, signer and config objects, to
  now + lock days. Extending never shortens anything, and an object written
  since the last run already carries a full lock. The server requires the
  lock period to be longer than the maintenance interval, so an object in
  use never reaches the end of its lock. Cost: one request per live object
  per run (a 1 TB repository of 4 MiB chunks is about 250,000 requests).
* **Retention** removes images the policy no longer keeps by deleting their
  manifests. A manifest still locked cannot be deleted: it is kept and the
  job reports "kept until its lock expires"; the next run removes it.
* **Space reclamation** deletes unreferenced chunks the same way: locked
  ones stay until their lock expires.
* The server refuses a retention policy that keeps images for less than
  the lock period (it could never be met), and the UI explains that storage
  use is at least lock days × daily change.

The ransomware hold (anomaly detection) still applies on top.

## 6. Append-only access

Machines that should never delete anything get credentials without delete
permissions, or reach the repository through a NAS gateway (already
append-only for its clients, see the gateway design). With compliance locks
even full credentials cannot remove a locked backup.

## 7. Where

* Fenrir-Backup server and web UI: New repository › S3 / object storage,
  with a "Test connection" that writes, reads, (if locked) checks the lock
  is enforced by trying to delete the test object, then lists.
* CLI: `--repo s3://bucket/prefix` with `FENRIR_S3_ENDPOINT`,
  `FENRIR_S3_REGION`, `FENRIR_S3_PATH_STYLE`, `FENRIR_S3_LOCK=compliance:30`,
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`.
* Fenrir Cloud: the same repository settings in the console.

### Azure Blob Storage

`azure://container/prefix` repositories (crate `azstore`) use the documented
Blob service REST API with the same rules:

* Requests are signed with Shared Key (HMAC-SHA256 with the storage account
  key over the documented canonical string), or carry a SAS token instead.
  The machine's sealed sign-in holds the account name and the key or token.
* Writes are create-only (`If-None-Match: *`).
* Immutability: each new blob gets a version-level immutability policy
  (`x-ms-immutability-policy-until-date`, mode `Locked` for the
  "compliance" setting, `Unlocked` for "governance"). The container needs
  version-level immutability enabled (and the account versioning). Deletes
  name the blob's version, which Azure refuses while it is immutable; the
  maintenance run extends the policies of blobs still in use
  (`comp=immutabilityPolicies`).
* The settings are the object-storage settings above (the endpoint; the
  region is not used); the web UI offers "Azure Blob Storage" as a provider.
* Tests: the Shared Key string to sign follows the documented layout (unit
  test); the backend runs against the Azurite emulator in CI (which checks
  Shared Key signatures, but does not implement immutability policies).

## 8. Tests

* SigV4 against the AWS documentation example (GET with Range).
* The backend against an S3 emulator (moto) in unit tests: create-only
  puts, list pagination, lock headers, delete refused while locked,
  extend.
* CI: a real MinIO server with an Object Lock bucket: a backup, verify,
  retention and prune with compliance locks; deletion refused before
  expiry, allowed after.
