# eDiscovery over backups

Status: implemented in the agent (`crates/agent/src/export.rs`, `download.rs`), Fenrir Cloud
(`fenrir_cloud/backup_cases.py`) and the standalone server (`crates/server/src/cases.rs`).

## What a case is

A case names **custodians**: machines (all their image and folder backups) and cloud-service tenants, optionally
narrowed to some of the tenant's accounts (mailboxes, users, sites). While the case is open:

* every current backup of a custodian is on **legal hold** (retention on the agent never deletes it), and with
  "hold later backups" each new backup of a custodian is held as it is recorded;
* **searches** run on machines with access to the backups, over the file catalogues and SaaS indexes they keep; the
  matches are kept with the case (up to 5,000 per search), so they stay after the search jobs are purged;
* **exports** are made on such a machine and encrypted for the requesting browser's one-time key, as file downloads
  are (`file-download.md`): the server relays ciphertext and never sees the items.

Closing a case (password check) releases the holds it placed. A hold placed by hand on the same backup, or by another
open case, stays: an image's `legal_hold` records the cases holding it (`cases`) and whether anything else does
(`caseOnly`).

## Exports and their manifest

* Files from image and folder backups: `DownloadFiles` with `manifest: true`.
* Items of SaaS backups: `ExportSaas { image_id, accounts, kinds, items, recipient }`. Mail is written as `.eml`
  (the message as the service returned it), files as themselves, records, Teams messages and directory objects as
  JSON, under `account/kind/path`. Each item is read with `saas::store::read_item`, which checks its bytes against the
  BLAKE3 hash recorded at backup time; an item that fails is listed under `failed`, not exported.

Both put `fenrir-manifest.json` at the root of the archive:

```json
{ "format": "fenrir-ediscovery-manifest", "version": 1, "generated_unix": 0, "agent_version": "", "host": "",
  "source": { "image_id": "", "...": "" },
  "entries": [ { "file": "ann@contoso.com/mail/Inbox/Budget.eml", "size": 0, "sha256": "", "blake3": "",
                 "account": "", "kind": "", "id": "", "path": "", "modified": "", "meta": {} } ] }
```

The job result carries the manifest's SHA-256 and entry count.

## Chain of custody

For each export the server records who asked, when, from which backup and on which machine, the job, the agent's
manifest hash, and the SHA-256 and size of the encrypted stream it relayed. The browser that decrypts the export
reports the SHA-256 of the archive it saved (a "receipt"). The case manifest (`GET .../cases/{id}/manifest`) collects
the case, custodians, held backups, searches, exports with all these hashes, and the case's audit records (each with
its hash-chain value), and ends with the SHA-256 of its own canonical JSON.

What it does not prove: that the archive was not changed after the browser saved it (keep the receipt hash with the
file), or anything about the source system before the backup was taken.
