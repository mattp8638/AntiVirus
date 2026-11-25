# SaaS backup: Microsoft 365, Google Workspace, Salesforce

Mailboxes, cloud drives and CRM records into the same repositories as disk images: encrypted on the machine that
runs the backup, deduplicated, kept by the same retention, immutable on Object Lock storage. Fenrir never holds a
vendor account of its own: each customer connects **their own** app registration, service account or connected
app, and its secret stays with them (on the machine that runs the backup; sealed per machine when managed by a
server, like repository passphrases).

## Storage (`saas::store`)

A SaaS backup is an image (machine `saas:<service>:<tenant>`, OS family `saas`) of two disks:

* **disk 0, the index** (JSON): every item at that time (account, kind, service ID, path, modified, size, BLAKE3
  of its bytes, service details, its chunk IDs), the change cursors for the next backup, warnings;
* **disk 1**: a virtual disk whose chunks are the items' bytes, each item starting on a chunk of its own.

So an item that did not change is the same chunks in every backup and is stored once, each backup restores on its
own (it lists everything), and prune keeps exactly what images list. Unchanged items are not even downloaded: the
service reports what changed since the cursor; the rest is taken from the previous index (and downloaded again if
a prune removed its chunks).

## Microsoft 365 (`saas::m365`)

Setup in the customer's Entra ID: an app registration with a client secret and **application** permissions
`User.Read.All`, `Mail.ReadWrite`, `Files.ReadWrite.All` (admin consent). Fenrir signs in with the client
credentials flow.

* Users: `/users`. Mail: every folder (`mailFolders/delta`), each folder's messages through a Graph **delta**
  query; content as MIME (`messages/{id}/$value`). OneDrive: `drive/root/delta`, files only, with their paths.
* Removed items (`@removed`, `deleted`) drop out of the index; throttling (429/503) is retried after `Retry-After`.
* Restore: files into the user's (or another user's) OneDrive under `Restored <date>/<path>` (upload sessions in
  320 KiB multiples above 4 MB); messages into `Restored <date>/<original folder>` (created as mail folders).
* An error for one user keeps that user's previous items and cursors and is reported; the others continue.

### SharePoint, Teams and Entra ID (opt-in)

Each needs its own application permission, so each is chosen separately (`--sites`, `--teams`, `--directory`;
checkboxes when connecting):

* **SharePoint** (`Sites.ReadWrite.All`): every site (`/sites?search=*`), every document library (drive) of it,
  through the drive's delta query like OneDrive. Items are `site-file`, account = the site's address, path =
  `<library>/<folders>/<name>`. Restore puts files back into the same library under `Restored <date>/`.
* **Teams** (`ChannelMessage.Read.All`; Microsoft approves this permission for each app): every team's channels,
  their messages through the channel delta query and each changed thread's replies, as JSON (`teams-message`,
  account `team:<name>`, path `<channel>/<thread>/<message>`). Files shared in channels are in the team's
  SharePoint site. Microsoft Graph does not allow posting messages back as their original authors, so these are
  kept for export and eDiscovery, not restored into Teams.
* **Entra ID** (`Directory.Read.All`, `Policy.Read.All`): users, groups with their member IDs, applications, service
  principals, directory roles with members, and Conditional Access policies (Entra ID P1), as JSON
  (`directory`, account `directory:<tenant>`), read in full each time. Restore: deleted users, groups,
  applications and service principals from the directory's recycle bin (30 days); after that a group is created
  again with its members that still exist, and a Conditional Access policy is created again **disabled** for
  review. Users cannot be created again as they were (passwords are not backed up); other objects are kept for
  reference and export.

## Google Workspace (`saas::google`)

Setup: a service account with a JSON key and **domain-wide delegation** in the Admin console for
`gmail.readonly`, `drive.readonly`, `admin.directory.user.readonly` (backup) and `gmail.insert`, `gmail.labels`,
`gmail.modify`, `drive` (restore). Fenrir signs an RS256 assertion (with `ring`) per user and scope set.

* Users from the Directory API (as the named administrator), suspended ones skipped.
* Gmail: the first time, every message ID; then the **history** API since the saved history ID (added and deleted
  messages); when Gmail no longer has that history, a full listing (known messages are still not downloaded
  again). Content `format=raw` (MIME).
* Drive: a full listing the first time, then the **changes** API from the saved page token. Folder paths are
  resolved; Google Docs, Sheets, Slides and Drawings are exported as .docx, .xlsx, .pptx and .png; other Google
  formats (Forms, Sites) are skipped with a warning.
* Restore: messages imported (`messages/import`, date from the header) with a `Restored <date>` label; files
  uploaded into a `Restored <date>` folder.

## Salesforce (`saas::salesforce`)

Setup: a connected app with the **client credentials flow** enabled and a run-as user that can see all data. Fenrir
signs in at the org's My Domain URL.

* Objects: the standard core objects and every custom object (or those named). For each, the queryable fields
  (compound address and location fields are left out; their parts are separate fields) through `queryAll`
  (paged), one item per record (its JSON).
* Incremental: records with `SystemModstamp` since the last backup; deletions from the `getDeleted` API (which
  covers about 15 days, so backups must run more often than that).
* Restore: a record that still exists is left alone, or updated with `--overwrite` (updateable fields); a deleted
  one is created again (createable fields, a new ID).

## Commands

```
fenrir-backup saas backup --service m365 --tenant contoso.onmicrosoft.com --client-id ID --secret-file s.txt [--user ...] [--no-mail|--no-files]
fenrir-backup saas backup --service google --tenant example.com --key-file sa.json --admin admin@example.com
fenrir-backup saas backup --service salesforce --tenant acme --domain-url https://acme.my.salesforce.com --client-id ID --secret-file s.txt [--object ...]
fenrir-backup saas list IMAGE [--account ...]
fenrir-backup saas export --image IMAGE --to DIR [--account ...] [--path ...]     (mail .eml, files, records .json)
fenrir-backup saas restore --image IMAGE --account ann@... [--to-account ...] [--kind mail|file|record] [--path ...] <service options>
```

Exported paths are made safe (no `..`, no absolute paths, no characters Windows refuses).

## From the server ("Apps & clusters")

The page connects a tenant or a cluster and picks the machine that runs its backups (any agent: the work is HTTPS
calls, and it reports the `saas` and `kubernetes` capabilities). The secret (client secret, service account key or
token) is sealed **in the browser** to that machine's public key, exactly like a repository passphrase, and stored in
a backup plan (`backup_saas` / `backup_kubernetes` job); the server keeps and forwards only the sealed form, and the
agent opens it for each job and never writes it down. Restores (`restore_saas` / `restore_kubernetes`) run on the same
machine with the plan's sealed secret. Restores that overwrite what is there now (Kubernetes objects replaced,
Salesforce records updated) need the cluster's or tenant's name typed; the server refuses them otherwise.
The backup and restore code is shared by the command line and the agent (`saas::run`, `k8s::repo`).

## Tests

`crates/saas/tests/{m365,google,salesforce}_mock.rs`: each connector against a local mock of the vendor's API: a full
backup, an incremental one in which only the changed or new items are downloaded and removed ones drop out (unchanged
items are the same chunks as before), and restores that send the right requests and bytes. The Google test signs
with a throwaway RSA key. Real tenants cannot be used in CI; the mocks follow the vendors' published API documents.
