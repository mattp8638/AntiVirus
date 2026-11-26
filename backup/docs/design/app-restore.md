# Design note: restoring one SQL Server or Exchange database

Status: implemented (agent `apprestore.rs`; file sets recorded by
`snapshot-win`). Not yet exercised against a live SQL Server or Exchange
server.

Application-aware Windows images (`app-aware.md`) coordinate SQL Server and
Exchange with VSS, so their database files are consistent in the image. Until
now they could only be restored with the whole volume.

## 1. What the image records

For every VSS writer component it reports, the image now lists the file
sets the application gave for it and its subcomponents
(`ApplicationInfo.files`: folder, name pattern, subfolders or not, and
whether they are database, log or other files). Older images have no list;
their databases are restored with the volume as before. The field is
optional in the manifest, so older agents read new images and the reverse.

## 2. Restore

`RestoreApplication` (Windows agents that report `restore_apps`):

1. Each file set is placed on a volume of the image by the deepest mount
   point holding its folder (`C:\`, or a volume mounted in a folder), and its
   files are found by pattern (ignoring case, in subfolders when the set says
   so).
2. They are copied out of the image (`filebrowse`, nothing mounted) into a
   new folder `<chosen folder>\<database>`; existing content is never
   overwritten.
3. SQL Server: an `attach-<name>.sql` script is always written. When asked,
   the agent gives the instance's service account (`NT SERVICE\MSSQLSERVER`
   or `NT SERVICE\MSSQL$<instance>`) access to the folder and attaches the
   files as a **new** database under the chosen name, with Windows sign-in;
   the live database is not touched. Names and paths are quoted (`[...]`,
   `N'...'`) and passed to PowerShell base64-encoded. If attaching fails
   (the agent's Local System account is often not a SQL Server
   administrator), the job says so and the script stays for an
   administrator.
4. Exchange: a `recover-<database>.ps1` script for the Exchange Management
   Shell is always written: bring the files to a clean shutdown with
   `eseutil /r`, mount them as a recovery database, list mailboxes, and
   restore one with `New-MailboxRestoreRequest`.
5. Exchange, one mailbox unattended (optional `mailbox: {source, target,
   folder}`): the agent, on an Exchange Mailbox server, loads the Exchange
   snap-in (or the remote shell), finds the log base name (`E00`..`E99`) from
   the restored logs, replays them with `eseutil /r ... /i` and refuses to go
   on unless `eseutil /mh` reads Clean Shutdown. It then creates a recovery
   database (`Recovery-<database>-<image>`, refused if one exists), mounts it,
   finds the source mailbox by display name or mailbox GUID (more than one
   match is refused, naming them), and starts `New-MailboxRestoreRequest`
   into the target mailbox, under the chosen folder (blank: the original
   folders). It waits up to 24 hours for Completed, CompletedWithWarning or
   Failed, then always removes the request and dismounts and removes the
   recovery database. Every name reaches PowerShell base64-encoded. The
   outcome (state, items and bytes moved, the mailboxes in the backup, the
   failed step and error) is a `exchange-mailbox-restore` check in the
   restore evidence (`restore-evidence.md`); a failed restore fails the job
   and the evidence is not verified. Writing into a live mailbox needs the
   target typed again (UI and API `confirm`); the agent's account needs the
   Mailbox Import Export role.

## 3. Security

Needs the scripts permission and the repository unlocked; refused for
backups with malware found unless acknowledged; audited
(`backup.restore.application`, with the component and attach name, and the
source and target mailbox).

## 4. Tests

* `snapshot-win::apps`: a top-level component carries its subcomponents'
  file sets.
* Agent: file sets placed on the deepest mount point; patterns, case and
  subfolders; T-SQL and scripts quote names and paths (an injected name stays
  inside brackets; the SQL is not spliced into PowerShell); service account
  names; writer recognition; the mailbox script never splices a name
  (an injected mailbox name only appears base64-encoded), cleans up in
  `finally`, and its JSON result parses; the log base name is found and two
  databases' logs are refused; requests are checked.
* Server: a mailbox restore needs an Exchange component, both mailboxes on
  one line and the target typed again.
* Not yet run against a live Exchange server: CI has no Exchange (it needs
  a domain controller and hours of setup).
* `cloud/tests/test_device_backup.py`: file-set counts kept per component;
  older images, unknown components, relative folders, bad instance names and
  attaching an Exchange database refused; the job carries what was asked.
