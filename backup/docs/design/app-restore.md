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
   Shell: bring the files to a clean shutdown with `eseutil /r`, mount them
   as a recovery database, list mailboxes, and restore one with
   `New-MailboxRestoreRequest` (to its own mailbox or a folder of another).
   Steps that change mailboxes are left commented for the administrator to
   fill in.

## 3. Security

Needs the scripts permission and the repository unlocked; refused for
backups with malware found unless acknowledged; audited
(`backup.restore.application`, with the component and attach name).

## 4. Tests

* `snapshot-win::apps`: a top-level component carries its subcomponents'
  file sets.
* Agent: file sets placed on the deepest mount point; patterns, case and
  subfolders; T-SQL and scripts quote names and paths (an injected name stays
  inside brackets; the SQL is not spliced into PowerShell); service account
  names; writer recognition.
* `cloud/tests/test_device_backup.py`: file-set counts kept per component;
  older images, unknown components, relative folders, bad instance names and
  attaching an Exchange database refused; the job carries what was asked.
