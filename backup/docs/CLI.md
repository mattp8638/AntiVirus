# `fenrir-backup` command-line reference

```text
fenrir-backup [--json] [--repo PATH] [--passphrase-file FILE | --recovery-key FILE] <command>
```

| Option | Meaning |
|---|---|
| `--json` | Print exactly one JSON document on stdout. Progress and messages go to stderr. |
| `--repo PATH` | Repository path. Also `FENRIR_REPO`. |
| `--passphrase-file FILE` | Read the passphrase from the first line of FILE. Otherwise `FENRIR_PASSPHRASE`, otherwise an interactive prompt. |
| `--recovery-key FILE` | Unlock with a recovery key file instead of a passphrase. |

## Commands

| Command | What it does |
|---|---|
| `repo init --recovery-key-out FILE [--chunk-size-kib 4096] [--zstd-level 3]` | Create an encrypted repository in an empty or new directory, and write a recovery key to FILE (mode 0600; never overwrites). |
| `repo info` | Parameters, image and chunk counts, stored bytes. |
| `key add-passphrase` | Add a passphrase (from `FENRIR_NEW_PASSPHRASE` or prompt). |
| `key add-recovery --out FILE` | Create another recovery key. |
| `backup system [--include-disk N]... [--vss-full] [--label L] [--rate-limit-mib N] [--workers N] [--dry-run]` | Windows: application-consistent image of the system disk through VSS. |
| `backup disk PATH... [--allow-inconsistent] [--machine-id ID] [--label L] [--dry-run]` | Image block devices or raw image files that are not in use. |
| `image list` | All images, oldest first. |
| `image show ID` | Full manifest of one image (ID or unique prefix). |
| `verify [--image ID]... [--sample PCT \| --full] [--workers N]` | Quick (manifests + chunk presence), sampled or full re-hash. |
| `restore disk --image ID [--disk N] --target PATH --yes [--no-zero-fill]` | Write one disk of an image to a device or file. |

### Safety

* `restore` overwrites its target and does nothing without `--yes`
  (exit code 6). The target must be named explicitly.
* A Linux block device that is mounted, used as swap, or held by
  device-mapper/md is refused (exit code 7). On Windows, restoring to a
  physical disk from the running system is refused; use the recovery
  environment (Phase 2).
* `backup disk` refuses a mounted device unless `--allow-inconsistent`, and
  then marks the image `inconsistent`.
* `--dry-run` never writes anything and needs no repository.

### VSS backup type

`backup system` uses the VSS **COPY** backup type by default, so application
writers (SQL Server, Exchange) keep their own log chains. `--vss-full` uses
**FULL**, which lets those writers truncate logs after a successful backup;
only use it if Fenrir-Backup is the application's backup of record.

## Exit codes

Stable; scripts and RMM tools can rely on them.

| Code | Name | Meaning |
|---|---|---|
| 0 | `ok` | Success. |
| 1 | `error` | Unclassified failure. |
| 2 | `usage` | Bad arguments or missing configuration. |
| 3 | `verify_failed` | Missing or corrupt data found, or data failed authentication. |
| 4 | `key_error` | Wrong or missing passphrase / recovery key. |
| 5 | `not_found` | Repository or image not found. |
| 6 | `confirmation_required` | Destructive operation needs `--yes`. Nothing changed. |
| 7 | `safety` | Refused by a safety check. Nothing changed. |
| 8 | `cancelled` | Cancelled. |
| 9 | `busy` | Another process holds the repository (a prune is running, or a backup is running when you prune). Retry later. |
| 10 | `ok_with_warnings` | Succeeded with warnings (e.g. a VSS writer failed, so that application's data is crash-consistent only). |

## JSON output

Success:

```json
{ "ok": true, "result": { ... }, "warnings": [ ... ] }
```

Failure:

```json
{ "ok": false, "error": { "kind": "key_error", "message": "..." }, "exit_code": 4 }
```

`verify` with problems returns `"ok": false` with the full report in
`result` and exit code 3.

## Scheduling before the agent exists

Until the agent (Phase 7) ships, schedule the CLI with the OS:

* Windows Task Scheduler, run as SYSTEM with highest privileges:
  `fenrir-backup.exe --json --repo E:\Backups --passphrase-file C:\ProgramData\Fenrir-Backup\pass.txt backup system`
  (protect the passphrase file with an ACL granting only SYSTEM and
  Administrators).
* Linux systemd timer for `fenrir-backup backup disk` of unmounted disks.
