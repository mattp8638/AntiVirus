# Ransomware protection (Windows agent)

The Windows agent's ransomware shield enforces the **Ransomware protection** section of a protection
policy. Code: `agent/windows/service/src/RansomwareShield.cpp` (Windows plumbing) and
`RansomwareDetector.cpp` (decisions, unit tested in `tests/PolicyAndDeviceControlTests.cpp`).

## What it does

| Setting | What the agent does |
| --- | --- |
| `enabled` | Turns the whole shield on or off. |
| `protectedFolders` | Folders to watch. `%USERPROFILE%` means every user profile on the PC (the service runs as SYSTEM). The same folders inside OneDrive (Known Folder Move) are watched too. Default: Documents, Desktop, Pictures. |
| `massEncryptionFilesPerMinute` | One process changing this many different files in protected folders within a minute is a burst. |
| `entropyDetection` | Before acting on a burst, the agent reads the start of up to 8 of the changed files. A burst counts only when most of them look encrypted (near-random bytes, no recognised file format). Office documents, photos, video and archives are recognised, so a sync client downloading files does not trip it. With this off, any burst counts. |
| `mode` | `audit`: report only. `block`: stop the process. `block-and-rollback`: stop it, then restore the changed files from the last snapshot. Programs under `C:\Windows` and the agent's own folder are never stopped, only reported. |
| `canaryFiles` | A hidden `$fenrir-canary-budget-2024.docx` in each protected folder (not in OneDrive folders). Any change is a critical alert, and in block modes the process is stopped. A check every minute also catches changes the watcher missed. Turning the setting off removes the files. |
| `protectedFoldersMode` | `audit`: report unsigned programs (not on the allowed list) that write into protected folders. `block`: stop them. Signed software is trusted, as with Windows Controlled Folder Access. |
| `allowedApps` | File names (`backup.exe`), full paths, or folders ending in `\`. Allowed programs are never counted or reported. |
| `networkShareProtection` | Folders shared over SMB are watched too. Encryption from another computer shows up as writes by the System process and is reported as remote (it cannot be stopped locally; isolate the attacking machine). |
| `rollbackSnapshots`, `snapshotIntervalHours` | A Volume Shadow Copy of each drive holding protected folders, on the interval. Users can also open the snapshots from Explorer's **Previous Versions**. A failed snapshot is retried after an hour. |
| `response.autoRollbackRansomware` | The cloud sends `ransomware.rollback` after a critical ransomware alert. |
| `blockShadowCopyDeletion` | Behaviour rules block `vssadmin delete shadows` and similar commands. |

## How file activity is seen

The shield runs its own real-time ETW session (`FenrirRansomwareShield`) on the
`Microsoft-Windows-Kernel-File` provider, which records the process behind every file open and write. Only
paths inside watched folders are kept. Writes made by the cache manager (paging I/O) are ignored, because
they are not tied to the program that made them. If the session cannot start, the agent sends
`ransomware.shield.degraded`, keeps canaries and snapshots running, and retries every 10 minutes.

## Rollback

The `ransomware.rollback` command (console, or automatically) uses the last recorded incident on the
device:

* It works only within 24 hours of the incident and only once per incident, so an old snapshot is never put
  back over recent work.
* For each changed file it restores the copy from the newest snapshot taken before the attack. A changed
  file is kept as `<name>.fenrir-pre-restore`.
* Renamed copies (`report.docx.locked`) are matched to their original name.
* Files that existed in the snapshot but are now missing from the affected folders are restored too.

## Telemetry and alerts

| Event | Cloud alert |
| --- | --- |
| `ransomware.detected`, `ransomware.blocked` | Agent ransomware shield verdict (critical, T1486) |
| `ransomware.canary.touched` | Ransomware canary file touched (critical) |
| `ransomware.protected_folder.write` / `.blocked` | Unapproved program wrote to a protected folder (medium) |
| `ransomware.restore.completed` / `.failed` | Stored as events; counts are in the payload |
| `ransomware.snapshot.created` / `.failed`, `ransomware.shield.*` | Stored as events |

Detections wake the agent's main loop, so they reach the cloud straight away rather than at the next sync.
