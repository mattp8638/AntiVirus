# Platform backup and restore

These scripts back up and restore the Fenrir server itself (CORE-09). Backing up customers' endpoints and SaaS data is a separate area (BDR).

## What a backup contains

`deploy/backup.sh [directory]` (default `/var/backups/fenrir`) writes a folder named `fenrir-backup-<UTC time>` containing:

- **`db.dump`:** a PostgreSQL custom-format dump. It is taken in a single transaction, so it is consistent.
- **`artifacts.tar.gz`:** the artifacts volume (evidence files, forensic and support bundles).
- **`releases.tar.gz`:** release manifests signed off the server, if you use them.
- **`manifest.json`:** the SHA-256 and size of every file, the schema version, the git commit, and a fingerprint of the vault key (never the key itself).

## Encryption, retention and off-site copies

Set these in `deploy/.env`; `install.sh` sets a passphrase for new servers.

| Setting | What it does |
|---|---|
| `FENRIR_BACKUP_PASSPHRASE` (or `FENRIR_BACKUP_PASSPHRASE_FILE`) | The backup becomes a single encrypted file, `fenrir-backup-<UTC time>.tar.enc` (AES-256, key from the passphrase with PBKDF2, 600,000 rounds), with a `.sha256` beside it. No unencrypted copy is left. Keep the passphrase offline with `.env`: without it the backup cannot be read. |
| `FENRIR_BACKUP_KEEP_DAYS` | Backups older than this are deleted after each run (default 14; `0` keeps them all). |
| `FENRIR_BACKUP_RCLONE_REMOTE` | Each backup is also copied off the server with [rclone](https://rclone.org), for example `b2:my-bucket/fenrir`. Set the remote up first with `rclone config`. Only encrypted backups are ever copied. |

Without a passphrase, backups are written as before (a folder) and the script warns that they are not encrypted.

Schedule it daily, for example in `crontab -e` as root:

```
17 2 * * * /opt/fenrir/deploy/backup.sh >> /var/log/fenrir-backup.log 2>&1
```

## What it deliberately does not contain

`deploy/.env` and `deploy/signing/` are not in the backup. They hold the database password, `FENRIR_SECRET_KEY`, `FENRIR_VAULT_KEY`, the code-signing certificate and the agent release key. Keep them offline, for example in a password manager or a safe.

Without the same `FENRIR_VAULT_KEY`, stored secrets in a restored database cannot be decrypted: vault credentials, Microsoft 365 connections and MFA seeds. `restore.sh` refuses to continue when the key's fingerprint doesn't match.

## Restoring

```
deploy/restore.sh /var/backups/fenrir/fenrir-backup-20261028T090000Z.tar.enc   # encrypted
deploy/restore.sh /var/backups/fenrir/fenrir-backup-20261028T090000Z           # unencrypted folder
```

An encrypted backup is decrypted with `FENRIR_BACKUP_PASSPHRASE` into a private temporary folder, removed afterwards.

The script works through these steps:

1. Checks every file against the manifest. A damaged or altered backup is refused before anything changes.
2. Checks that the vault key fingerprint matches `deploy/.env`. Use `--allow-different-vault-key` only if you rotated the key and kept the old one in `FENRIR_VAULT_OLD_KEYS`.
3. Asks you to type `RESTORE`, or accepts `--yes` for automation.
4. Stops the API, then recreates the database from the dump.
5. Replaces the artifacts volume.
6. Starts the API again and waits for `/ready`.
7. Checks that the audit chain verifies and that every stored secret still decrypts. It exits non-zero if either check fails.

Commands that had completed before the backup are restored as completed and are not run again. Commands that were still pending are delivered again, with the same reconciliation agents already apply to redelivered commands (see CORE-07).

## Recovery point and testing

The recovery point is the time of the last backup. Schedule `backup.sh` with cron at least daily, with a passphrase and an off-site remote set (above).

CI runs a full drill on every change:

1. Back up.
2. Destroy the devices and tickets tables.
3. Check that a damaged backup is refused.
4. Restore.
5. Compare the row counts for devices, tickets, commands and audit entries.
