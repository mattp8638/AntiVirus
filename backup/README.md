# Fenrir device backup

Disk-image backup for the Fenrir Platform: whole-system images of Windows
machines (VSS), Hyper-V VMs (from the host, nothing inside the VMs) and
Linux disks, stored encrypted and deduplicated in a repository on a local
disk or a network share. Developed as Fenrir-Backup and moved here so that
backups are managed from the Fenrir console alongside security and RMM.

**Integration status**

| Part | Where | State |
|---|---|---|
| Format, engine, VSS, Hyper-V, VHDX, boot-from-backup, NBD | `crates/` (Rust) | Moved; tested (`cargo test`) |
| Backup agent (`fenrir-backup-agent`) | `crates/agent` | Moved; talks to the backup API of Fenrir Cloud |
| CLI (`fenrir-backup`) | `crates/cli` | Moved |
| File-level restore (browse NTFS / ext4 inside images) | `crates/filebrowse` | Done; tested with real NTFS and ext4 volumes |
| Backup API, scheduling, retention, alerts | `cloud/fenrir_cloud/backup.py`, `routers/backup*.py` | Done; tested (`tests/test_device_backup.py`) |
| Console pages | `console/src/pages/Backups.tsx`, device page › Backup | Done |
| Agent installation from Fenrir agents | Device page › Backup › Enable backup (`script.run`) | Done |
| All-in-one: bundled in the Fenrir installers | `FenrirSetup.exe` / MSI, RMM scripts, Linux and macOS installers | Done |
| Agent builds in the platform image | `deploy/Dockerfile` (Linux, Windows); CI for macOS | Done |
| NAS repository gateway (relay through Fenrir Cloud, or direct) | | Designed (`docs/DEVICE_BACKUP.md` at the repository root); next |

Repository keys never reach the server: the console encrypts the
repository passphrase (and network share sign-ins) in the browser for each
backup agent's own key.

## Build and test

```bash
cd backup
cargo test --workspace
cargo build --release -p agent -p cli
```

The documents in `docs/` describe the repository format (`FORMAT.md`),
the CLI (`CLI.md`), the design of each phase (`design/`) and the security
practices (`SECURITY-CODE-OF-PRACTICE.md`). `THIRD_PARTY.md` lists every
Rust dependency and its licence. How backup works inside the platform (install, repositories, network
shares, permissions, alerts) is in `../docs/DEVICE_BACKUP.md`.
`docs/DEPLOY.md` and `docs/DEPLOYMENT-TEST-PLAN.md` here describe the
standalone Fenrir-Backup server it came from.
