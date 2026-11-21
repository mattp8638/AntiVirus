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
| Backup API, scheduling, retention, alerts | `cloud/fenrir_cloud` | Being ported from the standalone Rust server |
| Console pages | `console/src/pages/backup` | Being ported |
| Agent installation from Fenrir agents | `agent/`, RMM deployment | Planned |
| NAS repository gateway (relay through Fenrir Cloud, or direct) | | Planned |

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
Rust dependency and its licence. Deployment notes in `docs/DEPLOY.md` and
`docs/DEPLOYMENT-TEST-PLAN.md` still describe the standalone server and
will be rewritten for the integrated module.
