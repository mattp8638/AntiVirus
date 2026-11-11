# Fenrir

Fenrir is a free, self-hosted platform for MSPs and IT teams: RMM (monitoring, scripts, patching, software, remote
access), endpoint protection, vulnerability management, Microsoft 365 administration and a service desk, in one server
you run yourself. There are no per-device fees and no outside service it depends on.

!!! warning "No support"
    Fenrir is given away as it is, with no support, maintenance commitment or warranty. Read the
    [security policy](https://github.com/Palmertech-Webdev/fenrir-security/blob/main/SECURITY.md) before relying on it. If the
    repository is archived, fork it and carry on.

## Install in one command

On a fresh Ubuntu or Debian server (2 GB memory, 15 GB free disk) with a DNS record pointing at it:

```bash
git clone https://github.com/Palmertech-Webdev/fenrir-security /opt/fenrir && cd /opt/fenrir
sudo deploy/install.sh --domain rmm.example.com --email you@example.com --company "Your Company"
```

In 10-15 minutes it installs Docker, writes new secrets, makes your own free code-signing certificate, sets up HTTPS with
Let's Encrypt, builds and starts the server, schedules backups and updates, and runs the go-live check. Open TCP 80 and
443, and UDP 3478 for direct remote sessions.

The full manual setup, upgrades, backup and troubleshooting are in the
[README](https://github.com/Palmertech-Webdev/fenrir-security#readme).

## Where to go next

| You want to | Read |
|---|---|
| Move devices over from Itarian, Level or another RMM | [Migrating to Fenrir](MIGRATING.md) |
| Push the agent with the RMM, Group Policy or Intune you already have | [Deploy from your RMM](DEPLOY_FROM_YOUR_RMM.md) |
| Put Macs on it without an Apple Developer account | [macOS without notarisation](MACOS_INSTALL.md) |
| Sign Windows installers for free | [Code signing](CODE_SIGNING.md) |
| Keep the server up to date | [Automatic updates](AUTO_UPDATE.md) |
| Back up and restore | [Backup and restore](BACKUP_AND_RESTORE.md) |
| Go live safely | [Go-live checklist](GO_LIVE.md) |
| Show only RMM, protection and patching at first | [Modules and the Essentials layout](MSP_MODULES.md) |
| Understand remote sessions (relay and direct) | [Remote protocol](REMOTE_PROTOCOL.md) |

## Community catalogue

Apps to deploy and keep updated, and scripts for the library, are plain files in the repository's `catalogue/` folder,
reviewed in pull requests. See the
[catalogue README](https://github.com/Palmertech-Webdev/fenrir-security/blob/main/catalogue/README.md) to add one.
