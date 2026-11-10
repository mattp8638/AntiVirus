# Community catalogue

Fenrir loads two kinds of files from this folder:

- **Apps** (`apps/*.yml`): software technicians can install and keep up to date from **Software**.
- **Scripts** (`scripts/windows/*.ps1`, `scripts/unix/*.sh`): scripts for the script library.

Each app or script is one small file, so adding one is a one-file pull request.

## Add an app

```yaml
# apps/google-chrome.yml
name: 'Google Chrome'
publisher: 'Google'
category: 'Browsers'
windows:
  winget: 'Google.Chrome'           # the exact winget package ID
macos:                              # optional: leave out for Windows-only apps
  brew: 'google-chrome'             # a Homebrew cask name
detect: '^Google Chrome$'           # a regex matching the program's name in Add/Remove Programs or /Applications
```

- **Find the IDs:** run `winget search <name>` on Windows, or search <https://formulae.brew.sh/cask/> for macOS.
- **CI checks them:** every winget ID and cask is checked against the public winget and Homebrew catalogues.
- **What Fenrir does with it:** installs with `winget install --id <ID> --exact --silent` (or `brew install`), and keeps the app updated with the patch policy's third-party rules.

## Add a script

Start the file with header lines, then the script:

```powershell
# name: Clear Teams cache
# description: Deletes the new Teams client's cache for every user. Teams must be closed.
# category: Applications
# platforms: windows
# timeout: 300
# param: Days | Older than (days) | number | 7 | required
<the script>
```

Script rules:

- **Languages:** Windows scripts are PowerShell 5.1-compatible `.ps1` files. Linux and macOS scripts are POSIX shell `.sh` files: put the `#!/bin/sh` line first, then the header.
- **Parameters:** each `param:` line arrives as a variable: `$Days` in PowerShell, `$Days` in shell.
- **Custom fields:** device custom fields arrive as `FENRIR_CF_<KEY>` environment variables. To set one, print `FENRIR-FIELD key=value`.
- **Say what changes:** a script that changes the device must say so in its description. Most library scripts only read and report.
- **Stay safe:** no downloads from unknown sites, no disabling security features silently, no secrets in the file.

## The manifest

`MANIFEST.sha256` holds a checksum for every file. After adding or changing a file, run:

```bash
python3 catalogue/manifest.py --write
```

Commit the manifest with your change.

- **CI** fails when the manifest doesn't match.
- **The server** loads only files whose checksum matches, so a file edited on a server without review is ignored (with a warning in the log).
- **Upgrades** add new apps and scripts but never change or remove ones already in a server's library.
