# Installing on macOS without notarisation

Fenrir's macOS agent is installed by a shell script, not a `.pkg` or an app. That is deliberate: Apple notarisation
needs a paid Apple Developer account, and this project costs nothing to run. This page explains why the script works
without one, what you give up, and how to roll it out.

## Why it works

- **No Gatekeeper prompt.** Gatekeeper checks files carrying the `com.apple.quarantine` flag, which browsers and Mail
  add to downloads. A script fetched with `curl` (or pushed by your RMM/MDM) and run with `sudo` never gets that flag,
  and the installer clears it from the agent binary anyway.
- **Apple Silicon runs it.** Macs with M-series chips refuse arm64 code that has no signature at all. Go's linker gives
  the agent an ad-hoc signature, and CI checks the binary shipped in every server image still has it
  (`scripts/ci/check_macho_signature.py`). Intel Macs do not need one.
- **It checks itself.** The script carries both agent builds inside it, picks the right one with `uname -m`, and refuses
  to install if the SHA-256 does not match. Updates afterwards are verified against your server's own Ed25519 release key.
- **It runs as a system service.** A LaunchDaemon (`/Library/LaunchDaemons/com.fenrir.agent.plist`) starts the agent
  at boot as root, before anyone signs in, and restarts it if it stops.

## Installing

From the console: **Deploy agents → macOS** gives a per-customer script. On the Mac, as an administrator:

```sh
sudo sh Install-Fenrir-macOS.sh            # optionally: --proxy http://proxy.example:3128
```

From your RMM or MDM (Jamf, Intune, Kandji, Mosyle, Addigy, or any tool that runs scripts as root):
**Deploy agents → Deploy from your RMM** gives a one-line script for macOS that downloads the installer with the
deployment token and runs it. It does nothing if the agent is already running, so it is safe to run on a schedule. See
[DEPLOY_FROM_YOUR_RMM.md](DEPLOY_FROM_YOUR_RMM.md).

## Privacy permissions (the trade-off)

macOS asks a person to allow some things, whatever the signing:

| Permission | What needs it | Where |
|---|---|---|
| Full Disk Access | Complete malware scanning and file inventory | System Settings → Privacy & Security → Full Disk Access → add `/usr/local/bin/fenrir-agent` |
| Screen Recording | Remote screen view | Privacy & Security → Screen Recording |
| Accessibility | Remote mouse and keyboard control | Privacy & Security → Accessibility |

Without notarisation and a Developer ID there is no stable signing identity, so:

- An MDM privacy profile (PPPC) cannot pre-approve the agent reliably: the ad-hoc signature changes with every build.
- After an agent update, macOS may treat it as a different program and you may need to allow it again. Remote screen
  is the one users notice; scanning carries on without Full Disk Access but skips protected folders.

Everything else (inventory, scripts, patching with Homebrew, monitoring, alerts, terminal and files in remote sessions)
works without any of these permissions.

If you have an Apple Developer account, you can sign and notarise the agent yourself (`codesign --options runtime`
with your Developer ID, then `xcrun notarytool submit`) and deploy a PPPC profile for that identity. Fenrir does not do
this for you.

## Removing it

```sh
sudo launchctl bootout system/com.fenrir.agent
sudo rm -f /Library/LaunchDaemons/com.fenrir.agent.plist /usr/local/bin/fenrir-agent /var/log/fenrir-agent.log
sudo rm -rf /var/db/fenrir
```

Then retire the device in the console so it stops counting.
