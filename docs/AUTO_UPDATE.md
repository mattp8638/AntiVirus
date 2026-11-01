# Automatic updates

Two pieces keep everything current without merging, pulling and rebuilding by hand.

## 1. The server follows a branch

`deploy/auto-update.sh` checks the branch every 10 minutes. When it has new commits, the script:
1. pulls them;
2. builds the new image while the old one keeps serving;
3. restarts the containers;
4. waits for `/ready` (database schema and mapped device columns, as well as a running API).

If the build or the health check fails, it returns to the previous commit and skips the failed commit until a newer one arrives.

One-time setup on the server:

```
cd ~/AntiVirus
sudo deploy/install-auto-update.sh            # follows main
sudo deploy/install-auto-update.sh my-branch  # or follow another branch
```

| What | Command |
| --- | --- |
| Run now | `sudo systemctl start fenrir-auto-update.service` |
| Rebuild the current commit anyway | `sudo deploy/auto-update.sh --force` |
| Log | `sudo tail -f /var/log/fenrir-auto-update.log` |
| Turn off | `sudo systemctl disable --now fenrir-auto-update.timer` |

**Notes:**
- Git runs as the account that owns the checkout, so it uses that account's GitHub access.
- Files you changed by hand stop the update and are named in the log. Untracked files are never touched: `deploy/.env`, `deploy/docker-compose.https.yml`.
- `docker-compose.https.yml` is included automatically when it exists.

## 2. Agents follow the server

Every image build stamps the agents with a fingerprint of their source (`buildId` in `downloads/*build.json`). Agents ask the server which build it ships and replace themselves when the fingerprints differ. No version bump is needed.

- **Windows:** the service checks every 30 minutes. It then:
  1. downloads `FenrirSetup.exe` with its device key;
  2. checks the SHA-256;
  3. runs it with `--silent-upgrade`.

  The installer:
  - keeps the enrolled server and device identity;
  - writes `runtime\last-upgrade.log`;
  - and the restarted service reopens the agent window for the signed-in user.

  Each build is tried at most once every 6 hours.
- **Linux/macOS:** the agent checks every 30 minutes. It downloads the binary, checks the SHA-256, swaps it in, and restarts.
- **Turning it off:** the policy setting **Updates → Update agent automatically** turns this off per policy.

**Limits:**
- Windows PCs installed before self-update existed need one manual reinstall to get it.
- A device with an uninstall-protection token cannot stop its own service for the upgrade.
- Local developer builds (`buildId` "dev") never self-update.

## 3. Signed agent releases (Linux and macOS)

Linux and macOS agents built with a release key install an update only if all of these hold:

- **Signature:** the server sends a release manifest signed with that key.
- **Content:** the manifest names this platform and architecture and has not expired. It must also carry a higher release number than the running agent.
- **Download:** the downloaded binary matches the manifest's SHA-256 and size.

So the agent refuses an altered binary, an altered or replayed manifest, a release built for another platform, and an older release. Forcing an update can reinstall the current release but never an older one. Each refusal is reported to the console as an `agent.update.rejected` event.

**The key.** `auto-update.sh` creates `deploy/signing/release-ed25519.pem` on first run and logs its public key. The file stays on the server and is listed in `.gitignore`. It reaches the image build as a BuildKit secret, so it never ends up in an image layer.

**Back the key up offline.** Agents built with it accept only updates it signs. If it is lost, agents can only be updated by reinstalling them.

**Rollback.** To roll back, rebuild the older code with a newer release number, for example by setting `FENRIR_RELEASE_SEQ` in `deploy/.env`. Releases only move forwards.

**Key rotation.**

1. Create the new key.
2. Put its public key in `FENRIR_RELEASE_PUBLIC_KEYS` in `deploy/.env`. The next build then pins both the old and the new key.
3. Once every agent has updated, switch `FENRIR_RELEASE_KEY` to the new key.

**Signing off the server.** For a key that never touches the server:

1. Set `FENRIR_RELEASE_KEY` to an empty file and put the offline key's public key in `FENRIR_RELEASE_PUBLIC_KEYS`.
2. On the machine that holds the key, sign the built binaries:
   ```
   fenrir-release-sign -key release.pem -out out -release N -version V -build-id B linux:amd64:fenrir-agent-linux-amd64 …
   ```
3. Copy the resulting `<platform>-<arch>.manifest.json` and `.manifest.sig` files into `deploy/releases`.

**Builds without a key.** CI, and a lab checkout without a key, build agents that keep the older check: the SHA-256 reported by the server. `linux-build.json` records `releaseSigned` and `pinnedReleaseKeys`.
