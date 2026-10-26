# Automatic updates

Two pieces keep everything current without merging, pulling and rebuilding by hand.

## 1. The server follows a branch

`deploy/auto-update.sh` checks the branch every 10 minutes. When it has new commits, the script:
1. pulls them;
2. builds the new image while the old one keeps serving;
3. restarts the containers;
4. waits for `/health`.

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
