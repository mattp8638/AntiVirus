# Customer-specific agent installation downloads

The **Deploy agents** page now selects a target OS and customer/group **before** it generates an enrollment token. It returns a one-time authenticated download. Raw tokens are SHA-256-hashed in the database and contained only in the generated files. The endpoint never writes these files to a public URL.

## What downloads work

| Operating system | Download | Runtime prerequisites | Current limitations |
|---|---|---|---|
| Linux amd64 / arm64 | `Install-Fenrir-Linux.sh` | systemd, curl, SHA-256 tooling, sudo | Fully provisions the managed Go agent and automatic-start systemd service. Confirm cloud check-in and test a reboot. |
| Windows x64 | `Fenrir-Windows-Enrollment.zip` | **Signed native FenrirSetup.exe** staged on the cloud, configured certificate thumbprint, Administrator PowerShell | The bundle embeds a signed native GUI installer. The PowerShell launcher verifies signature and SHA-256, opens setup, then checks the service and cloud URL. Kernel minifilter requires separate proper driver signing. |
| macOS | Not offered | Signed/entitled package, device enrollment support and launchd | **Not implemented:** current Swift prototype lacks an installable enrollment daemon. The UI deliberately disables downloads. |

### Windows release staging

The default Docker Compose stack mounts `deploy/releases` read-only at `/app/cloud/downloads/releases`.

1. Build the Windows native setup from the intended commit on a trusted Windows build workstation, and test it on a clean Windows VM.
2. Sign the release with an Authenticode code-signing certificate trusted by target Windows devices. Publish a signed driver separately if claiming minifilter protection.
3. Copy `FenrirSetup.exe` into `deploy/releases/` on the server. Keep only verified releases, and limit write permission to trusted release operators.
4. Run `Get-AuthenticodeSignature .\FenrirSetup.exe | Select-Object -ExpandProperty SignerCertificate` on Windows. Set `FENRIR_WINDOWS_SIGNER_THUMBPRINT` in your **server's** `deploy/.env` to that release-signing certificate's 40-character SHA-1 thumbprint, then recreate the cloud container.
5. Refresh availability on the Deploy page; Windows should become available. The ZIP includes `FenrirSetup.exe`, `Install-Fenrir.ps1` and a README. The script rejects any installer whose hash, signature or pinned certificate doesn't match.

Example to recreate the cloud service:

```bash
cd ~/AntiVirus
sudo docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build cloud
```

The image itself is not responsible for building/signing the Windows installer. Do **not** put a self-signed development binary into commercial release distribution. Windows' `Get-AuthenticodeSignature` must report `Valid` on the target workstation.

### Using the downloads

- **Linux:** transfer the downloaded `.sh` using an authenticated channel, inspect it, then `sudo sh ./Install-Fenrir-Linux.sh`. It creates the root-only enrollment config, downloads the architecture-specific binary from your configured HTTPS server, checks SHA-256, installs a systemd service and confirms the service started.
- **Windows:** extract the ZIP onto the intended Windows endpoint; verify its origin, inspect the PowerShell file, optionally use `Unblock-File .\Install-Fenrir.ps1` after validation, and run `.\Install-Fenrir.ps1` in Administrator PowerShell. Complete native Fenrir Setup when it opens; the script checks installation afterwards.

Both files contain a **customer enrollment secret**. Do not email unencrypted files, store them in public shares, embed them on public web pages, or paste the token into tickets. Revoke unused or exposed tokens in the console. Downloading a package creates a new token; retrying creates another token.

### API

- `GET /api/console/enrollment-installers/status` – authenticated installability flags and reasons.
- `POST /api/console/enrollment-installers` – authenticated, `configure`-permission, body `{os, tenantId, groupId?, label?, expiresInDays}`. Returns an attachment (never a public download link). Refuses unavailable builds **before** creating a token. Checks tenant and group ownership.

### Acceptance requirements

Before commercial deployment verify Linux amd64 and arm64 clean installations, first enrollment, service startup after two reboots, repeated install without data loss, duplicate enrollment behavior and token revocation. On Windows also verify certificate trust, setup handling of `--server` and `--enroll-token`, service recovery after crashes, the specific Windows build, cloud check-in to the selected tenant, and compatibility with existing endpoint security. macOS support requires a separately implemented signed PKG, entitlements, real enrollment logic and launchd service.

**Current status:** functionality committed on a development branch. Passing unit tests and container builds are necessary but not sufficient proof of persistent endpoint operation. Do not merge or deploy until platform-specific acceptance tests pass.
