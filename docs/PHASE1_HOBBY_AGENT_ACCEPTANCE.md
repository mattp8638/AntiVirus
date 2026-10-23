# Phase 1 — hobby/development agent reliability

Scope: **Windows user-mode agent + Docker-hosted cloud + basic RMM check-in**, without purchasing a code-signing certificate. The aim is a persistent, auditable lab installation. This is not a replacement for Windows Defender and does not provide a signed kernel minifilter.

## Changes on this branch

- Explicitly opt into unsigned **user-mode** Windows installer bundles. The server requires both `FENRIR_ALLOW_UNSIGNED_WINDOWS_INSTALLERS=true` and a manually pinned, trusted `FENRIR_WINDOWS_SETUP_SHA256` matching the staged `FenrirSetup.exe`. The generated PowerShell launcher still verifies SHA-256. It does **not** disable Defender, SmartScreen, code-integrity policies or kernel driver signing.
- Windows console shows a conspicuous reduced-protection warning when hobby mode is enabled. Signed releases remain a separate, stricter path.
- Re-running an installer with the **same** server and enrollment token preserves its device identity. If a machine is already enrolled, a **different** token/server now stops with an explicit error instead of resetting its identity and silently moving customers. Test with `EnrollmentPersistenceTests.cpp`.
- The setup executable refuses to queue deferred replacements of locked binaries that would otherwise take effect at the next reboot. If the running agent cannot be stopped safely, repair fails visibly instead of claiming success and leaving mixed binaries.
- `Test-FenrirRebootPersistence.ps1` captures a baseline, confirms auto-start and stable process health, then verifies service path and the fingerprint of the original enrollment token through two **actual** Windows reboots. It does not expose the raw secret or alter Windows security.

## Build and stage the unsigned native Windows installer

On a trusted Windows development machine with Visual Studio C++ tools, CMake and the repository checked out on this branch:

```powershell
cmake -S agent/windows/service -B build -DANTIVIRUS_REQUIRE_MINIFILTER_PAYLOAD=OFF
cmake --build build --config Release --target antivirus-setup
Get-FileHash -Algorithm SHA256 agent/windows/out/install/FenrirSetup.exe
```

Make sure the setup and its bundled binaries all come from the **same branch/commit**. The build's unsigned binaries are appropriate only for an isolated test environment, not production endpoints. Windows reputation or policy enforcement may block them; inspect the detection and fix the underlying concern rather than bypassing protection.

Transfer the resulting `FenrirSetup.exe` to **your Linux server** in `~/AntiVirus/deploy/releases/`. This is the trusted release-staging operation; the customer installer itself will be downloaded via the console.

On the Linux server:

```bash
cd ~/AntiVirus
mkdir -p deploy/releases
sha256sum deploy/releases/FenrirSetup.exe
nano deploy/.env
```

Set in `deploy/.env` (the SHA-256 must be the actual trusted value you independently verified on the Windows build computer):

```dotenv
FENRIR_ALLOW_UNSIGNED_WINDOWS_INSTALLERS=true
FENRIR_WINDOWS_SETUP_SHA256=<the actual 64-character SHA-256 digest>
FENRIR_WINDOWS_SIGNER_THUMBPRINT=
```

Then update the cloud container (the existing PostgreSQL volume is preserved):

```bash
sudo docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build cloud
sudo docker compose -f deploy/docker-compose.yml --env-file deploy/.env ps
curl -f http://localhost:8080/health
```

In **Deploy agents**, choose **Windows**, the customer, and group, then **Generate & download**. The ZIP includes the staged Setup executable, a per-customer `Install-Fenrir.ps1`, and a README. Only run downloaded installers you built and verified yourself. Keep the enrollment bundle private and revoke exposed/unused tokens.

For Linux, the normal deployment flow remains in place.

## Two-reboot Windows acceptance gate

On a test machine, complete Setup, confirm the service is Running, and keep the three scripts together:

```powershell
# Run elevated after installing the agent.
.\agent\windows\installer\Get-FenrirAgentDiagnostics.ps1 -AssertHealthy
.\agent\windows\installer\Test-FenrirRebootPersistence.ps1 -Mode Baseline

Restart-Computer

# After sign-in:
.\agent\windows\installer\Test-FenrirRebootPersistence.ps1 -Mode Verify
Restart-Computer

# After sign-in again:
.\agent\windows\installer\Test-FenrirRebootPersistence.ps1 -Mode Verify
```

Additionally verify **the same device ID** is still present in Fenrir Console after each reboot, with new heartbeats. Check no duplicate device was created. From the console run a harmless, read-only RMM command (for example, report hostname) and confirm its result, exit status, audit entry and tenant ownership. Disconnect/reconnect the lab network, and confirm queued commands resume without reinstalling the endpoint.

If Windows stops or removes the service, collect `Get-FenrirAgentDiagnostics.ps1` results and inspect service/application/Defender event logs and any legitimate security-product detections; do not disable the security product just to pass the test.

## Known limitations / release gate

- GitHub CI has not executed against recent repository commits. The new portable enrollment-policy C++ test is wired into the platform workflow but a green remote build has not been obtained.
- No live Windows installation, actual two-reboot exercise, Device API heartbeat, remote command or Defender coexistence test has been performed by this code review.
- Hash pinning on the server and in the wrapper confirms payload integrity for your own lab build; it **is not equivalent to publisher authentication** from Authenticode signatures.
- The macOS installer remains unavailable. The Windows kernel minifilter cannot be deployed as unsigned driver on ordinary modern Windows installations.
- An explicit, audited customer migration/re-enrollment flow is still needed if an already-enrolled endpoint must deliberately move between customers or cloud servers.
- DO NOT claim 100% Windows reliability or full antivirus coverage until actual device, cloud and reboot acceptance tests pass.
