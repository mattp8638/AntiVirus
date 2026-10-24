# Cloud-native customer installers (Option A)

## Deployment contract

Selecting **Windows** and pressing **Generate & download** returns a **unique,
self-contained `Fenrir-Windows-Installer.exe`** with the specific customer's
cloud origin and fresh enrollment token embedded inside the executable. The
technician does not download GitHub artifacts, stage releases or run PowerShell
scripts. The server builds and retains the base unsigned Windows user-mode
setup automatically during the **Ubuntu Docker image build**.

**Full source is NOT recompiled on every click.** Docker automatically
cross-compiles the Windows agent + native self-extracting setup once during
`docker compose build`. Each download appends validated tenant-specific data
in memory to that already-compiled base executable. This is intentional Option A.

The download is returned immediately as an authenticated, private/no-store
HTTP response. Raw tokens are not placed in download links, public web
directories, server-side generated files, audit logs, or the database. The
database holds the digest, expiry, customer and optional device group only.

## Ubuntu deployment

No additional Windows certificate or separate manual release step is needed:

```sh
cd ~/AntiVirus
git pull
sudo docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build cloud
sudo docker compose -f deploy/docker-compose.yml --env-file deploy/.env ps
```

The Docker build installs the free MinGW-w64 cross-compiler in a separate
build stage. It automatically builds the original native Windows setup with
its service, endpoint GUI, remote helper and other user-mode components. The
runtime cloud container receives just the completed read-only base executable;
no compiler is available to the public-facing API.

Existing PostgreSQL volumes and credentials are preserved. Do not use
`docker compose down -v`. Existing obsolete
`FENRIR_WINDOWS_SETUP_SHA256`, `FENRIR_ALLOW_UNSIGNED_WINDOWS_INSTALLERS`
or `FENRIR_WINDOWS_SIGNER_THUMBPRINT` entries in an old `deploy/.env` are
ignored and can be cleaned up later.

## Operator workflow

1. In the console, go to **Deploy agents** and select **Windows**.
2. Select customer, optional group, label and enrollment-token lifetime.
3. Click **Generate & download Windows installer**.
4. Receive **one .exe**, distinct on each request. Keep it private because
   it contains a still-valid customer enrollment credential.
5. On your isolated Windows VM, run the exe as administrator and complete
   the Fenrir setup window. Enrollment/cloud settings are read from inside
   the downloaded exe; they are never passed on the command line.
6. Confirm the service starts and the device appears under the intended
   customer. Reboot twice and test RMM/PSA as in
   `PHASE2_FUNCTIONAL_EXIT_GATES.md`. Revoke leaked/unused tokens.

**Windows setup does not disable SmartScreen, Defender, or Windows code
integrity.** The unsigned hobby build has no signed kernel minifilter;
full real-time antivirus protection is not claimed.

## Implementation details

The trusted base executable is bundled at
`/app/cloud/downloads/windows/FenrirSetup.exe`. A request creates a new
random token, validates the destination customer and group, appends its
configuration and SHA-256 digest to the PE overlay, then responds with the
new executable. A built-in Windows setup reader checks the format and digest
before using the settings.

SHA-256 on unsigned embedded metadata detects accidental corruption only.
It is **not** an Authenticode publisher signature; unsigned executables can
be maliciously modified and rehashed. Install only the exe received over
your own HTTPS Fenrir console in a controlled VM.

If the automatic cross-build fails, the Docker image build fails and the
old running deployment stays intact. The cloud will not issue phantom
enrollment tokens for an unavailable Windows template.

## Evidence and exit gates

`cloud/tests/test_deployment_installers.py` checks unique output, private
download headers, token isolation, corruption, missing builds, and no
filesystem staging. CI must also build the actual Docker cross-compiled
Windows executable and run the full cloud, console, Linux and integration
suite. The user must still perform the actual Windows VM installation,
two-reboot test and check-in/RMM/remote-session tests before release approval.
