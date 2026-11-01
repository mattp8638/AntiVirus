# Windows patching: service execution and WinGet diagnostics

The protection service owns patch discovery, installation, temporary scripts and runtime database updates. The desktop client requests refreshes and per-app checks through the local broker, on a background thread. Refresh/check requests retain the broker's PatchRefresh authorization; installations retain PatchInstall authorization. Do not grant standard users write access to the service's update folder to work around a refresh failure.

## What the update states mean

| State | Meaning |
|---|---|
| Available | WinGet matched the installed package and listed an applicable upgrade/version. |
| Current | WinGet matched the installed package and reported no applicable upgrade. This follows WinGet's applicability and pinning rules. |
| Updater available | A vendor updater is configured; this alone does not prove that a new version exists. It is excluded from the confirmed-update count. |
| Package not matched | WinGet could not correlate this package in the service account. Check the mapped package ID, registration and installation scope. |
| Check needed | The provider is missing, failed, timed out, returned unreadable output, or the result remains unverified. This is not an up-to-date finding. |
| Verification pending | An installer returned success, but the follow-up inventory has not confirmed completion. Refresh after the installer finishes or the device restarts. |

Discovery uses `winget list --id PACKAGE --exact --source winget`, followed by its `--upgrade-available` filter. It never uses `upgrade --id` as a check: that command runs an installer. An installation checks applicability first, upgrades the exact package silently and checks it again. The actual available version is retained instead of the literal word `available`.

WinGet is resolved from the protected machine App Installer directory, using numeric package versions and the native architecture. The service does not depend on the signed-in user's PATH or app-execution alias. Calls have bounded execution times and capture provider output. RMM patch scanning and software deployment use the same executable resolution and explicit community source.

RMM scans report Windows Update and WinGet coverage separately. A failed provider cannot turn its missing patches or linked vulnerabilities into installed/fixed findings just by returning an empty list. Incomplete coverage and provider errors remain visible in the console and survive heartbeats. Compliance uses all approved devices as its denominator; incomplete scans and pending restarts are not counted as verified fully patched. Failed scans retry after a short backoff. Legacy agents without coverage metadata retain their earlier protocol until upgraded.

## Reported failures

- `WINGET_0x8A150014` (decimal 2316632084) means no matching installed package was found. An application visible in a user's registry/profile is not necessarily visible to the service's WinGet instance. A recipe's package ID can also be wrong for that edition/channel. This requires matching/context correction, not repeated blind installation attempts.
- `Unable to create temporary patch orchestrator script` from the desktop refresh was caused by trying to write the service's update directory from the desktop user. Refresh and Check now use the service broker. Install the updated service and client together.
- Missing App Installer, broken sources and timeouts are reported as provider errors. They must not produce an up-to-date result or a confirmed-update count.

App Installer/WinGet must be supported on the endpoint's OS and usable in the service context. Per-user packages and applications outside the WinGet catalogue may need the vendor updater or an approved user-context/manual workflow. The current change does not create a general per-user installer broker or install App Installer automatically.

## Deployment and validation

Rebuild the cloud image to publish the new Windows installer, then update the endpoint's service and desktop client with that installer (or the approved agent rollout). A cloud rebuild alone does not replace an already-running endpoint client.

On a test Windows endpoint, verify a standard user can request a refresh without writing the protected update directory, Check does not start an installer, and installation still requires the configured authorization. Test a real outdated package, an up-to-date package, a per-user-only package and an unavailable source. Confirm update counts and post-install verification; inspect patch history/provider diagnostics for failures. Reboot only through the configured restart policy or an explicit operator action.

Portable tests exercise the command protocol using provider fixtures, including source failures, matching failures, timeouts and post-install verification. The endpoint HTML is tested against available, current, capability-only and unknown/error states. Windows CI builds/runs the WinGet tests and builds the actual installer; this does not replace a live Windows/App Installer acceptance test.

References: [Microsoft WinGet list](https://learn.microsoft.com/en-us/windows/package-manager/winget/list), [upgrade](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade), [return codes](https://github.com/microsoft/winget-cli/blob/master/doc/windows/package-manager/winget/returnCodes.md), [supported client OS and installation](https://github.com/microsoft/winget-cli#installing-the-client).
