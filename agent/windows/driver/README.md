# AntivirusMinifilter

Fenrir's Windows file-system minifilter. With it loaded, Fenrir checks programs **before they run** instead of
just after.

## What it does

| When | What happens |
|---|---|
| Windows is about to map a file as code (a program starting, a DLL or driver loading) | The driver asks the Fenrir service. If the service says block, the mapping fails with "Access is denied" and the program never runs. |
| A handle that wrote an executable, script or archive is closed | The file is sent for a scan. The service can quarantine it. |
| A file was found clean | That result is kept until the file changes, the service reconnects, or 10 minutes pass, so a program that starts often is not rescanned every time. |

The service decides; the driver only asks and enforces. Detection uses the same engine, policy and exclusions as
everything else in Fenrir.

## Safety

- **Fails open.** No service connected, no answer within 10 seconds (3 for scans after writes), or a malformed reply
  all mean allow. After three failures in a row it stops asking for a minute, so a hung service cannot stall every
  program start.
- **No deadlock with the scanner.** The service reads files to scan them, so its own file activity is never sent
  back to it. The System process is skipped too.
- **No name lookups under section locks.** File names are resolved when a file is opened and kept with the handle.
- **Only administrators and SYSTEM** can connect to its communication port (`\AntiVirusRealtimePort`).
- **Demand start.** The Fenrir service loads it when it starts, not the boot loader, so a faulty driver cannot stop
  Windows booting.
- **Unloadable** (`fltmc unload AntivirusMinifilter`, administrators only), so setup can upgrade it.

## Files

| File | Purpose |
|---|---|
| `src/AntivirusMinifilter.c` | The driver |
| `AntivirusMinifilter.inf` | Install package (load-order group *FSFilter Activity Monitor*, altitude 370030, the same as setup's fallback registration) |
| `build.ps1` | Builds the `.sys`, stamps the INF, makes the catalog (Windows Driver Kit, x64 developer prompt) |
| `prebuilt/x64/` | The built, **unsigned** package, committed by `.github/workflows/driver.yml` whenever the source changes |
| `../shared/include/RealtimeProtectionProtocol.h` | The message format, shared with the service |

Fenrir's server builds the installer on Linux, which cannot compile kernel drivers. So the
GitHub workflow builds the driver with Microsoft's toolchain and commits the result. The server stages
`prebuilt/x64` into the installer and signs the `.sys` and `.cat` with its code-signing certificate
(`deploy/sign-windows.sh`). A lab build with no certificate gets a throwaway test signature on the driver only.

## Loading it

Windows only loads kernel drivers with an acceptable signature:

- **Customer machines:** the driver must be attestation-signed by Microsoft (see `docs/DRIVER_SIGNING.md`). Until
  then setup installs it, Windows refuses it, and Fenrir carries on without pre-execution blocking.
- **A lab machine or VM:** turn on test signing, then the server-signed or test-signed driver loads. See
  *Testing on a lab machine* in `docs/DRIVER_SIGNING.md`.

Before a public release, ask Microsoft for an altitude in the *FSFilter Anti-Virus* range and change it in both the
INF and setup (`kMinifilterDefaultInstanceAltitude`, `kMinifilterLoadOrderGroup`).
