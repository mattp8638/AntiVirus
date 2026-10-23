# Windows agent persistence — findings and verification

This change addresses installer correctness and service recovery configuration. **It does not establish that an endpoint has survived a reboot**: that requires installation on a disposable, authorised Windows test VM and before/after measurements.

## Source findings

1. The service already requests `SERVICE_AUTO_START`, restart recovery actions and a service failure-actions flag in `ServiceMain.cpp`. Previously those recovery configuration calls ignored failure. They now cause installation/repair to report failure if Windows refuses the required recovery settings. Unexpected exits are also reported to Windows Application Event Log (source `FenrirAgent`, event ID `4097`) and marked as service failures so SCM recovery can act.
2. The native setup had a placeholder `if (!true)` in place of minifilter installation while still running driver-required post-install checks. Setup now checks the **actual Windows minifilter service state**, explicitly reports reduced protection, and does not pretend that an unsigned/unavailable driver is installed.
3. Setup previously unconditionally reset the stored cloud endpoint to the default during repair, potentially causing a valid installed device to appear offline in its original MSP tenant. Repair now retains the registered cloud endpoint.
4. Setup now checks that `FenrirAgent` is registered as automatic-start, points at the permanent Program Files executable, has restart-on-failure configured, retains its executable and remains in SCM `RUNNING` state without restarting during an observation period. This does not replace a reboot test.
5. Repair uses the agent's authorised `--stop` maintenance command before modifying files. A protected installation requires valid maintenance authorisation; setup must not bypass it.
6. Failed stop requests cannot hang forever or lead to an automatic uninstall/upgrade while the service is still running. A failed maintenance request restores service-control protection.
7. Repairs and startup hardening preserve the existing uninstall-protection token hash rather than silently clearing it.

No change weakens Windows Defender, disables endpoint protection, creates a persistence bypass or forces a service to survive an authorised uninstall. The minifilter still needs a legitimately signed/verified deployment to provide kernel-level real-time enforcement.

## Before/after-reboot diagnosis

Run from elevated PowerShell in a Windows VM with a legitimately installed agent:

```powershell
.\agent\windows\installer\Get-FenrirAgentDiagnostics.ps1 | Out-File -Encoding utf8 .\fenrir-before.json
Restart-Computer
# After you log back in:
.\agent\windows\installer\Get-FenrirAgentDiagnostics.ps1 | Out-File -Encoding utf8 .\fenrir-after.json
```

Compare both reports. A missing SCM service, a stopped service, a missing executable, absent Add/Remove Programs entry and an offline cloud enrolment require different fixes. Check Windows System service-control events and Defender/third-party antivirus quarantine for the exact cause. Do **not** suppress a legitimate malware detection or disable protection to make installation pass.

## Release acceptance criteria

- Signed or otherwise appropriately validated user-mode binaries and driver packages for the target Windows build.
- Windows service installed under a stable Program Files path, `StartMode=Auto`, restart recovery actions, healthy binary and running status.
- Install then reboot **twice** on a clean test VM and confirm the service and endpoint client still exist, run, and check into the same tenant with the original device identity.
- Confirm repair preserves tenant enrolment, device identity and data, with a customer-authorised maintenance process if service tamper protection prevents a stop.
- Test a service crash and validate Windows SCM restart; test disconnected network and reconnect without reinstall.
- Confirm minifilter/AMSI/ETW/WFP claims separately; absence of a signed minifilter must be reported as degraded.
- Capture baseline reports and relevant Windows Event Log entries for any failed acceptance step.

## Known limitations

- This source review has not reproduced the reported reboot failure on the affected PC; the mechanism is not conclusively proven.
- No live Windows installation, reboot, native installer build, code-signature validation or Defender coexistence run has been executed by this review.
- Do not deploy this branch to customers until the above tests pass and the installer/service binary are rebuilt and signed through the project's authorised release procedure.
