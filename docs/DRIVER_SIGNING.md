# Driver signing: what it really costs

Short version: getting the Fenrir minifilter signed for Windows 10/11 costs roughly **£300–£600 a year**, not a fortune. ELAM is the expensive part, and Fenrir does not need it.

Prices below are typical public list prices at the time of writing. Check current prices before buying.

| What | Needed for | Cost | Notes |
|---|---|---|---|
| EV code-signing certificate | Opening a Microsoft Hardware Dev Center account; signing driver submissions | ~£250–£600/year (Certum, SSL.com, Sectigo; DigiCert costs more) | Comes on a hardware token or in a cloud HSM. Needs a registered company. |
| Microsoft attestation signing | Loading the minifilter on Windows 10/11 client machines | **Free** | Upload the driver package in Partner Center and Microsoft signs it. No lab testing needed. |
| WHQL / HLK certification | Windows Server, and the "certified" badge | Free tooling; costs staff time | Run the Hardware Lab Kit tests on your own machines. |
| ELAM (early-launch anti-malware) | Loading before other boot drivers, and protected-process status for the service | Requires Microsoft Virus Initiative membership, which needs independent lab certification (several thousand £/year) | Optional. Fenrir works without it. |
| Apple Developer Program | Signing and notarising the macOS agent | ~£79 ($99)/year | The Endpoint Security entitlement is requested from Apple, free. |

## What works today without a driver

The Windows agent already does the following in user mode, with no signed driver:

- **Process-start enforcement:** attack surface rules, app control, the ML model and hash verdicts.
- **Device control** through Windows' own policies.
- **Network isolation** through the Windows Filtering Platform.
- **Scripts:** AMSI script scanning.

The trade-off is that blocking happens just after a process starts, typically within a second, not before. Defender, SentinelOne and ESET get pre-execution blocking from their signed kernel drivers.

## Recommended path

1. Buy an EV certificate in the company's name (one-off identity validation, then about a week).
2. Register at partner.microsoft.com/dashboard/hardware and attestation-sign `AntivirusMinifilter.sys`.
3. Turn on `requireMinifilterBrokerConnection` in policy once the signed driver is in the installer.
4. Leave ELAM and MVI until independent test results exist.

## The driver itself

The source is in `agent/windows/driver/` (see its README). `.github/workflows/driver.yml` builds it with the Windows
Driver Kit and commits the unsigned package to `agent/windows/driver/prebuilt/x64`. The server's image build puts
it in the installer and signs it with the server's code-signing certificate. A lab build with no certificate gets a
throwaway test signature on the driver only. For production, the same package is uploaded to Partner Center for
attestation signing instead.

## Testing on a lab machine

Use a virtual machine or a spare PC. **Never do this on a customer machine:** test signing lets any test-signed
driver load.

1. **Turn off Secure Boot.** On a Hyper-V generation 2 VM: VM *Settings → Security*, untick *Enable Secure Boot*.
   On a physical PC it is in the firmware (UEFI) settings.
2. **Turn on test signing.** In an administrator prompt run `bcdedit /set testsigning on`, then restart. Windows shows
   "Test Mode" in the corner of the desktop.
3. **Install Fenrir** from the console with a fresh installer, built after the server image was rebuilt. Setup's log
   should show the minifilter being installed rather than "skipped; payload not embedded".
4. **Check it is running:**
   - `fltmc filters` lists `AntivirusMinifilter` (altitude 370030);
   - `sc query AntivirusMinifilter` shows `RUNNING`;
   - the device's timeline in the console shows *real-time protection broker connected*.
5. **Check it blocks.** Download the standard EICAR test file from eicar.org and save it as `eicar.exe` in your
   Downloads folder, then try to run it.
   - With the driver working, Windows says **Access is denied** and the console shows a real-time block.
   - Without the driver, Windows says the app can't run on this PC instead.
   - Depending on policy, Fenrir may quarantine the file as soon as it is saved, which also shows the driver is
     working.

To go back: `bcdedit /set testsigning off`, then restart. Windows then refuses the test-signed driver, and Fenrir
carries on without pre-execution blocking.

If Windows refuses the driver, the setup log and the device timeline say so (*driver signature rejected*). With
test signing on, that usually means Secure Boot is still enabled.
