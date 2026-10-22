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
