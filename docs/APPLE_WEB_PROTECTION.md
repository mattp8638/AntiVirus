# Web protection for iPhone, iPad and Mac

Fenrir protects Apple devices from malware and phishing websites without an app, Intune, an Apple MDM or an Apple
developer account. It uses only Fenrir.

## How it works

1. A technician opens **Devices › Add a phone**, picks the customer and makes an enrolment code. Each code enrols one
   device and expires after 24 hours. This is the same code Android phones use.
2. The device's user scans the QR code with the camera, or opens the link in Safari on a Mac. The page sees that it is
   an iPhone, iPad or Mac and offers **Install web protection**.
3. Fenrir creates a device record for the customer (platform `ios` for iPhone and iPad, `macos` for a Mac) and returns a
   configuration profile. The profile holds a single `com.apple.dnsSettings.managed` payload, which sets the device's
   encrypted DNS (DNS over HTTPS) to that device's own Fenrir resolver, `https://<server>/dns/<device token>/dns-query`.
4. The user installs it from Settings. iPhone and iPad: **Settings › Profile Downloaded › Install**. Mac:
   **System Settings › Privacy & Security › Profiles** (on macOS 15, **System Settings › General › Device Management**).
5. From then on, every website lookup on the device goes to Fenrir. The customer's DNS policy (threat intelligence,
   blocklists, blocked categories, observe or block mode) applies exactly as it does on a PC with the agent. Blocked
   lookups are logged against the device and listed on its page.

Requirements: iOS or iPadOS 14 or later, macOS 11 or later, and a Fenrir server on a public `https://` address
(`FENRIR_PUBLIC_URL`). Apple does not accept a plain-http resolver, so enrolment is refused until the address is https.

## What the console shows

These devices are marked **web protection only** in the device list. Their page has three sections: **Web protection**,
**Security › Alerts** and **Settings**. Web protection shows:

- **Status**: Working, Quiet (no lookups for over a day), Stopped, Waiting for install, Not installed, or Decommissioned.
- When the device first used the profile, the last lookup, how many lookups were blocked in the last 7 days, and the
  most recent blocks.
- A warning if the device's policy has DNS protection off or in observe mode, because then nothing is blocked.
- A link to install the profile again. Only staff who can change configuration see it.

There are no remote actions. Nothing on the device can run them, so Fenrir refuses every command, bulk action, script,
patch scan and condition remediation for these devices.

## Knowing it still works

The device is counted as seen whenever it looks a name up. The time is written at most once a minute. An hourly job
raises a medium alert:

- **Web protection was never installed on …**: the profile was made more than 24 hours ago and has never been used.
- **Web protection has stopped on …**: no lookups for 72 hours. The profile may have been removed, a VPN may be in use,
  or the device has been off.

The alert closes itself at the next lookup. The usual "offline" monitors ignore these devices, because a phone that is
asleep is not a problem.

## Signing the profile

An unsigned profile installs normally but shows as **Unverified**. To show it as **Verified**, give Fenrir a
certificate and key:

```
FENRIR_PROFILE_SIGNING_CERT=/etc/fenrir/profile-signing.pem   # leaf certificate first, then its chain
FENRIR_PROFILE_SIGNING_KEY=/etc/fenrir/profile-signing.key    # unencrypted PEM private key
```

The TLS certificate for the server's own domain works well. Caddy keeps its certificates in its data volume. Copy them
somewhere the cloud container can read, and copy them again when they renew. Profiles are signed when they are
downloaded, so a renewed certificate takes effect straight away.

## Decommissioning

When you decommission a profile device, nothing is filtered or logged for it any more, and its profile can no longer be
downloaded. Its lookups **still get plain answers**. Encrypted DNS does not fall back to the network's resolver, so
refusing them would cut the device off from every website until someone removed the profile. Remove the profile from
the device: **Settings › General › VPN & Device Management** on an iPhone or iPad. The resolver stops answering only
when the decommissioned record is deleted permanently.

## Limits

- **The user can remove the profile.** Only a supervised device (Apple Business Manager or Apple Configurator) can be
  stopped from removing it. Fenrir notices within 72 hours and alerts.
- **A VPN app or iCloud Private Relay can send lookups around the profile.** While a VPN is connected, its own DNS
  settings usually take priority.
- **Fenrir must stay reachable.** While the Fenrir server, or its upstream resolver (`FENRIR_DNS_UPSTREAM`), is down,
  devices with the profile cannot look names up at all. Treat the server as a service those devices depend on.
- **This is web protection, not device management.** Fenrir cannot see installed apps, locate, lock or wipe an Apple
  device, or report its patch level. That needs Apple MDM: an APNs certificate, an MDM server, and Apple Business
  Manager for company-owned devices. Fenrir does not have Apple MDM today. Apple does not let apps inspect other apps on
  iOS, so the scanning Fenrir does on Android is not possible on an iPhone.
- Re-enrolling the same device creates a new record. The new profile replaces the old one on the device, because they
  share an identifier. Decommission the old record once its "stopped" alert appears.

## Code

- `cloud/fenrir_cloud/web_profile.py`: profile building and signing, liveness, the hourly alert job and the status view.
- `cloud/fenrir_cloud/routers/web_profile.py`: `POST /api/v1/enroll/apple`, `GET /dns/{token}/apple.mobileconfig`,
  `GET /api/console/devices/{id}/web-protection`.
- `cloud/fenrir_cloud/routers/protection.py`: the resolver records liveness and keeps answering decommissioned profile devices.
- `console/src/components/WebProtection.tsx`: the enrolment page's Apple part and the device page.
- Tests: `cloud/tests/test_web_profile.py`, `console/tests/web-protection.test.tsx`.

Status: built and tested in CI. Not yet installed on a real iPhone, iPad or Mac.
