# Apple device management (MDM-02)

**Protection → Apple devices (MDM)** manages iPhones, iPads and Macs with Apple's MDM protocol. This is separate from
web protection ([APPLE_WEB_PROTECTION.md](APPLE_WEB_PROTECTION.md)), which is a DNS profile and not device
management. The code is in `cloud/fenrir_cloud/apple_mdm.py`; the device-facing endpoints are `/mdm/checkin` and
`/mdm/server`.

## What Apple requires

These are dependencies. The page shows the state of each.

| Dependency | Why | State in Fenrir |
|---|---|---|
| **APNs MDM push certificate** (identity.apple.com/pushcert, with a CSR signed by an MDM vendor) | Without it devices are never told to check in | Upload the certificate and key. Fenrir reads the topic and expiry and alerts 30 and 7 days before expiry. A certificate with a different topic is refused: renew the existing one, or every device is orphaned. |
| **Apple Business Manager** server token | Automated device enrolment (ADE) and App Store app licences | Only the expiry is recorded, with reminders. ADE device sync and app licences are **not built**. |
| A public HTTPS address for Fenrir, with a publicly trusted certificate | Devices check in to it | Set it on the page. |

## Enrolment

**Download an enrolment profile** produces a `.mobileconfig` for one device, valid for seven days. It contains:
* a device identity certificate, issued by this customer's Fenrir MDM certificate authority, inside a password-protected
  PKCS#12 payload;
* the MDM payload: check-in and command URLs, the push topic, all access rights, signed messages, and check-out on
  removal.

The user installs the profile (Settings → Profile Downloaded). The device then sends three check-ins:
1. *Authenticate* (serial number, model, OS);
2. *TokenUpdate* (its push token);
3. *CheckOut*, later, if the profile is removed.

## Request authentication

Every request carries `Mdm-Signature`, a detached CMS signature made with the device identity. Fenrir checks all of the
following before it reads the request:
* the signature over the signed attributes is valid;
* the signed message digest matches the body (SHA-256 or SHA-1);
* the signing certificate was issued by this customer's MDM CA;
* its serial belongs to an enrolment Fenrir issued.

A device that checked out is refused afterwards.

## Commands

| Command | Notes |
|---|---|
| DeviceInformation, SecurityInfo, ProfileList, InstalledApplicationList, CertificateList | Inventory and posture. DeviceInformation runs automatically at enrolment. |
| InstallProfile, RemoveProfile | Step-up authentication |
| InstallApplication | Enterprise apps by https manifest URL. App Store apps need ABM licences (not built). Step-up authentication. |
| DeviceLock | Step-up authentication |
| EraseDevice | Step-up authentication, and the device's serial number typed to confirm |

Commands are queued, pushed through Apple (HTTP/2 with the push certificate) and handed to the device when it checks
in. Results are stored with the command. *NotNow* (for example a locked device) leaves the command queued. A push token
that Apple reports as unregistered marks the device removed. Every command is audited.

## Not built yet

* ADE (DEP API) sync and zero-touch enrolment;
* App Store app and book licences;
* declarative device management;
* user enrolment (BYOD);
* configuration profile templates in the console (profiles are installed from a `.mobileconfig`).

Live verification needs an Apple push certificate and real devices.

## Dependency added

`h2` (MIT), with `hpack` and `hyperframe` (MIT), through `httpx[http2]`: Apple's push service accepts HTTP/2 only.
They are pinned with hashes in `cloud/requirements.lock`.
