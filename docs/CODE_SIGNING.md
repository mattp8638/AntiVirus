# Windows code signing

The server signs every Fenrir Windows program during its image build:
- the service, the agent window, the remote helper, the privileged-access (PAM) tool and the AMSI provider;
- then the installer, which embeds those signed copies.

Windows then shows the publisher (for example "Fenrir-Security") instead of "Unknown publisher". Tampered files are also detectable.

There are two ways to sign:

| Method | Cost | Trusted by Windows out of the box | Notes |
|---|---|---|---|
| **Azure Trusted Signing** (recommended) | about US$10 a month | yes | Microsoft's managed signing service. No certificate file to protect or renew, and signatures build SmartScreen and Defender reputation for your organisation. |
| A `.pfx` certificate | OV/EV certificate from a CA, or free if self-signed | CA-issued: yes. Self-signed: only once installed on each device | Works anywhere, but the key file must be kept safe and renewed. |

When both are set up, Azure Trusted Signing is used.

## Azure Trusted Signing (recommended)

Microsoft may show this service under a newer name ("Artifact Signing"); the steps are the same.

**Who can use it.** Organisations with at least three years of verifiable history in the US, Canada, the EU or the UK
(and individual developers in the US and Canada). Microsoft verifies the organisation's identity once.

**In the Azure portal (once):**

1. Create a **Trusted Signing account** in a supported region and note its endpoint, for example
   `weu.codesigning.azure.net` (West Europe) or `eus.codesigning.azure.net` (East US).
2. In the account, create an **identity validation** of type *Public* for your organisation and wait until it is
   *Completed* (Microsoft may ask for documents).
3. Create a **certificate profile** of type *Public Trust* that uses that identity validation. Note the profile name.
4. In Microsoft Entra ID, create an **app registration** (for example "Fenrir code signing") and give it a client secret.
5. On the certificate profile (Access control (IAM)), give that app the role
   **Trusted Signing Certificate Profile Signer**. It needs no other role.

**On the Fenrir server:**

```
cd ~/AntiVirus
mkdir -p deploy/signing && chmod 700 deploy/signing
cat > deploy/signing/azure-trusted-signing.env <<'ENV'
AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000
AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000
AZURE_CLIENT_SECRET=the-client-secret
TRUSTED_SIGNING_ENDPOINT=weu.codesigning.azure.net
TRUSTED_SIGNING_ACCOUNT=your-account-name
TRUSTED_SIGNING_PROFILE=your-certificate-profile
ENV
chmod 600 deploy/signing/azure-trusted-signing.env
```

Then set `FENRIR_BUILD_PROFILE=production` in `deploy/.env` and rebuild (automatic updates find the file themselves; for
a manual `docker compose build`, also set `FENRIR_CODESIGN_AZURE=./signing/azure-trusted-signing.env` in `deploy/.env`).
`deploy/preflight.sh` checks the file is complete and owner-only.

What happens during the build:
- The credentials are checked before anything is compiled, so a wrong secret stops the build at once with Entra's reason.
- The files are signed with [jsign](https://github.com/ebourg/jsign) (a pinned version, checked against its SHA-256;
  a Java runtime is installed in the build stage when needed). The secret reaches it only through the environment.
- Every file is timestamped by Microsoft's timestamp service. Trusted Signing certificates last three days, so a file
  that cannot be timestamped fails the build rather than ship a signature that would soon stop verifying.
- `build.json` records `"method": "azure-trusted-signing"`. The server does not warn about the certificate's short
  life, and Deploy agents says devices need no certificate installed.
- The installer does not add these certificates to devices' Trusted Publishers store: Windows already trusts them.

The client secret expires (24 months at most). Put a reminder in your calendar, or the next build will stop with
Entra's "invalid client secret" message.

## A .pfx certificate (once, on the server)

```
cd ~/AntiVirus
mkdir -p deploy/signing && chmod 700 deploy/signing
# copy your .pfx to the server as deploy/signing/codesign.pfx (for example with scp from your PC)
chmod 600 deploy/signing/codesign.pfx
printf '%s' 'the-pfx-password' > deploy/signing/codesign.password   # leave empty if it has none
chmod 600 deploy/signing/codesign.password
```

The next rebuild signs everything; automatic updates do this for you. Signing is confirmed in two places:
- The build log shows `sign-windows: signed ...` for each file.
- Deploy agents in the console shows the signer.

How the certificate is kept safe:
- `deploy/signing/` is ignored by git, so the certificate is never committed.
- The build reads it as a BuildKit secret, so it is not stored in the image.
- The extracted key is deleted as soon as signing finishes.

## Build profiles

`FENRIR_BUILD_PROFILE` in `deploy/.env` chooses how the Windows agent is built.

| Profile | Certificate | Result |
|---|---|---|
| `production` (the default for `docker compose`) | required | Everything signed. With no certificate, or a wrong password, the build stops before compiling and says what to fix. |
| `lab` | not used | Agents built unsigned and recorded as `unsigned-lab` in `build.json`. Customers cannot download them unless `FENRIR_ALLOW_UNSIGNED_WINDOWS_INSTALLERS=true` and `FENRIR_WINDOWS_SETUP_SHA256` are set. |

Build the lab profile by hand with the override file, which needs no signing files at all:

```
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.lab.yml --env-file deploy/.env up -d --build
```

Automatic updates (`deploy/auto-update.sh`) follow `FENRIR_BUILD_PROFILE`. When it is not set, a server with a
certificate builds `production` and one without builds `lab`, logging a warning on every run. Set
`FENRIR_BUILD_PROFILE=production` once the certificate is in place, so a missing certificate stops the update
instead of quietly producing unsigned agents.

Signing the user-mode programs does not sign a kernel driver. The real-time protection minifilter needs
Microsoft's driver signing (attestation or WHQL) and is not part of this image yet; see docs/parity/decisions.md.

## Timestamps

Each file is timestamped (DigiCert, then Sectigo) so its signature stays valid after the certificate expires. If neither service can be reached, the file is signed without a timestamp and the console says so. Such files stop verifying once the certificate expires.

## Self-signed certificates: making Windows trust them

**The installer does this for you.** On every install, repair and automatic upgrade, `FenrirSetup.exe`
checks its own signature and adds the certificate that signed it to the local computer's **Trusted
Publishers** store. A self-signed certificate also goes into **Trusted Root Certification Authorities**.
* Only a code-signing certificate that cannot issue other certificates is accepted.
* A changed or badly signed installer adds nothing.
* A full uninstall removes the certificate again.
* Devices installed before this change get it at their next automatic upgrade.

The installer log shows what happened. The steps below are only needed for PCs that should trust Fenrir's
files before the agent is installed, for example to stop the first download being flagged.

A self-signed certificate is only trusted on devices that have it installed. Download it from:
- Deploy agents → Windows → "Download the code-signing certificate";
- or directly at `https://<your server>/downloads/fenrir-codesign.cer`.

Install it in both **Trusted Root Certification Authorities** and **Trusted Publishers** (local computer).

**One PC, as administrator:**

```
certutil -addstore -f Root fenrir-codesign.cer
certutil -addstore -f TrustedPublisher fenrir-codesign.cer
```

**Group Policy:** Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies. Import the certificate into *Trusted Root Certification Authorities* and *Trusted Publishers*.

**Intune:** Devices → Configuration → Create profile → Windows 10 and later → Templates → *Trusted certificate*. Create one profile per store.

**Limits:**
- Until the certificate is trusted (before the first install), Windows shows the file as signed by an untrusted publisher.
- SmartScreen can still warn about new downloads. Its reputation comes from publicly trusted (CA-issued) certificates, especially EV ones.
- A self-signed certificate cannot sign the kernel driver; that needs Microsoft's driver-signing process (see `DRIVER_SIGNING.md`).

## Getting Defender and SmartScreen to trust new builds

Signing tells Windows who made a file; reputation decides whether Defender and SmartScreen trust it. A new publisher,
or a new build of a security agent that hooks processes and watches files, can still be flagged at first. To build
trust:

1. **Sign every build the same way.** Reputation follows the signing identity, and Azure Trusted Signing keeps one
   identity across its short-lived certificates.
2. **Report false positives to Microsoft.** At https://www.microsoft.com/wdsi/filesubmission, choose *Software developer*
   and *Incorrectly detected as malware/malicious*, upload the flagged file (or its SHA-256), and give the detection name
   from Defender's history. Do this for each flagged release; analysts usually answer within a few days, and a cleared
   file is cleared for every Defender customer.
3. **Consider the Microsoft Virus Initiative (MVI)** once Fenrir is sold widely. Members can register as the device's
   antivirus with Windows Security Center and get early access to Defender changes. It needs a signed, certified product
   and an independent test certification (for example AV-TEST or AV-Comparatives).
4. **While you wait,** the agent tells you itself: the Defender self-protection check raises
   `agent.defender.flagged` when Defender detects Fenrir files, and `installer/Repair-FenrirDefender.ps1` restores a
   quarantined agent (see DEVICE_PRESENCE.md).

## Customer installers stay signed

The server adds each customer's enrolment details to the installer when it is downloaded. For signed builds those details go inside the signature's certificate table, which Windows does not hash, so the signature stays valid.

This is the same approach as Chrome's download tags. Devices that turn on Microsoft's optional `EnableCertPaddingCheck` hardening (the CVE-2013-3900 setting, which some hardening guides and scanners recommend) see the downloaded installer as badly signed; it is off by default. On such devices, use the untagged `FenrirSetup.exe` from the server image (`cloud/downloads/windows/` in the container), which keeps a valid signature, and pass the enrolment details on the command line: `FenrirSetup.exe --server https://<your server> --enroll-token <token>`.

## Advice for a .pfx certificate

- Give the .pfx a password, and keep a copy offline.
- It expires on the date in the certificate. Before then, replace `deploy/signing/codesign.pfx` and redeploy the new public certificate to devices.
