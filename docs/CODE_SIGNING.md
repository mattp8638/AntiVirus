# Windows code signing

The server signs every Fenrir Windows program during its image build:
- the service, the agent window, the remote helper, the privileged-access (PAM) tool and the AMSI provider;
- then the installer, which embeds those signed copies.

Windows then shows the publisher (for example "Fenrir-Security") instead of "Unknown publisher". Tampered files are also detectable.

## Setting it up (once, on the server)

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

## Customer installers stay signed

The server adds each customer's enrolment details to the installer when it is downloaded. For signed builds those details go inside the signature's certificate table, which Windows does not hash, so the signature stays valid.

This is the same approach as Chrome's download tags. Devices that turn on Microsoft's optional `EnableCertPaddingCheck` hardening reject this; it is off by default.

## Advice for the certificate

- Give the .pfx a password, and keep a copy offline.
- It expires on the date in the certificate. Before then, replace `deploy/signing/codesign.pfx` and redeploy the new public certificate to devices.
