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

Without a certificate, the build is unsigned, as before.

## Timestamps

Each file is timestamped (DigiCert, then Sectigo) so its signature stays valid after the certificate expires. If neither service can be reached, the file is signed without a timestamp and the console says so. Such files stop verifying once the certificate expires.

## Self-signed certificates: making Windows trust them

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
- Until the certificate is trusted, Windows shows the file as signed by an untrusted publisher.
- SmartScreen can still warn about new downloads. Its reputation comes from publicly trusted (CA-issued) certificates, especially EV ones.
- A self-signed certificate cannot sign the kernel driver; that needs Microsoft's driver-signing process (see `DRIVER_SIGNING.md`).

## Customer installers stay signed

The server adds each customer's enrolment details to the installer when it is downloaded. For signed builds those details go inside the signature's certificate table, which Windows does not hash, so the signature stays valid.

This is the same approach as Chrome's download tags. Devices that turn on Microsoft's optional `EnableCertPaddingCheck` hardening reject this; it is off by default.

## Advice for the certificate

- Give the .pfx a password, and keep a copy offline.
- It expires on the date in the certificate. Before then, replace `deploy/signing/codesign.pfx` and redeploy the new public certificate to devices.
