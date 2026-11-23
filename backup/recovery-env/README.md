# recovery-env

Build scripts for the Fenrir-Backup recovery media (design:
[docs/design/phase-2.md](../docs/design/phase-2.md)).

* `build.sh`: builds `fenrir-recovery.iso`, a Debian stable live system
  for x86_64 that boots with UEFI (Secure Boot on, through Debian's
  Microsoft-signed shim, signed GRUB and signed kernel) and legacy BIOS. It
  holds `fenrir-backup-agent` and `fenrir-backup`, starts the agent in
  recovery mode, and shows a menu on the screen (`fenrir-console`).
* `packages.txt`: the Debian packages in the image.
* `overlay/`: files added to the image (the agent service, the console,
  automatic login on the first screen only).
* `grub.cfg`: the boot menu.

Windows PE media (design §6) is not available yet: restoring from Windows
needs the target disk's volumes locked and dismounted first, which the
agent does not do yet.

```bash
cargo build --release -p agent -p cli --target x86_64-unknown-linux-musl
sudo recovery-env/build.sh out/fenrir-recovery.iso \
  target/x86_64-unknown-linux-musl/release/fenrir-backup-agent \
  target/x86_64-unknown-linux-musl/release/fenrir-backup
```

Needs root, `mmdebstrap`, `squashfs-tools`, `xorriso`, `mtools`,
`dosfstools` and access to a Debian mirror (`MIRROR=`). On hosts without
Debian 13's archive keys (e.g. Ubuntu), the script fetches Debian's
keyring package and checks it against a pinned SHA-256. About 3 minutes;
the ISO is about 310 MB.

The ISO contains a 4 KiB placeholder, `/fenrir/recovery.json`. The
server fills it in when a user downloads the ISO from the web UI, so the
stick finds the server by itself (`protocol::recovery`).

## Licences

This directory is not a Cargo crate. It assembles an image from Debian
packages, many under the GPL or other copyleft licences, which is allowed
here and only here (see `THIRD_PARTY.md` at the top of the repository).
Nothing from these packages is linked into Fenrir-Backup's own programs.

Every build writes `fenrir-recovery.iso.packages`: the name, exact version
and source package of everything in the image. Their licences are in the
image under `/usr/share/doc/<package>/copyright`, and the corresponding
source is available from Debian (`apt-get source <package>=<version>`, or
snapshot.debian.org for older versions). Firmware packages from Debian's
`non-free-firmware` component are redistributable under their own licences,
also in their `copyright` files.
