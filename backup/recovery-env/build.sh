#!/bin/bash
# Build the Fenrir-Backup recovery ISO (design: docs/design/phase-2.md §2).
#
#   sudo recovery-env/build.sh OUT.iso AGENT CLI
#
# AGENT and CLI are the Linux x86_64 fenrir-backup-agent and fenrir-backup
# binaries to put in the image. Needs root, mmdebstrap, squashfs-tools,
# xorriso, mtools and dosfstools, and access to a Debian mirror
# (MIRROR, default https://deb.debian.org/debian). SUITE defaults to stable.
# KEYRING: Debian archive keyring to trust (default: Debian's, fetched and
# checked against a pinned SHA-256).
#
# Output: OUT.iso (hybrid: burn it, or write it to a USB stick byte for
# byte), OUT.iso.packages (every package and version in the image) and
# OUT.iso.sha256.
set -euo pipefail

out=$(realpath -m "$1")
agent=$(realpath "$2")
cli=$(realpath "$3")
here=$(cd "$(dirname "$0")" && pwd)
suite=${SUITE:-stable}
mirror=${MIRROR:-https://deb.debian.org/debian}
mkdir -p "$(dirname "$out")"
work=$(mktemp -d "${TMPDIR:-/tmp}/fenrir-recovery.XXXXXX")
trap 'rm -rf --one-file-system "$work"' EXIT
root=$work/root
iso=$work/iso

packages=$(grep -v '^\s*#' "$here/packages.txt" | xargs | tr ' ' ',')

# Debian's archive keys. Build hosts that are not Debian 13 or later (e.g.
# Ubuntu) lack the current ones, so fetch Debian's keyring package, pinned by
# checksum, unless KEYRING names a keyring to use.
keyring_deb=debian-archive-keyring_2025.1_all.deb
keyring_sha=9ea7778e443144ca490668737a8ab22dd3e748bb99e805e22ec055abeb3c7fac
if [ -z "${KEYRING:-}" ]; then
  curl -fsSL --retry 3 -o "$work/$keyring_deb" "$mirror/pool/main/d/debian-archive-keyring/$keyring_deb"
  echo "$keyring_sha  $work/$keyring_deb" | sha256sum -c --quiet
  dpkg-deb -x "$work/$keyring_deb" "$work/keyring"
  KEYRING=$work/keyring/usr/share/keyrings/debian-archive-keyring.gpg
fi

echo "== root file system ($suite)"
mmdebstrap --mode=root --variant=minbase --keyring="$KEYRING" \
  --components="main non-free-firmware" \
  --include="$packages" \
  --aptopt='APT::Install-Recommends "false"' \
  --dpkgopt='path-exclude=/usr/share/man/*' \
  --dpkgopt='path-exclude=/usr/share/locale/*' \
  --dpkgopt='path-include=/usr/share/locale/locale.alias' \
  --dpkgopt='path-exclude=/usr/share/doc/*' \
  --dpkgopt='path-include=/usr/share/doc/*/copyright' \
  --customize-hook='copy-in '"$here"'/overlay/. /' \
  --customize-hook='upload '"$agent"' /usr/local/bin/fenrir-backup-agent' \
  --customize-hook='upload '"$cli"' /usr/local/bin/fenrir-backup' \
  --customize-hook='chroot "$1" sh -c "chmod 0755 /usr/local/bin/fenrir-backup-agent /usr/local/bin/fenrir-backup /usr/local/sbin/fenrir-console && chmod 0600 /root/.bash_profile"' \
  --customize-hook='chroot "$1" systemctl enable fenrir-recovery-agent.service NetworkManager.service' \
  --customize-hook='echo fenrir-recovery > "$1/etc/hostname"' \
  --customize-hook='printf "127.0.0.1 localhost\n127.0.1.1 fenrir-recovery\n" > "$1/etc/hosts"' \
  --customize-hook='chroot "$1" passwd --lock root' \
  --customize-hook='rm -f "$1"/etc/machine-id "$1"/var/lib/dbus/machine-id && : > "$1/etc/machine-id"' \
  --customize-hook='chroot "$1" dpkg-query -W -f "\${Package}\t\${Version}\t\${source:Package}\n" > "$1/usr/share/fenrir-packages.tsv"' \
  "$suite" "$root" "$mirror"

echo "== live file system"
mkdir -p "$iso/live" "$iso/boot/grub" "$iso/fenrir" "$iso/.disk" "$iso/EFI/BOOT"
cp "$root/usr/share/fenrir-packages.tsv" "$out.packages"
kernel=$(ls "$root"/boot/vmlinuz-* | sort -V | tail -1)
initrd=$(ls "$root"/boot/initrd.img-* | sort -V | tail -1)
cp "$kernel" "$iso/live/vmlinuz"
cp "$initrd" "$iso/live/initrd.img"
shim=$root/usr/lib/shim/shimx64.efi.signed
mm=$root/usr/lib/shim/mmx64.efi.signed
grubcd=$root/usr/lib/grub/x86_64-efi-signed/gcdx64.efi.signed
for f in "$shim" "$mm" "$grubcd"; do
  [ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
done
# BIOS El Torito image and the hybrid MBR, made with the image's own GRUB.
chroot "$root" grub-mkimage -O i386-pc-eltorito -p /boot/grub -o /tmp/eltorito.img \
  biosdisk iso9660 part_msdos part_gpt normal search search_fs_file configfile linux echo test all_video gfxterm
mkdir -p "$iso/boot/grub/i386-pc"
cp "$root/tmp/eltorito.img" "$iso/boot/grub/i386-pc/eltorito.img"
cp "$root"/usr/lib/grub/i386-pc/*.mod "$root"/usr/lib/grub/i386-pc/*.lst "$iso/boot/grub/i386-pc/"
cp "$root/usr/lib/grub/i386-pc/boot_hybrid.img" "$work/boot_hybrid.img"
mksquashfs "$root" "$iso/live/filesystem.squashfs" -comp zstd -Xcompression-level 15 -noappend -quiet \
  -e boot -e tmp/eltorito.img -e var/cache/apt -e var/lib/apt/lists

echo "== boot files"
echo "Fenrir-Backup recovery ($suite, $(date -u +%Y-%m-%d))" > "$iso/.disk/info"
cp "$here/grub.cfg" "$iso/boot/grub/grub.cfg"
# The personalisation block (protocol::recovery): marker, then spaces.
python3 -c 'import sys; b=b"FENRIR-RECOVERY-CONFIG-V1\n"; sys.stdout.buffer.write(b + b" " * (4096 - len(b)))' > "$iso/fenrir/recovery.json"
# Signed chain for UEFI with Secure Boot: shim → Debian's CD GRUB, which finds
# /.disk/info and reads /boot/grub/grub.cfg.
cp "$shim" "$iso/EFI/BOOT/BOOTX64.EFI"
cp "$grubcd" "$iso/EFI/BOOT/grubx64.efi"
cp "$mm" "$iso/EFI/BOOT/mmx64.efi"
efi=$work/efiboot.img
mkfs.vfat -C -n FENRIR_EFI "$efi" 8192 >/dev/null
mmd -i "$efi" ::/EFI ::/EFI/BOOT
mcopy -i "$efi" "$iso/EFI/BOOT/BOOTX64.EFI" "$iso/EFI/BOOT/grubx64.efi" "$iso/EFI/BOOT/mmx64.efi" ::/EFI/BOOT/
printf 'search --file --set=root /.disk/info\nset prefix=($root)/boot/grub\nconfigfile $prefix/grub.cfg\n' > "$work/efi-grub.cfg"
mcopy -i "$efi" "$work/efi-grub.cfg" ::/EFI/BOOT/grub.cfg

echo "== ISO"
xorriso -as mkisofs -iso-level 3 -full-iso9660-filenames -joliet -joliet-long -rational-rock \
  -volid FENRIR_RECOVERY \
  --grub2-mbr "$work/boot_hybrid.img" -partition_offset 16 \
  -eltorito-boot boot/grub/i386-pc/eltorito.img -no-emul-boot -boot-load-size 4 -boot-info-table --grub2-boot-info \
  -eltorito-alt-boot -e --interval:appended_partition_2:all:: -no-emul-boot \
  -append_partition 2 0xef "$efi" -appended_part_as_gpt \
  -output "$out" "$iso" 2>&1 | grep -v '^xorriso : UPDATE' || true
[ -s "$out" ] || { echo "no ISO written" >&2; exit 1; }
(cd "$(dirname "$out")" && sha256sum "$(basename "$out")" > "$out.sha256")
echo "== $(du -h "$out" | cut -f1) $out"
