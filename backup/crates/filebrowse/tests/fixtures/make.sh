#!/bin/sh
# Regenerate the file system fixtures used by tests/browse.rs (needs root,
# ntfs-3g, e2fsprogs and zstd). The same tree goes into both volumes.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'umount "$work/m" 2>/dev/null || true; rm -rf "$work"' EXIT

tree="$work/tree"
mkdir -p "$tree/Users/anna/Documents/Sub Folder" "$tree/Users/anna/Pictures"
printf 'quarterly report\n' > "$tree/Users/anna/Documents/report.txt"
printf '# notes\nremember the milk\n' > "$tree/Users/anna/Documents/Sub Folder/notes.md"
printf 'unicode\n' > "$tree/Users/anna/Documents/Ünïcode ✓.txt"
# 3 MiB spanning several 1 MiB image chunks (non-resident on NTFS).
python3 -c "import sys; sys.stdout.buffer.write(bytes((i*31 + i//4096) % 251 for i in range(3*1024*1024)))" > "$tree/Users/anna/Pictures/big.bin"
touch -d '2026-03-04 05:06:07 UTC' "$tree/Users/anna/Documents/report.txt"

truncate -s 16M "$work/ntfs.img"
mkntfs -F -Q -q -L DATA "$work/ntfs.img" >/dev/null 2>&1
mkdir "$work/m"
ntfs-3g "$work/ntfs.img" "$work/m"
cp -a "$tree/." "$work/m/"
umount "$work/m"

# ext gets a symlink too (listed as a link, never followed or restored).
ln -s Documents/report.txt "$tree/Users/anna/link"
truncate -s 16M "$work/ext4.img"
mke2fs -q -t ext4 -L data -d "$tree" "$work/ext4.img"

zstd -q -19 -f "$work/ntfs.img" -o "$here/ntfs.img.zst"
zstd -q -19 -f "$work/ext4.img" -o "$here/ext4.img.zst"
ls -l "$here"
