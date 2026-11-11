#!/usr/bin/env bash
# Build the public copy of this repository: the committed files only, without the private component snapshots and
# without any history, checked for private names before anything is written out.
#
#   scripts/handoff/make_public_snapshot.sh <empty output folder> [--private "word1,word2"]
#
# Then either push the folder as a new repository, or copy its contents over a checkout of the public repository and
# commit them there (one commit that replaces everything).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="${1:-}"; shift || true
private=""
while [ $# -gt 0 ]; do case "$1" in --private) private="${2:-}"; shift 2 ;; *) echo "unknown option $1" >&2; exit 2 ;; esac; done
[ -n "$out" ] || { echo "usage: $0 <empty output folder> [--private words]" >&2; exit 2; }
[ ! -e "$out" ] || [ -z "$(ls -A "$out")" ] || { echo "$out is not empty" >&2; exit 2; }
git -C "$root" diff --quiet HEAD -- || { echo "commit your changes first: the snapshot is built from HEAD" >&2; exit 2; }

mkdir -p "$out"
git -C "$root" archive --format=tar HEAD | tar -x -C "$out"
# Snapshots of other private repositories, kept only for reference in the development repository.
rm -rf "$out/components"
# Internal evidence pages link to CI runs of the development repository: keep the text, drop those links.
python3 - "$out" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
link = re.compile(r"\[([^\]]+)\]\(https://github\.com/mattp8638/AntiVirus[^)]*\)")
bare = re.compile(r"https://github\.com/mattp8638/AntiVirus[^\s)\]|,\"]*")
for path in (root / "docs" / "parity").glob("*"):
    if path.is_file():
        text = path.read_text()
        new = bare.sub("(development repository)", link.sub(r"\1", text))
        if new != text:
            path.write_text(new)
PY

git -C "$out" init -q
git -C "$out" add -A
python3 "$out/scripts/handoff/public_check.py" --strict \
  --private "mattp8638,mjrpalmer,pmadmin,vmi3694088,Pete-Desktop${private:+,$private}" \
  || { echo "The snapshot still contains private names or built-in addresses (above). Nothing was committed." >&2; exit 1; }
echo
echo "Public copy ready in $out ($(git -C "$out" ls-files | wc -l) files, no history)."
