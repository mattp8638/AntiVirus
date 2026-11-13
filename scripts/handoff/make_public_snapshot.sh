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
# This script names the private words it looks for, so it stays in the development repository.
rm -f "$out/scripts/handoff/make_public_snapshot.sh"
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

# A neutral template: no owner names, and identifiers each fork sets for itself (see FORKING.md).
python3 - "$out" <<'PY'
import pathlib, re, shutil, sys
root = pathlib.Path(sys.argv[1])
notice = root / "NOTICE"
notice.write_text(re.sub(r"Copyright (\d{4}) .*? and the Fenrir contributors", r"Copyright \1 The Fenrir contributors", notice.read_text()))
owners = root / ".github" / "CODEOWNERS"
if owners.exists():
    owners.write_text("# Who must review changes to which paths. Add your own GitHub users or teams, for example:\n"
                      "# *                @your-org/maintainers\n# /deploy/         @your-org/maintainers\n")
# The Android app ID and the Apple profile ID were the original deployment's: use a placeholder forks replace.
old_pkg, new_pkg = "uk.co.fenrirsecurity", "com.example.fenrir"
for java in root.glob("agent/android/app/src/*/java"):
    src = java / "uk" / "co" / "fenrirsecurity"
    if src.is_dir():
        dest = java / "com" / "example" / "fenrir"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dest))
        shutil.rmtree(java / "uk", ignore_errors=True)
for path in root.rglob("*"):
    if path.is_file() and path.suffix in {".kt", ".kts", ".xml", ".pro", ".md", ".py", ".json", ".yml", ".ts", ".tsx"}:
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        if old_pkg in text:
            path.write_text(text.replace(old_pkg, new_pkg))
PY

git -C "$out" init -q
git -C "$out" add -A
python3 "$out/scripts/handoff/public_check.py" --strict \
  --private "mattp8638,mjrpalmer,pmadmin,vmi3694088,Pete-Desktop,Matthew Palmer,PM-DC${private:+,$private}" \
  || { echo "The snapshot still contains private names or built-in addresses (above). Nothing was committed." >&2; exit 1; }
# The check has passed: blank its built-in word list, which names the original owner, in the published copy.
sed -i 's/^BUILT_IN_PRIVATE = .*/BUILT_IN_PRIVATE: list[str] = []  # add the names you must not publish/' "$out/scripts/handoff/public_check.py"
sed -i 's/^STATIC = .*/STATIC: list[str] = []  # addresses of services you no longer run/' "$out/scripts/handoff/public_check.py"
git -C "$out" add -A
echo
echo "Public copy ready in $out ($(git -C "$out" ls-files | wc -l) files, no history)."
