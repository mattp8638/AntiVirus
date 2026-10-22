#!/bin/sh
# MinGW ships lower-case Windows SDK headers (windows.h); the sources use MSVC
# spelling (Windows.h). On case-sensitive file systems, generate forwarding
# headers so the agent cross-compiles from Linux without touching the sources.
#   agent/windows/cmake/make-mingw-header-shims.sh <out-dir>
set -eu
OUT=${1:?output dir}
SYSROOT=${MINGW_SYSROOT:-/usr/x86_64-w64-mingw32/include}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$OUT"
grep -rhoE '#include[[:space:]]*<[A-Za-z0-9_./]+>' "$ROOT" --include=*.cpp --include=*.h --include=*.c --include=*.rc \
  | sed -E 's/.*<([^>]+)>/\1/' | sort -u | while read -r h; do
  [ -e "$SYSROOT/$h" ] && continue
  lower=$(printf '%s' "$h" | tr 'A-Z' 'a-z')
  if [ -e "$SYSROOT/$lower" ]; then
    mkdir -p "$OUT/$(dirname "$h")"
    printf '#include <%s>\n' "$lower" > "$OUT/$h"
  fi
done
echo "header shims in $OUT"
