#!/usr/bin/env bash
# Reproducible packaging check (AGT-09): the Linux and macOS agents are built twice, from two copies of the
# source in different directories with separate build caches, using the release build's flags. The binaries must
# be byte-identical, so anyone can rebuild a release from its tag and compare the published SHA-256.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
pkg=github.com/AntiVirus/agent/linux/pkg/fleet
ldflags="-s -w -X $pkg.BuildID=reproducible -X $pkg.ReleaseSeq=1 -X $pkg.ReleasePublicKeys="
for copy in a b; do
  mkdir -p "$work/$copy"
  cp -r "$root/agent/linux" "$work/$copy/src"
done
status=0
for target in linux/amd64 linux/arm64 darwin/arm64; do
  os=${target%/*}; arch=${target#*/}
  for copy in a b; do
    (cd "$work/$copy/src" && GOCACHE="$work/$copy/cache" CGO_ENABLED=0 GOOS=$os GOARCH=$arch \
      go build -trimpath -ldflags "$ldflags" -o "$work/$copy/agent-$os-$arch" ./cmd/fenrir-agent)
  done
  a=$(sha256sum "$work/a/agent-$os-$arch" | cut -d' ' -f1)
  b=$(sha256sum "$work/b/agent-$os-$arch" | cut -d' ' -f1)
  if [ "$a" = "$b" ]; then echo "reproducible $os/$arch $a"; else echo "::error::$os/$arch differs: $a vs $b"; status=1; fi
done
exit $status
