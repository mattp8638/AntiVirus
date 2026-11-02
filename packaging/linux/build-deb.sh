#!/bin/sh
# Build fenrir-agent .deb packages from dist/linux binaries.
#   make -C agent/linux agent agent-arm64 && packaging/linux/build-deb.sh 1.0.0
set -eu
VERSION=${1:-1.0.0}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT="$ROOT/dist/packages"
mkdir -p "$OUT"
for ARCH in amd64 arm64; do
  BIN="$ROOT/dist/linux/fenrir-agent-linux-$ARCH"
  [ -f "$BIN" ] || { echo "missing $BIN"; exit 1; }
  PKG=$(mktemp -d)
  install -D -m 0755 "$BIN" "$PKG/usr/local/bin/fenrir-agent"
  install -D -m 0644 "$ROOT/agent/linux/systemd/fenrir-agent.service" "$PKG/lib/systemd/system/fenrir-agent.service"
  mkdir -p "$PKG/DEBIAN" "$PKG/etc/fenrir"
  cat > "$PKG/DEBIAN/control" <<CTRL
Package: fenrir-agent
Version: $VERSION
Architecture: $ARCH
Maintainer: Palmertech <support@palmertech.example>
Depends: nftables
Section: admin
Priority: optional
Description: Fenrir endpoint protection agent
 Managed anti-malware, EDR telemetry, ransomware canaries and network
 isolation for Linux, controlled from Fenrir Cloud.
CTRL
  cat > "$PKG/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
mkdir -p /var/lib/fenrir && chmod 700 /var/lib/fenrir
if [ ! -f /etc/fenrir/agent.env ]; then
  umask 077
  printf 'FENRIR_SERVER=%s\nFENRIR_ENROLLMENT_TOKEN=%s\nFENRIR_STATE_DIR=/var/lib/fenrir\n' "${FENRIR_SERVER:-}" "${FENRIR_TOKEN:-}" > /etc/fenrir/agent.env
fi
systemctl daemon-reload || true
if grep -q '^FENRIR_SERVER=.\+' /etc/fenrir/agent.env; then systemctl enable --now fenrir-agent || true;
else echo "Edit /etc/fenrir/agent.env then: systemctl enable --now fenrir-agent"; fi
POST
  cat > "$PKG/DEBIAN/prerm" <<'PRE'
#!/bin/sh
systemctl disable --now fenrir-agent 2>/dev/null || true
nft delete table inet fenrir_isolation 2>/dev/null || true
PRE
  chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm"
  dpkg-deb --root-owner-group --build "$PKG" "$OUT/fenrir-agent_${VERSION}_${ARCH}.deb" >/dev/null
  rm -rf "$PKG"
  echo "built $OUT/fenrir-agent_${VERSION}_${ARCH}.deb"
done
