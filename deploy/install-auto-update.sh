#!/usr/bin/env bash
# One-time setup: run deploy/auto-update.sh every 10 minutes with systemd.
#   sudo deploy/install-auto-update.sh --stable     # production: the newest release tag vX.Y.Z
#   sudo deploy/install-auto-update.sh --candidate  # staging: release candidates vX.Y.Z-rc.N as well
#   sudo deploy/install-auto-update.sh              # every commit on the main branch
#   sudo deploy/install-auto-update.sh my-branch    # every commit on another branch
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRACK=branch
BRANCH="${1:-main}"
case "$BRANCH" in
  --stable) TRACK=stable; BRANCH=main ;;
  --candidate) TRACK=candidate; BRANCH=main ;;
esac
chmod +x "$DEPLOY_DIR/auto-update.sh"
printf 'FENRIR_DEPLOY_TRACK=%s\nFENRIR_DEPLOY_BRANCH=%s\n' "$TRACK" "$BRANCH" > "$DEPLOY_DIR/auto-update.env"
WHAT="the $BRANCH branch"
[ "$TRACK" = stable ] && WHAT="release tags (vX.Y.Z)"
[ "$TRACK" = candidate ] && WHAT="release and candidate tags (vX.Y.Z, vX.Y.Z-rc.N)"

cat > /etc/systemd/system/fenrir-auto-update.service <<UNIT
[Unit]
Description=Fenrir: pull, rebuild and redeploy when $WHAT change
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$DEPLOY_DIR/auto-update.sh
TimeoutStartSec=2h
UNIT

cat > /etc/systemd/system/fenrir-auto-update.timer <<UNIT
[Unit]
Description=Check for Fenrir updates every 10 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min
Persistent=true

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now fenrir-auto-update.timer
echo "Auto-update enabled: following $WHAT."
echo "  Run now:      sudo systemctl start fenrir-auto-update.service"
echo "  Watch:        sudo tail -f /var/log/fenrir-auto-update.log"
echo "  Turn off:     sudo systemctl disable --now fenrir-auto-update.timer"
