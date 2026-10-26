#!/usr/bin/env bash
# One-time setup: run deploy/auto-update.sh every 10 minutes with systemd.
#   sudo deploy/install-auto-update.sh            # follow the main branch
#   sudo deploy/install-auto-update.sh my-branch  # follow another branch
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANCH="${1:-main}"
chmod +x "$DEPLOY_DIR/auto-update.sh"
printf 'FENRIR_DEPLOY_BRANCH=%s\n' "$BRANCH" > "$DEPLOY_DIR/auto-update.env"

cat > /etc/systemd/system/fenrir-auto-update.service <<UNIT
[Unit]
Description=Fenrir: pull, rebuild and redeploy when the $BRANCH branch changes
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
echo "Auto-update enabled for branch '$BRANCH'."
echo "  Run now:      sudo systemctl start fenrir-auto-update.service"
echo "  Watch:        sudo tail -f /var/log/fenrir-auto-update.log"
echo "  Turn off:     sudo systemctl disable --now fenrir-auto-update.timer"
