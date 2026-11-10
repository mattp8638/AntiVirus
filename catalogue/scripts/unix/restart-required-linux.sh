#!/bin/sh
# name: Restart required? (Linux)
# description: Whether the system needs a restart after updates.
# category: Updates
# platforms: linux
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
if [ -f /var/run/reboot-required ]; then echo 'Restart required:'; cat /var/run/reboot-required.pkgs 2>/dev/null
elif command -v needs-restarting >/dev/null 2>&1; then needs-restarting -r; else echo 'No restart flagged.'; fi
