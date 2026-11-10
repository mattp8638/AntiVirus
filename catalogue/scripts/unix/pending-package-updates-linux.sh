#!/bin/sh
# name: Pending package updates (Linux)
# description: Packages with updates available (apt, dnf or zypper).
# category: Updates
# platforms: linux
# timeout: 900
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
if command -v apt-get >/dev/null 2>&1; then apt-get -s upgrade 2>/dev/null | grep -E '^Inst' | cut -d' ' -f2 | sort
elif command -v dnf >/dev/null 2>&1; then dnf -q check-update || true
elif command -v zypper >/dev/null 2>&1; then zypper -q list-updates; fi
[ -f /var/run/reboot-required ] && echo 'A restart is required.'
