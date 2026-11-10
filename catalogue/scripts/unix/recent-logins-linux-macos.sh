#!/bin/sh
# name: Recent logins (Linux/macOS)
# description: The last 30 logins and failed SSH attempts.
# category: Security
# platforms: linux, macos
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
last -n 30 2>/dev/null | head -30
echo '--- Failed SSH logins (last 24 hours) ---'
if command -v journalctl >/dev/null 2>&1; then journalctl -u ssh -u sshd --since '24 hours ago' 2>/dev/null | grep -c 'Failed password'; fi
