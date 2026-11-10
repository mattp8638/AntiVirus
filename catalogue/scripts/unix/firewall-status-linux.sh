#!/bin/sh
# name: Firewall status (Linux)
# description: ufw, firewalld or nftables status.
# category: Security
# platforms: linux
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
if command -v ufw >/dev/null 2>&1; then ufw status verbose
elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --state && firewall-cmd --list-all
else nft list ruleset 2>/dev/null | head -60; fi
