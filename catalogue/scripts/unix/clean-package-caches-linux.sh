#!/bin/sh
# name: Clean package caches (Linux)
# description: Removes cached package files and unused dependencies (changes the system).
# category: Maintenance
# platforms: linux
# timeout: 1800
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
if command -v apt-get >/dev/null 2>&1; then apt-get clean && apt-get -y autoremove
elif command -v dnf >/dev/null 2>&1; then dnf clean all && dnf -y autoremove; fi
journalctl --vacuum-time=14d 2>/dev/null
df -h /
