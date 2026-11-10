#!/bin/sh
# name: Listening ports (Linux/macOS)
# description: Programs listening for network connections.
# category: Network
# platforms: linux, macos
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
if command -v ss >/dev/null 2>&1; then ss -tulpn; else lsof -nP -iTCP -sTCP:LISTEN; fi
