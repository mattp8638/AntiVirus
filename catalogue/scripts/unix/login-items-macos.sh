#!/bin/sh
# name: Login items (macOS)
# description: Launch agents and daemons that start automatically.
# category: Security
# platforms: macos
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
ls -la /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null
for home in /Users/*; do [ -d "$home/Library/LaunchAgents" ] && { echo "--- $home"; ls "$home/Library/LaunchAgents"; }; done
