#!/bin/sh
# name: Installed applications (macOS)
# description: Applications in /Applications with their versions.
# category: Inventory
# platforms: macos
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
for app in /Applications/*.app; do
  v=$(defaults read "$app/Contents/Info" CFBundleShortVersionString 2>/dev/null); echo "$(basename "$app" .app)	${v:-?}"
done
