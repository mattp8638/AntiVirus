#!/bin/sh
# name: macOS firewall status
# description: Application firewall and stealth mode.
# category: Security
# platforms: macos
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate --getstealthmode
