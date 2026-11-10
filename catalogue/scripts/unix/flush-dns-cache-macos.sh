#!/bin/sh
# name: Flush DNS cache (macOS)
# description: Clears the macOS DNS cache.
# category: Network
# platforms: macos
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
dscacheutil -flushcache; killall -HUP mDNSResponder; echo 'DNS cache flushed.'
