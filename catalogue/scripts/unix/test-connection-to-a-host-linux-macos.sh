#!/bin/sh
# name: Test connection to a host (Linux/macOS)
# description: DNS lookup, ping and a TCP port test.
# category: Network
# platforms: linux, macos
# timeout: 300
# param: Target | Host | string | example.com | required
# param: Port | TCP port | number | 443 | required
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
echo "--- DNS ---"; (host "$Target" 2>/dev/null || nslookup "$Target")
echo "--- Ping ---"; ping -c 3 "$Target"
echo "--- TCP $Port ---"; if nc -z -w 5 "$Target" "$Port" 2>/dev/null; then echo "port $Port open"; else echo "port $Port closed or filtered"; fi
