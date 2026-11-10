#!/bin/sh
# name: Network configuration (Linux/macOS)
# description: Interfaces, addresses, default route and DNS servers.
# category: Network
# platforms: linux, macos
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
if command -v ip >/dev/null 2>&1; then ip -brief address; ip route | grep default; else ifconfig | grep -E '^[a-z]|inet '; netstat -rn | grep default; fi
echo '--- DNS ---'; (scutil --dns 2>/dev/null | grep nameserver | sort -u) || grep nameserver /etc/resolv.conf
