#!/bin/sh
# name: Top processes (Linux/macOS)
# description: Busiest processes by CPU and memory.
# category: Performance
# platforms: linux, macos
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
echo '--- CPU ---'; ps -eo pid,user,%cpu,%mem,comm -r 2>/dev/null | head -11 || ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu | head -11
echo '--- Memory ---'; ps -eo pid,user,%mem,rss,comm -m 2>/dev/null | head -11 || ps -eo pid,user,%mem,rss,comm --sort=-%mem | head -11
