#!/bin/sh
# name: Disk space (Linux/macOS)
# description: Free space on mounted file systems.
# category: Disk
# platforms: linux, macos
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
df -h | grep -vE '^(tmpfs|devtmpfs|overlay|map |devfs)'
