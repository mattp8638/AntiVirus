#!/bin/sh
# name: Largest directories
# description: The 20 largest directories under a path.
# category: Disk
# platforms: linux, macos
# timeout: 1800
# param: Path | Directory | string | /var | optional
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
du -xh "${Path:-/}" 2>/dev/null | sort -rh | head -20
