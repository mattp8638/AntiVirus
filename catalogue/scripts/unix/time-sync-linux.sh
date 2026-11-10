#!/bin/sh
# name: Time sync (Linux)
# description: Whether the clock is synchronised.
# category: Diagnostics
# platforms: linux
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
timedatectl 2>/dev/null || chronyc tracking 2>/dev/null
