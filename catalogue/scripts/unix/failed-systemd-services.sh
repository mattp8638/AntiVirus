#!/bin/sh
# name: Failed systemd services
# description: Services that failed to start.
# category: Services
# platforms: linux
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
systemctl --failed --no-pager
