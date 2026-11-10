#!/bin/sh
# name: Recent errors in the journal
# description: Error-level messages from the last 24 hours.
# category: Diagnostics
# platforms: linux
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
journalctl -p err --since '24 hours ago' --no-pager | tail -60
