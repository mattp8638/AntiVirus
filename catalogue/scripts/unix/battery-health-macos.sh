#!/bin/sh
# name: Battery health (macOS)
# description: Battery condition and cycle count.
# category: Diagnostics
# platforms: macos
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
system_profiler SPPowerDataType | grep -E 'Cycle Count|Condition|Maximum Capacity'
