#!/bin/sh
# name: macOS updates available
# description: Software updates waiting for this Mac.
# category: Updates
# platforms: macos
# timeout: 900
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
softwareupdate --list 2>&1
