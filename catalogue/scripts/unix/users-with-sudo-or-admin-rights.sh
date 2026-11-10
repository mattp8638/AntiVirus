#!/bin/sh
# name: Users with sudo or admin rights
# description: Accounts that can become root or administrator.
# category: Security
# platforms: linux, macos
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
if [ "$(uname -s)" = Darwin ]; then dscl . -read /Groups/admin GroupMembership
else getent group sudo wheel admin 2>/dev/null; grep -hvE '^\s*(#|$|Defaults)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; fi
