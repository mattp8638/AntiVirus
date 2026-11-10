#!/bin/sh
# name: SSH server settings
# description: Whether SSH allows root login and password authentication.
# category: Security
# platforms: linux
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|port) ' || grep -hE '^(PermitRootLogin|PasswordAuthentication|Port)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
