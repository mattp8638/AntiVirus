#!/bin/sh
# name: Gatekeeper and SIP status
# description: Whether Gatekeeper and System Integrity Protection are on.
# category: Security
# platforms: macos
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
spctl --status; csrutil status
