#!/bin/sh
# name: FileVault status
# description: Whether FileVault disk encryption is on, recorded in a filevault_on field if you created one.
# category: Security
# platforms: macos
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
status="$(fdesetup status)"; echo "$status"
case "$status" in *"is On"*) echo "FENRIR-FIELD filevault_on=true" ;; *) echo "FENRIR-FIELD filevault_on=false" ;; esac
