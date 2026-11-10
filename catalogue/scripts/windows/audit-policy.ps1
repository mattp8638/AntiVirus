# name: Audit policy
# description: Which security events Windows records (sign-ins, account changes, process creation).
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
auditpol /get /category:* | Out-String
