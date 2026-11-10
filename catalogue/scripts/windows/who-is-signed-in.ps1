# name: Who is signed in
# description: Users signed in to this device right now (console and remote).
# category: Users
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
quser 2>&1 | Out-String
