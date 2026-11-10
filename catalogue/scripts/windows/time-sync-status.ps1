# name: Time sync status
# description: Windows Time source and last successful sync; resyncs now.
# category: Diagnostics
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
w32tm /query /status | Out-String
w32tm /resync /force | Out-String
