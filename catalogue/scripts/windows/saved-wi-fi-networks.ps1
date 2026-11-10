# name: Saved Wi-Fi networks
# description: Wi-Fi networks this device remembers (names only, no passwords).
# category: Network
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
netsh wlan show profiles | Select-String 'All User Profile' | ForEach-Object { ($_ -split ':', 2)[1].Trim() }
