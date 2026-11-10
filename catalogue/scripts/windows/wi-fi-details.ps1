# name: Wi-Fi details
# description: The Wi-Fi network, signal strength and channel.
# category: Network
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
netsh wlan show interfaces | Out-String
