# name: Public IP address
# description: The device's public internet address as other sites see it.
# category: Network
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
try { (Invoke-RestMethod -UseBasicParsing -Uri 'https://api.ipify.org?format=json' -TimeoutSec 10).ip } catch { "Could not reach the lookup service: $($_.Exception.Message)" }
