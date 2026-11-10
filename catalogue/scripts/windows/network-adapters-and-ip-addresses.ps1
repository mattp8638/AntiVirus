# name: Network adapters and IP addresses
# description: Adapters, link speed, IP addresses, gateways and DNS servers.
# category: Network
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name, InterfaceDescription, LinkSpeed, MacAddress | Format-Table -AutoSize
Get-NetIPConfiguration | Select-Object InterfaceAlias, @{n='IPv4';e={$_.IPv4Address.IPAddress}}, @{n='Gateway';e={$_.IPv4DefaultGateway.NextHop}}, @{n='DNS';e={$_.DNSServer.ServerAddresses -join ', '}} | Format-Table -AutoSize
