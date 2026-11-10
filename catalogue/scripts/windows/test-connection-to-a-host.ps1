# name: Test connection to a host
# description: Ping, DNS lookup and a TCP port test to a host.
# category: Network
# platforms: windows
# timeout: 300
# param: Target | Host | string | microsoft.com | required
# param: Port | TCP port | number | 443 | required
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Resolve-DnsName -Name $Target -ErrorAction SilentlyContinue | Select-Object Name, Type, IPAddress | Format-Table -AutoSize
Test-NetConnection -ComputerName $Target -Port ([int]$Port) | Format-List ComputerName, RemoteAddress, PingSucceeded, TcpTestSucceeded
