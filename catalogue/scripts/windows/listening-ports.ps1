# name: Listening ports
# description: Programs listening for network connections, with their ports.
# category: Network
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} | Sort-Object LocalPort | Format-Table -AutoSize
