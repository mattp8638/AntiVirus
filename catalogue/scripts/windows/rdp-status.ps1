# name: RDP status
# description: Whether Remote Desktop is enabled, Network Level Authentication is required, and who may connect.
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
$ts = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
$nla = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
"RDP enabled: $($ts.fDenyTSConnections -eq 0)   NLA required: $($nla.UserAuthentication -eq 1)   Port: $($nla.PortNumber)"
Get-LocalGroupMember -SID 'S-1-5-32-555' -ErrorAction SilentlyContinue | Select-Object Name | Format-Table -AutoSize
