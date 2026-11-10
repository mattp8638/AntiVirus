# name: Mapped drives
# description: Network drives mapped for each signed-in user.
# category: Network
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { Test-Path "$($_.PSPath)\Network" } | ForEach-Object {
  $sid = $_.PSChildName
  Get-ChildItem "$($_.PSPath)\Network" | ForEach-Object { [pscustomobject]@{ User = $sid; Drive = $_.PSChildName; Path = (Get-ItemProperty $_.PSPath).RemotePath } }
} | Format-Table -AutoSize
