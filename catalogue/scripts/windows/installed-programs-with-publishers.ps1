# name: Installed programs with publishers
# description: Every installed program (32 and 64-bit) with version and publisher.
# category: Inventory
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
  Sort-Object DisplayName -Unique | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize | Out-String -Width 250
