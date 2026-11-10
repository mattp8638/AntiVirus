# name: USB storage history
# description: USB storage devices that have been connected to this computer.
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' -ErrorAction SilentlyContinue | ForEach-Object { (Get-ItemProperty $_.PSPath).FriendlyName } | Sort-Object -Unique
