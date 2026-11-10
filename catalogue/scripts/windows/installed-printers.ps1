# name: Installed printers
# description: Printers, their drivers and ports.
# category: Printers
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-Printer | Select-Object Name, DriverName, PortName, Shared, Default | Format-Table -AutoSize | Out-String -Width 250
