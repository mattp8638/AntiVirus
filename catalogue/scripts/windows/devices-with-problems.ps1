# name: Devices with problems
# description: Hardware Device Manager reports as not working.
# category: Diagnostics
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-PnpDevice -PresentOnly | Where-Object Status -ne 'OK' | Select-Object Class, FriendlyName, Status, InstanceId | Format-Table -AutoSize | Out-String -Width 250
