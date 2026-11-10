# name: Driver versions
# description: Display, network and storage drivers with version and date.
# category: Inventory
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceClass -in 'DISPLAY','NET','SCSIADAPTER','HDC' } | Select-Object DeviceClass, DeviceName, DriverVersion, DriverDate | Sort-Object DeviceClass | Format-Table -AutoSize | Out-String -Width 250
