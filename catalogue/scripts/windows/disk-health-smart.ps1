# name: Disk health (SMART)
# description: Physical disk health and wear reported by Windows storage.
# category: Disk
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus, @{n='SizeGB';e={[math]::Round($_.Size/1GB)}} | Format-Table -AutoSize
Get-PhysicalDisk | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue | Select-Object DeviceId, Temperature, Wear, ReadErrorsTotal, WriteErrorsTotal | Format-Table -AutoSize
