# name: Start a service
# description: Starts a Windows service.
# category: Services
# platforms: windows
# timeout: 300
# param: ServiceName | Service name | string |  | required
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Start-Service -Name $ServiceName -ErrorAction Stop; Get-Service -Name $ServiceName | Format-List Name, Status
