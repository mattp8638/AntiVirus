# name: Stop a service
# description: Stops a Windows service (changes the system).
# category: Services
# platforms: windows
# timeout: 300
# param: ServiceName | Service name | string |  | required
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Stop-Service -Name $ServiceName -Force -ErrorAction Stop; Get-Service -Name $ServiceName | Format-List Name, Status
