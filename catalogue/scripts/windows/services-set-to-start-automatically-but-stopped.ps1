# name: Services set to start automatically but stopped
# description: Automatic services that are not running.
# category: Services
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" | Select-Object Name, DisplayName, State, ExitCode | Format-Table -AutoSize
