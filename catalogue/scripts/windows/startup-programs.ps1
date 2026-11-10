# name: Startup programs
# description: Programs that start automatically with Windows.
# category: Performance
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-Table -AutoSize | Out-String -Width 250
