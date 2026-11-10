# name: Update Microsoft 365 Apps
# description: Starts a Microsoft 365 Apps update now.
# category: Applications
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
$c2r = "$env:CommonProgramFiles\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
if (Test-Path $c2r) { & $c2r /update user displaylevel=false forceappshutdown=false; 'Office update started.' } else { 'Microsoft 365 Apps (Click-to-Run) is not installed.' }
