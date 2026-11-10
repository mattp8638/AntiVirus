# name: Cancel a scheduled restart
# description: Cancels a restart scheduled with shutdown /r.
# category: Maintenance
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
shutdown.exe /a; if ($LASTEXITCODE -eq 0) { 'Restart cancelled.' } else { 'No restart was scheduled.' }
