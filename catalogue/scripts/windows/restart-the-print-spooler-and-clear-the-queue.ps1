# name: Restart the print spooler and clear the queue
# description: Stops the spooler, deletes stuck print jobs and starts it again.
# category: Printers
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Stop-Service Spooler -Force
Remove-Item "$env:windir\System32\spool\PRINTERS\*" -Force -ErrorAction SilentlyContinue
Start-Service Spooler
Get-Service Spooler | Format-List Name, Status
