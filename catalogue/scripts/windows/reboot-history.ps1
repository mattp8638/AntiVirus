# name: Reboot history
# description: When the device last started and shut down, and who or what restarted it.
# category: Diagnostics
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1074,6005,6006,6008} -MaxEvents 30 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, @{n='Detail';e={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 250
