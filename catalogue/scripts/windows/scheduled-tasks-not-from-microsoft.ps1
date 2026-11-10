# name: Scheduled tasks not from Microsoft
# description: Scheduled tasks outside the Microsoft folder: a common place for persistence.
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | Select-Object TaskPath, TaskName, State, @{n='Action';e={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '}} | Format-Table -AutoSize | Out-String -Width 300
