# name: Event log errors (last 24 hours)
# description: Errors and critical events in the System and Application logs over the last day, grouped by source.
# category: Diagnostics
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue |
  Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 25 Count, Name | Format-Table -AutoSize | Out-String -Width 250
