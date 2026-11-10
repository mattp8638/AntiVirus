# name: Failed sign-ins
# description: Failed sign-in attempts in the last 24 hours, by account and source.
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue |
  Group-Object { "$($_.Properties[6].Value)\$($_.Properties[5].Value) from $($_.Properties[19].Value)" } |
  Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize
