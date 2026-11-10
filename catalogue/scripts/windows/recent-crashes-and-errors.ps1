# name: Recent crashes and errors
# description: Application crashes, blue screens and unexpected shutdowns in the last 7 days.
# category: Diagnostics
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000,1002; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | Select-Object -First 20 TimeCreated, Id, @{n='App';e={$_.Properties[0].Value}} | Format-Table -AutoSize
Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,1001,6008; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, ProviderName | Format-Table -AutoSize
