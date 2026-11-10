# name: Top processes by CPU and memory
# description: The ten busiest processes by CPU time and by memory.
# category: Performance
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
'--- CPU ---'; Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, Id, CPU, @{n='MemMB';e={[math]::Round($_.WorkingSet64/1MB)}} | Format-Table -AutoSize
'--- Memory ---'; Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 Name, Id, @{n='MemMB';e={[math]::Round($_.WorkingSet64/1MB)}} | Format-Table -AutoSize
