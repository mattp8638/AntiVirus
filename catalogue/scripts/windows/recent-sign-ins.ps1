# name: Recent sign-ins
# description: The last 30 successful sign-ins from the Security log (interactive and remote).
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 500 -ErrorAction SilentlyContinue |
  Where-Object { $_.Properties[8].Value -in 2,10,11 } | Select-Object -First 30 TimeCreated,
  @{n='User';e={"$($_.Properties[6].Value)\$($_.Properties[5].Value)"}}, @{n='Type';e={@{2='Console';10='Remote';11='Cached'}[[int]$_.Properties[8].Value]}},
  @{n='From';e={$_.Properties[18].Value}} | Format-Table -AutoSize
