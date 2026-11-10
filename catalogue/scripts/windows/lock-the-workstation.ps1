# name: Lock the workstation
# description: Locks every signed-in session (the user can unlock with their password).
# category: Users
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-Process -IncludeUserName explorer -ErrorAction SilentlyContinue | ForEach-Object { tsdiscon.exe $_.SessionId 2>$null }
'Sessions locked.'
