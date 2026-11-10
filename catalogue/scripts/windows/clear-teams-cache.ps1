# name: Clear Teams cache
# description: Deletes the new Teams client's cache for every user. Teams must be closed.
# category: Applications
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-Process ms-teams -ErrorAction SilentlyContinue | Stop-Process -Force
Get-ChildItem 'C:\Users\*\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams' -ErrorAction SilentlyContinue | ForEach-Object { Remove-Item "$($_.FullName)\*" -Recurse -Force -ErrorAction SilentlyContinue; "Cleared $($_.FullName)" }
