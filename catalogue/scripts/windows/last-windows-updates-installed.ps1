# name: Last Windows updates installed
# description: The 25 most recent updates (hotfixes) and when they were installed.
# category: Updates
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-HotFix | Sort-Object { $_.InstalledOn -as [datetime] } -Descending | Select-Object -First 25 HotFixID, Description, InstalledOn | Format-Table -AutoSize
