# name: Shares on this computer
# description: Folders this computer shares, with their permissions.
# category: Network
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-SmbShare | Where-Object { $_.Name -notmatch '\$$' } | ForEach-Object { $_ | Select-Object Name, Path, Description; Get-SmbShareAccess -Name $_.Name | Format-Table AccountName, AccessRight -AutoSize }
