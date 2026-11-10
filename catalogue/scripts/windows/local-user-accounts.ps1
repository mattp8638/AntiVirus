# name: Local user accounts
# description: Local accounts, whether enabled, and when they last signed in.
# category: Users
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, Description | Format-Table -AutoSize
