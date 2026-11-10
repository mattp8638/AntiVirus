# name: Local administrators
# description: Members of the local Administrators group.
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object Name, ObjectClass, PrincipalSource | Format-Table -AutoSize
