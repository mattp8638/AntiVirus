# name: Windows Server roles
# description: Installed Windows Server roles and features (servers only).
# category: Inventory
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) { Get-WindowsFeature | Where-Object Installed | Select-Object Name, DisplayName | Format-Table -AutoSize } else { 'Not a Windows Server.' }
