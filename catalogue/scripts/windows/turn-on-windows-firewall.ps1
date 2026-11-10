# name: Turn on Windows Firewall
# description: Enables Windows Firewall on all profiles (changes the system).
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
Get-NetFirewallProfile | Format-Table Name, Enabled
