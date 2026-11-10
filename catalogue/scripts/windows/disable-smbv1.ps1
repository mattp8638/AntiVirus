# name: Disable SMBv1
# description: Turns off the outdated SMBv1 protocol (changes the system; a restart may be needed).
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
Get-SmbServerConfiguration | Format-List EnableSMB1Protocol
