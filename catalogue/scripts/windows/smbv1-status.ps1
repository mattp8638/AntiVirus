# name: SMBv1 status
# description: Whether the outdated SMBv1 protocol is enabled.
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-SmbServerConfiguration | Format-List EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue | Format-List FeatureName, State
