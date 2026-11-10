# name: Update Defender signatures
# description: Downloads the latest Microsoft Defender signatures.
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Update-MpSignature -ErrorAction Stop
Get-MpComputerStatus | Format-List AntivirusSignatureVersion, AntivirusSignatureLastUpdated
