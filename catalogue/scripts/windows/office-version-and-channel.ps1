# name: Office version and channel
# description: Microsoft 365 Apps version, update channel and last update.
# category: Applications
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue | Format-List VersionToReport, CDNBaseUrl, UpdateChannel, Platform, ProductReleaseIds
