# name: Windows Update settings
# description: Policies and settings that control Windows Update on this device (WSUS, deferrals, pause).
# category: Updates
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue | Format-List WUServer, TargetReleaseVersionInfo, DeferFeatureUpdatesPeriodInDays, DeferQualityUpdatesPeriodInDays
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue | Format-List NoAutoUpdate, AUOptions, UseWUServer
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -ErrorAction SilentlyContinue | Format-List PauseUpdatesExpiryTime
