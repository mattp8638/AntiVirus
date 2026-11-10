# name: Refresh Group Policy
# description: Applies Group Policy now (gpupdate /force).
# category: Maintenance
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
gpupdate /force | Out-String
