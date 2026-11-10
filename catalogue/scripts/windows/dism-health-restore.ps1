# name: DISM health restore
# description: Checks and repairs the Windows component store (changes the system).
# category: Maintenance
# platforms: windows
# timeout: 3600
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
dism.exe /Online /Cleanup-Image /RestoreHealth
"DISM exit code: $LASTEXITCODE"
