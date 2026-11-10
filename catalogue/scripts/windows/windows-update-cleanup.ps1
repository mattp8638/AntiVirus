# name: Windows Update cleanup
# description: Removes superseded update files with DISM component cleanup (changes the system; can take a long time).
# category: Maintenance
# platforms: windows
# timeout: 3600
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
dism.exe /Online /Cleanup-Image /StartComponentCleanup /Quiet
"DISM exit code: $LASTEXITCODE"
