# name: System file check
# description: Runs SFC to find and repair damaged Windows files.
# category: Maintenance
# platforms: windows
# timeout: 3600
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
sfc.exe /scannow | Select-String -Pattern 'Windows Resource Protection' | ForEach-Object { $_.Line }
"SFC exit code: $LASTEXITCODE"
